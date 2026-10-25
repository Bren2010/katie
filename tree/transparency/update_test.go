package transparency

import (
	"bytes"
	"testing"
	"time"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/test"
	"github.com/Bren2010/katie/tree/transparency/wire"
)

// sequencedTree returns a Tree with a goroutine that sequences each
// UpdateRequest it receives in its own log entry.
func sequencedTree(t *testing.T, config structs.PrivateConfig) *Tree {
	ch := make(chan UpdateRequest)
	tree, err := NewTree(config, test.MemStore(), ch)
	if err != nil {
		t.Fatal(err)
	}
	tree.now = func() time.Time { return time.UnixMilli(1000) }

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case req := <-ch:
				_, err := tree.Mutate([]LabelUpdate{{
					Label:           req.Label,
					StartingVersion: req.StartingVersion,
					Values:          req.Values,
				}}, nil)
				req.Response <- UpdateResponse{Pos: tree.n() - 1, Err: err}
			}
		}
	}()

	return tree
}

// signedAt returns `value` signed by the Service Operator as version `ver` of
// `label`.
func signedAt(t *testing.T, tree *Tree, key suites.SigningPrivateKey, label []byte, ver uint32, value string) structs.UpdateValue {
	tbs, err := structs.Marshal(&structs.UpdateTBS{
		Config:  tree.config.Public(),
		Label:   label,
		Version: ver,
		Value:   []byte(value),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(tbs)
	if err != nil {
		t.Fatal(err)
	}
	return structs.UpdateValue{Value: []byte(value), Signature: sig}
}

// collect reads every UpdateResponse from `ch`. It fails the test if the
// stream contains an error or doesn't terminate.
func collect(t *testing.T, ch <-chan wire.UpdateResponse) []*structs.UpdateResponse {
	t.Helper()
	var out []*structs.UpdateResponse
	for res := range ch {
		if res.Err != nil {
			t.Fatal(res.Err)
		} else if len(out) > 10 {
			t.Fatal("stream of update responses did not terminate")
		}
		out = append(out, res.Out)
	}
	return out
}

type expectedResponse struct {
	pos      uint64
	skipped  uint32
	values   []string
	info     int
	startVer uint32
}

func checkResponses(t *testing.T, got []*structs.UpdateResponse, want []expectedResponse) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("unexpected number of update responses: %d", len(got))
	}
	for i, res := range got {
		exp := want[i]
		if res.Position != exp.pos {
			t.Fatalf("response %d: unexpected position: %d", i, res.Position)
		} else if res.SkippedVersions != exp.skipped {
			t.Fatalf("response %d: unexpected skipped versions: %d", i, res.SkippedVersions)
		} else if len(res.Info) != exp.info {
			t.Fatalf("response %d: unexpected number of update infos: %d", i, len(res.Info))
		} else if len(res.Values) != len(exp.values) {
			t.Fatalf("response %d: unexpected number of values: %d", i, len(res.Values))
		}
		for j, val := range res.Values {
			if !bytes.Equal(val.Value, []byte(exp.values[j])) {
				t.Fatalf("response %d: unexpected value: %q", i, val.Value)
			}
		}
		endVer := exp.startVer + exp.skipped + uint32(exp.info) - 1
		if len(res.BinaryLadder) != len(updateLadderVersions(exp.startVer, endVer)) {
			t.Fatalf("response %d: unexpected number of binary ladder steps: %d", i, len(res.BinaryLadder))
		}
	}
}

func TestUpdateStreamTerminates(t *testing.T) {
	tree := sequencedTree(t, test.Config(t))
	label := []byte("label")

	for i, val := range []string{"a", "b"} {
		var greatest *uint32
		if i > 0 {
			greatest = new(uint32(i - 1))
		}
		ch, err := tree.Update(t.Context(), &structs.UpdateRequest{
			Label:           label,
			GreatestVersion: greatest,
			Values:          []structs.LabelValue{{Value: []byte(val)}},
		})
		if err != nil {
			t.Fatal(err)
		}
		// The user already knows the values they submitted, so the single
		// response for the new log entry contains no values.
		checkResponses(t, collect(t, ch), []expectedResponse{
			{pos: uint64(i), info: 1, startVer: uint32(i)},
		})
	}
}

func TestManagerUpdateSkippedVersions(t *testing.T) {
	config, key := test.ConfigWithManager(t)
	tree := sequencedTree(t, config)
	label := []byte("label")

	ch, err := tree.ManagerUpdate(t.Context(), &structs.ManagerUpdateRequest{
		Label:         label,
		Values:        []structs.UpdateValue{signedAt(t, tree, key, label, 0, "v0")},
		SignedVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkResponses(t, collect(t, ch), []expectedResponse{
		{pos: 0, info: 1, startVer: 0},
	})

	// Versions 1 and 2 were authorized by the Service Operator but never
	// sequenced, so they're sequenced as dummy versions before version 3.
	ch, err = tree.ManagerUpdate(t.Context(), &structs.ManagerUpdateRequest{
		Label:           label,
		GreatestVersion: new(uint32(0)),
		Values: []structs.UpdateValue{
			signedAt(t, tree, key, label, 3, "v3"),
			signedAt(t, tree, key, label, 4, "v4"),
		},
		SignedVersion: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkResponses(t, collect(t, ch), []expectedResponse{
		{pos: 1, skipped: 2, info: 2, startVer: 1},
	})

	// A user that knows no versions of the label syncs through both log
	// entries, receiving values only for the non-dummy versions.
	ch, err = tree.ManagerUpdate(t.Context(), &structs.ManagerUpdateRequest{Label: label})
	if err != nil {
		t.Fatal(err)
	}
	checkResponses(t, collect(t, ch), []expectedResponse{
		{pos: 0, values: []string{"v0"}, info: 1, startVer: 0},
		{pos: 1, skipped: 2, values: []string{"v3", "v4"}, info: 2, startVer: 1},
	})

	// A user can't claim to know only some of the versions inserted in a log
	// entry, whether they're dummy versions or not.
	for _, ver := range []uint32{1, 2, 3} {
		_, err = tree.ManagerUpdate(t.Context(), &structs.ManagerUpdateRequest{
			Label:           label,
			GreatestVersion: new(ver),
		})
		if err == nil {
			t.Fatalf("expected greatest version %d to be rejected", ver)
		}
	}
	ch, err = tree.ManagerUpdate(t.Context(), &structs.ManagerUpdateRequest{
		Label:           label,
		GreatestVersion: new(uint32(4)),
	})
	if err != nil {
		t.Fatal(err)
	}
	checkResponses(t, collect(t, ch), nil)
}

func TestManagerUpdateWithoutValues(t *testing.T) {
	config, key := test.ConfigWithManager(t)
	tree := sequencedTree(t, config)
	label := []byte("label")

	ch, err := tree.ManagerUpdate(t.Context(), &structs.ManagerUpdateRequest{
		Label:  label,
		Values: []structs.UpdateValue{signedAt(t, tree, key, label, 0, "v0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	collect(t, ch)

	// A request without values must have a signed version of zero, even
	// though the next version of the label is one.
	ch, err = tree.ManagerUpdate(t.Context(), &structs.ManagerUpdateRequest{
		Label:           label,
		GreatestVersion: new(uint32(0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	checkResponses(t, collect(t, ch), nil)

	// A request with values still may not reuse a version counter.
	_, err = tree.ManagerUpdate(t.Context(), &structs.ManagerUpdateRequest{
		Label:         label,
		Values:        []structs.UpdateValue{signedAt(t, tree, key, label, 0, "v0")},
		SignedVersion: 0,
	})
	if err == nil {
		t.Fatal("expected request reusing a version counter to fail")
	}
}
