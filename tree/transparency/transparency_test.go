package transparency

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"
	"strings"
	"testing"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/test"
)

// countingKV wraps an in-memory key-value store and keeps a copy of the keys
// committed to it. The db package doesn't expose the contents of a store, so
// this is how tests assert on how many entries of each kind were persisted.
type countingKV struct {
	inner    db.KeyValueStore
	treeHead []byte
	data     map[string]struct{}
}

func newCountingKV() *countingKV {
	return &countingKV{
		inner: db.NewMemoryKeyValueStore(),
		data:  make(map[string]struct{}),
	}
}

func (kv *countingKV) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	return kv.inner.BatchGet(ctx, keys)
}

func (kv *countingKV) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	if err := kv.inner.Commit(ctx, batch, treeHead); err != nil {
		return err
	}
	for key, value := range batch {
		if value == nil {
			delete(kv.data, key)
		} else {
			kv.data[key] = struct{}{}
		}
	}
	kv.treeHead = treeHead
	return nil
}

// TreeHead returns the most recently committed tree head.
func (kv *countingKV) TreeHead() []byte { return kv.treeHead }

// Count returns the number of committed keys with the given prefix, ignoring
// keys that were deleted. The prefixes mirror the key layout of
// db.TransparencyStore: "i" for label indices, "v" for label versions, and "t"
// for log entries.
func (kv *countingKV) Count(prefix string) int {
	out := 0
	for key := range kv.data {
		if strings.HasPrefix(key, prefix) {
			out++
		}
	}
	return out
}

// memStoreCounting returns a TransparencyStore along with the countingKV that
// backs it.
func memStoreCounting() (db.TransparencyStore, *countingKV) {
	kv := newCountingKV()
	return db.NewTransparencyStore(context.Background(), kv, false), kv
}

// memStore returns a TransparencyStore backed by an in-memory key-value store.
func memStore() db.TransparencyStore {
	kv := db.NewMemoryKeyValueStore()
	return db.NewTransparencyStore(context.Background(), kv, false)
}

func generateRandomTree(t *testing.T) (*Tree, [][]byte) {
	config := test.Config(t)
	store := memStore()

	labels := make([][]byte, 5)
	for i := range labels {
		labels[i] = make([]byte, 8)
		rand.Read(labels[i])
	}

	tree, err := NewTree(config, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 7 {
		add := make([]LabelValue, len(labels))
		for j, label := range labels {
			add[j] = LabelValue{
				Label: label,
				Value: structs.UpdateValue{Value: []byte{byte(i)}},
			}
		}
		if _, err := tree.Mutate(add, nil); err != nil {
			t.Fatal(err)
		}
	}

	return tree, labels
}

func verifySearchResponse(
	t *testing.T,
	res *structs.SearchResponse,
	treeHead bool,
	version *uint32,
	value []byte,
	searchVer uint32,
	greatestVer uint32,
	excludeVers []uint32,
) {
	if treeHead && res.FullTreeHead.TreeHead == nil {
		t.Fatal("no tree head provided when expected")
	} else if !treeHead && res.FullTreeHead.TreeHead != nil {
		t.Fatal("tree head provided when none expected")
	}

	if version == nil && res.Version != nil {
		t.Fatal("version provided when none expected")
	} else if version != nil && res.Version == nil {
		t.Fatal("version not provided when expected")
	} else if version != nil && *res.Version != *version {
		t.Fatal("unexpected version provided")
	}

	if !bytes.Equal(value, res.Value.Value) {
		t.Fatal("unexpected value provided")
	}

	ladder := math.SearchBinaryLadder(searchVer, searchVer, nil, nil)
	if len(res.BinaryLadder) != len(ladder) {
		t.Fatal("unexpected number of entries in binary ladder")
	}
	for i, step := range res.BinaryLadder {
		if len(step.Proof) == 0 {
			t.Fatal("no vrf proof for version provided")
		}
		expected := ladder[i] <= greatestVer && !slices.Contains(excludeVers, ladder[i])
		if expected && len(step.Commitment) == 0 {
			t.Fatal("no commitment value provided when expected")
		} else if !expected && len(step.Commitment) != 0 {
			t.Fatal("commitment value provided when not expected")
		}
	}
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	tree, labels := generateRandomTree(t)
	ver := uint32(6)

	// No state, greatest version search.
	res, err := tree.Search(ctx, &structs.SearchRequest{Last: nil, Label: labels[0], Version: nil})
	if err != nil {
		t.Fatal(err)
	}
	verifySearchResponse(t, res, true, &ver, []byte{6}, 6, 6, []uint32{6})

	// Tree size less than current, greatest version search.
	size := tree.treeHead.TreeSize - 1
	res, err = tree.Search(ctx, &structs.SearchRequest{Last: &size, Label: labels[0], Version: nil})
	if err != nil {
		t.Fatal(err)
	}
	verifySearchResponse(t, res, true, &ver, []byte{6}, 6, 6, []uint32{6})

	// Tree size equal to current, greatest version search.
	size = tree.treeHead.TreeSize
	res, err = tree.Search(ctx, &structs.SearchRequest{Last: &size, Label: labels[0], Version: nil})
	if err != nil {
		t.Fatal(err)
	}
	verifySearchResponse(t, res, false, &ver, []byte{6}, 6, 6, []uint32{6})

	// No state, fixed version search.
	ver = 1
	res, err = tree.Search(ctx, &structs.SearchRequest{Last: nil, Label: labels[0], Version: &ver})
	if err != nil {
		t.Fatal(err)
	}
	verifySearchResponse(t, res, true, nil, []byte{1}, 1, 6, []uint32{1, 2})

	// Tree size less than current, fixed version search.
	size = tree.treeHead.TreeSize - 1
	res, err = tree.Search(ctx, &structs.SearchRequest{Last: &size, Label: labels[0], Version: &ver})
	if err != nil {
		t.Fatal(err)
	}
	verifySearchResponse(t, res, true, nil, []byte{1}, 1, 6, []uint32{1, 2})

	// Tree size equal to current, fixed version search.
	size = tree.treeHead.TreeSize
	res, err = tree.Search(ctx, &structs.SearchRequest{Last: &size, Label: labels[0], Version: &ver})
	if err != nil {
		t.Fatal(err)
	}
	verifySearchResponse(t, res, false, nil, []byte{1}, 1, 6, []uint32{1, 2})
}
