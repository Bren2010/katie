package auditor

import (
	"context"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/transparency"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/test"
)

func makeAuditor(t *testing.T) (
	structs.PrivateConfig,
	db.TransparencyStore,
	*transparency.Tree,
	*Auditor,
) {
	config, auditorKey := test.ConfigWithAuditor(t)
	store := db.NewTransparencyStore(context.Background(), db.NewMemoryKeyValueStore(), false)

	tree, err := transparency.NewTree(config, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := NewAuditor(config.Public(), auditorKey, db.NewMemoryAuditorStore(), true)
	if err != nil {
		t.Fatal(err)
	}

	for range 10 {
		// Generate random labels to insert.
		added := make([]transparency.LabelValue, 5)
		for j := range added {
			label := make([]byte, 16)
			rand.Read(label)

			added[j] = transparency.LabelValue{
				Label: label,
				Value: structs.UpdateValue{Value: []byte("value")},
			}
		}

		// Add to tree, check for TODO
		update, err := tree.Mutate(added, nil)
		if err != nil {
			t.Fatal(err)
		} else if err := auditor.Process(update); err != nil {
			t.Fatal(err)
		}
	}

	return config, store, tree, auditor
}

func getFrontier(
	t *testing.T,
	config *structs.PrivateConfig,
	store db.TransparencyStore,
	treeSize uint64,
) []uint64 {
	handle := algorithms.NewProducedProofHandle(config.Suite, store, nil)
	provider := algorithms.NewDataProvider(config.Suite, handle)

	frontier := math.Frontier(treeSize)
	timestamps := make([]uint64, len(frontier))
	for i, x := range frontier {
		timestamp, err := provider.GetTimestamp(x)
		if err != nil {
			t.Fatal(err)
		}
		timestamps[i] = timestamp
	}

	return timestamps
}

func TestAuditorState(t *testing.T) {
	const expectedTreeSize = 10
	config, store, tree, auditor := makeAuditor(t)
	state := auditor.state

	// Verify tree head
	frontier := getFrontier(t, &config, store, expectedTreeSize)

	if state.treeHead.Timestamp != frontier[len(frontier)-1] {
		t.Fatal("unexpected timestamp")
	} else if state.treeHead.TreeSize != expectedTreeSize {
		t.Fatal("unexpected tree size")
	} else if state.treeHead.Signature != nil {
		t.Fatal("unexpected signature")
	}

	// Verify full subtrees
	root, err := log.Root(config.Suite, state.treeHead.TreeSize, state.fullSubtrees)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := structs.Marshal(&structs.TreeHeadTBS{
		Config:   config.Public(),
		TreeSize: expectedTreeSize,
		Root:     root,
	})
	if err != nil {
		t.Fatal(err)
	}
	ok := config.SignatureKey.Public().Verify(tbs, tree.TreeHead().Signature)
	if !ok {
		t.Fatal("unexpected root hash computed")
	}

	// Verify frontier timestamps
	if len(state.timestamps) != len(frontier) {
		t.Fatal("unexpected number of timestamps")
	}
	for i, timestamp := range state.timestamps {
		if timestamp != frontier[i] {
			t.Fatal("unexpected timestamp")
		}
	}
}

func TestAuditorPersistent(t *testing.T) {
	_, _, _, auditor := makeAuditor(t)

	if _, err := auditor.Commit(); err != nil {
		t.Fatal(err)
	}

	auditor2, err := NewAuditor(auditor.config, auditor.auditorKey, auditor.tx, true)
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(auditor.state, auditor2.state) {
		t.Fatal("loaded state is different than persisted state")
	}
}

// TestAuditorRetainsRecentInsertions checks that the auditor remembers every
// VRF output that was inserted after the previous rightmost distinguished log
// entry, including the ones from earlier log entries.
//
// Process relies on this to reject the removal of a prefix tree leaf that was
// added too recently. If the auditor forgets an insertion, addedSince reports
// that the leaf was not added recently and the premature removal is accepted.
func TestAuditorRetainsRecentInsertions(t *testing.T) {
	config, auditorKey := test.ConfigWithAuditor(t)
	store := db.NewTransparencyStore(context.Background(), db.NewMemoryKeyValueStore(), false)

	tree, err := transparency.NewTree(config, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := NewAuditor(config.Public(), auditorKey, db.NewMemoryAuditorStore(), true)
	if err != nil {
		t.Fatal(err)
	}

	// insertedAt records the log entry that each VRF output was added in.
	insertedAt := make(map[string]uint64)
	checked := 0

	for range 10 {
		added := make([]transparency.LabelValue, 2)
		for j := range added {
			label := make([]byte, 16)
			rand.Read(label)

			added[j] = transparency.LabelValue{
				Label: label,
				Value: structs.UpdateValue{Value: []byte("value")},
			}
		}

		// The new log entry is appended to the end of the tree as it stands.
		pos := uint64(0)
		if auditor.state != nil {
			pos = auditor.state.treeHead.TreeSize
		}

		update, err := tree.Mutate(added, nil)
		if err != nil {
			t.Fatal(err)
		} else if err := auditor.Process(update); err != nil {
			t.Fatal(err)
		}
		for _, entry := range update.Added {
			insertedAt[string(entry.VrfOutput)] = pos
		}

		// A prefix tree leaf is only eligible for removal once it predates the
		// previous rightmost distinguished log entry. Everything inserted after
		// that point has to still be known to the auditor.
		prevDLE, _, err := auditor.previousRightmost(update.Timestamp)
		if err != nil {
			t.Fatal(err)
		} else if prevDLE == nil {
			continue
		}
		for vrfOutput, at := range insertedAt {
			if at <= *prevDLE {
				continue
			} else if !auditor.state.addedSince(*prevDLE, []byte(vrfOutput)) {
				t.Fatalf(
					"auditor forgot a vrf output inserted in log entry %v, so it would accept its removal before log entry %v",
					at, *prevDLE,
				)
			}
			checked++
		}
	}

	if checked == 0 {
		t.Fatal("test did not exercise any retained insertions")
	}
}
