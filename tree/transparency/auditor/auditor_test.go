package auditor

import (
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/db/memory"
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
	store := memory.NewTransparencyStore()

	tree, err := transparency.NewTree(config, store)
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := NewAuditor(config.Public(), auditorKey, memory.NewAuditorStore())
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

		// Add to tree, check for
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

	if state.TreeHead.Timestamp != frontier[len(frontier)-1] {
		t.Fatal("unexpected timestamp")
	} else if state.TreeHead.TreeSize != expectedTreeSize {
		t.Fatal("unexpected tree size")
	} else if state.TreeHead.Signature != nil {
		t.Fatal("unexpected signature")
	}

	// Verify full subtrees
	root, err := log.Root(config.Suite, state.TreeHead.TreeSize, state.FullSubtrees)
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
	if len(state.Timestamps) != len(frontier) {
		t.Fatal("unexpected number of timestamps")
	}
	for i, timestamp := range state.Timestamps {
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

	auditor2, err := NewAuditor(auditor.config, auditor.auditorKey, auditor.tx)
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(auditor.state, auditor2.state) {
		t.Fatal("loaded state is different than persisted state")
	}
}
