package transparency

import (
	"bytes"
	"testing"

	"github.com/Bren2010/katie/db/memory"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func TestFirstMutate(t *testing.T) {
	store := memory.NewTransparencyStore()

	var (
		label1 = []byte("label")
		label2 = []byte("other")

		val1 = []byte("version 0")
		val2 = []byte("version 1")
		val3 = []byte("version 2")
		val4 = []byte("other 0")
	)

	tree, err := NewTree(testConfig(t), store)
	if err != nil {
		t.Fatal(err)
	}

	// Make the first mutation.
	_, err = tree.Mutate([]LabelValue{
		{Label: label1, Value: structs.UpdateValue{Value: val1}},
		{Label: label2, Value: structs.UpdateValue{Value: val4}},
		{Label: label1, Value: structs.UpdateValue{Value: val2}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check that all expected database entries are present.
	if store.TreeHead == nil {
		t.Fatal("no tree head written")
	} else if len(store.Indices) != 2 {
		t.Fatal("unexpected number of indices")
	} else if len(store.Versions) != 3 {
		t.Fatal("unexpected number of label versions")
	} else if len(store.LogEntries) != 1 {
		t.Fatal("unexpected number of log entries written")
	}

	indices, err := store.BatchGetIndex([][]byte{label1, label2})
	if err != nil {
		t.Fatal(err)
	} else if len(indices) != 2 {
		t.Fatal("unexpected number of indices returned")
	} else if !bytes.Equal(indices[0], []byte{0, 0}) || !bytes.Equal(indices[1], []byte{0}) {
		t.Fatal("unexpected indices returned")
	}

	// Make a second mutation.
	_, err = tree.Mutate([]LabelValue{
		{Label: label1, Value: structs.UpdateValue{Value: val3}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check stored data.
	if len(store.Indices) != 2 {
		t.Fatal("unexpected number of indices")
	} else if len(store.Versions) != 4 {
		t.Fatal("unexpected number of label versions")
	} else if len(store.LogEntries) != 2 {
		t.Log(store.LogEntries)
		t.Fatal("unexpected number of log entries written")
	}

	indices, err = store.BatchGetIndex([][]byte{label1})
	if err != nil {
		t.Fatal(err)
	} else if len(indices) != 1 {
		t.Fatal("unexpected number of indices returned")
	} else if !bytes.Equal(indices[0], []byte{0, 0, 1}) {
		t.Fatal("unexpected index returned")
	}
}

// TODO: Test removing label.
// TODO: Test adding and removing label in same request.
