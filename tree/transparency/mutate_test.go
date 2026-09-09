package transparency

import (
	"bytes"
	"testing"

	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/test"
)

func TestAddLabel(t *testing.T) {
	store, kv := memStoreCounting()

	var (
		label1 = []byte("label")
		label2 = []byte("other")
	)

	tree, err := NewTree(test.Config(t), store, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make the first mutation.
	_, err = tree.Mutate([]LabelValue{
		{Label: label1, Value: structs.UpdateValue{Value: []byte("version 0")}},
		{Label: label2, Value: structs.UpdateValue{Value: []byte("other 0")}},
		{Label: label1, Value: structs.UpdateValue{Value: []byte("version 1")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check that all expected database entries are present.
	if kv.TreeHead() == nil {
		t.Fatal("no tree head written")
	} else if kv.Count("i") != 2 {
		t.Fatal("unexpected number of indices")
	} else if kv.Count("v") != 3 {
		t.Fatal("unexpected number of label versions")
	} else if kv.Count("t") != 1 {
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
		{Label: label1, Value: structs.UpdateValue{Value: []byte("version 2")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check stored data.
	if kv.Count("i") != 2 {
		t.Fatal("unexpected number of indices")
	} else if kv.Count("v") != 4 {
		t.Fatal("unexpected number of label versions")
	} else if kv.Count("t") != 2 {
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

func TestRemoveLabel(t *testing.T) {
	store, kv := memStoreCounting()

	var label = []byte("label")

	tree, err := NewTree(test.Config(t), store, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add some versions of the label.
	_, err = tree.Mutate([]LabelValue{
		{Label: label, Value: structs.UpdateValue{Value: []byte("version 0")}},
		{Label: label, Value: structs.UpdateValue{Value: []byte("version 1")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Delete the label.
	_, err = tree.Mutate(nil, [][]byte{label})
	if err != nil {
		t.Fatal(err)
	}

	// Check that index and label versions were removed.
	if kv.Count("i") != 0 {
		t.Fatal("unexpected number of indices")
	} else if kv.Count("v") != 0 {
		t.Fatal("unexpected number of label versions")
	} else if kv.Count("t") != 2 {
		t.Fatal("unexpected number of log entries written")
	}
}

func TestRemoveLabelTooSoon(t *testing.T) {
	store := memStore()

	var label = []byte("label")

	tree, err := NewTree(test.Config(t), store, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add some versions of the label.
	for i := range 3 {
		_, err = tree.Mutate([]LabelValue{
			{Label: label, Value: structs.UpdateValue{Value: []byte{byte(i)}}},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Delete the label.
	_, err = tree.Mutate(nil, [][]byte{label})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAddRemoveSameLabel(t *testing.T) {
	store, kv := memStoreCounting()

	var label = []byte("label")

	tree, err := NewTree(test.Config(t), store, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add some versions of the label.
	_, err = tree.Mutate([]LabelValue{
		{Label: label, Value: structs.UpdateValue{Value: []byte("version 0")}},
		{Label: label, Value: structs.UpdateValue{Value: []byte("version 1")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Delete the label and add a new version in the same operation.
	_, err = tree.Mutate([]LabelValue{
		{Label: label, Value: structs.UpdateValue{Value: []byte("version 2")}},
	}, [][]byte{label})
	if err != nil {
		t.Fatal(err)
	}

	// Check that index and label versions were removed.
	if kv.Count("i") != 1 {
		t.Fatal("unexpected number of indices")
	} else if kv.Count("v") != 1 {
		t.Fatal("unexpected number of label versions")
	} else if kv.Count("t") != 2 {
		t.Fatal("unexpected number of log entries written")
	}

	// Check stored data.
	stored, err := tree.getVersion(label, 0)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(stored.Value.Value, []byte("version 2")) {
		t.Fatal("unexpected data stored")
	}
}
