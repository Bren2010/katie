package transparency

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/test"
)

func TestAddLabel(t *testing.T) {
	store, kv := test.MemStoreCounting()

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
	store, kv := test.MemStoreCounting()

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
	store := test.MemStore()

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
	store, kv := test.MemStoreCounting()

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

// TestEmptyMutation checks that a log entry can be added without modifying the
// prefix tree.
func TestEmptyMutation(t *testing.T) {
	store, kv := test.MemStoreCounting()

	var label = []byte("label")

	tree, err := NewTree(test.Config(t), store, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tree.Mutate(nil, nil); err != nil {
		t.Fatal(err)
	}
	_, err = tree.Mutate([]LabelValue{
		{Label: label, Value: structs.UpdateValue{Value: []byte("version 0")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.Mutate(nil, nil); err != nil {
		t.Fatal(err)
	}

	if kv.Count("t") != 3 {
		t.Fatal("unexpected number of log entries written")
	} else if tree.TreeHead().TreeSize != 3 {
		t.Fatal("unexpected tree size")
	}
}

// TestRemoveLabelBeforeAuditorStart checks that a label can't be removed until
// the previous distinguished log entry is one that the Third-Party Auditor has
// processed, because the auditor would reject the removal otherwise.
func TestRemoveLabelBeforeAuditorStart(t *testing.T) {
	store := test.MemStore()

	var label = []byte("label")

	config, _ := test.ConfigWithAuditor(t)
	config.AuditorStartPos = 2
	tree, err := NewTree(config, store, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Log entry 0 adds the label.
	_, err = tree.Mutate([]LabelValue{
		{Label: label, Value: structs.UpdateValue{Value: []byte("version 0")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Log entry 1 can't remove it. The previous distinguished log entry is 0,
	// which is before the auditor's starting position.
	_, err = tree.Mutate(nil, [][]byte{label})
	if err == nil || !strings.Contains(err.Error(), "auditor") {
		t.Fatalf("expected removal to be rejected because of the auditor, got: %v", err)
	}

	// Log entry 4 can, because the previous distinguished log entry is 3.
	for range 3 {
		if _, err := tree.Mutate(nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tree.Mutate(nil, [][]byte{label}); err != nil {
		t.Fatal(err)
	}
}

// TestMutateRollback checks that a failed mutation leaves no trace in the
// database, even if some of its changes were written before it failed.
func TestMutateRollback(t *testing.T) {
	store, kv := test.MemStoreCounting()

	var label = []byte("label")

	tree, err := NewTree(test.Config(t), store, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		_, err = tree.Mutate([]LabelValue{
			{Label: label, Value: structs.UpdateValue{Value: []byte{byte(i)}}},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Removing the label fails because it was modified too recently. Labels
	// are processed in a random order, so with this many additions, some are
	// almost certainly written before the removal fails.
	newLabels := test.RandomLabels(20)
	add := make([]LabelValue, len(newLabels))
	for i, newLabel := range newLabels {
		add[i] = LabelValue{Label: newLabel, Value: structs.UpdateValue{Value: []byte("new")}}
	}
	if _, err := tree.Mutate(add, [][]byte{label}); err == nil {
		t.Fatal("expected error")
	}

	// None of the additions are visible, or committed by the next mutation.
	indices, err := tree.batchGetIndex(newLabels)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range indices {
		if len(index) != 0 {
			t.Fatal("index from failed mutation is visible")
		}
	}
	if _, err := tree.Mutate(nil, nil); err != nil {
		t.Fatal(err)
	} else if kv.Count("i") != 1 {
		t.Fatal("unexpected number of indices")
	} else if kv.Count("v") != 3 {
		t.Fatal("unexpected number of label versions")
	} else if kv.Count("t") != 4 {
		t.Fatal("unexpected number of log entries written")
	}
}

// TestMutateFailedCommit checks that a Tree refuses to write after a commit
// fails, and that a reloaded Tree can continue from the committed state.
func TestMutateFailedCommit(t *testing.T) {
	store, kv := test.MemStoreCounting()

	var label = []byte("label")

	tree, err := NewTree(test.Config(t), store, nil)
	if err != nil {
		t.Fatal(err)
	} else if _, err := tree.Mutate(nil, nil); err != nil {
		t.Fatal(err)
	}

	kv.CommitErr = errors.New("commit failed")
	_, err = tree.Mutate([]LabelValue{
		{Label: label, Value: structs.UpdateValue{Value: []byte("version 0")}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "commit failed") {
		t.Fatalf("expected commit to fail, got: %v", err)
	} else if tree.n() != 1 {
		t.Fatal("tree size advanced after failed commit")
	}

	// Further writes are refused, even once the database recovers.
	kv.CommitErr = nil
	if _, err := tree.Mutate(nil, nil); err == nil || !strings.Contains(err.Error(), "reloaded") {
		t.Fatalf("expected write to be refused, got: %v", err)
	}

	// A reloaded tree doesn't see the failed mutation, and can be written to.
	reloaded, err := NewTree(test.Config(t), store, nil)
	if err != nil {
		t.Fatal(err)
	} else if reloaded.n() != 1 {
		t.Fatal("unexpected tree size after reload")
	}
	if index, err := reloaded.getIndex(label); err != nil {
		t.Fatal(err)
	} else if len(index) != 0 {
		t.Fatal("label from failed mutation is visible")
	}
	if _, err := reloaded.Mutate(nil, nil); err != nil {
		t.Fatal(err)
	} else if reloaded.n() != 2 {
		t.Fatal("unexpected tree size")
	}
}
