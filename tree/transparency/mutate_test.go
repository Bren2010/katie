package transparency

import (
	"bytes"
	"errors"
	"math"
	"slices"
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
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label1, Values: []structs.UpdateValue{
			{Value: []byte("version 0")},
			{Value: []byte("version 1")},
		}},
		{Label: label2, Values: []structs.UpdateValue{{Value: []byte("other 0")}}},
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
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label1, Values: []structs.UpdateValue{{Value: []byte("version 2")}}},
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
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{
			{Value: []byte("version 0")},
			{Value: []byte("version 1")},
		}},
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
		_, err = tree.Mutate([]LabelUpdate{
			{Label: label, Values: []structs.UpdateValue{{Value: []byte{byte(i)}}}},
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
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{
			{Value: []byte("version 0")},
			{Value: []byte("version 1")},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Delete the label and add a new version in the same operation.
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{{Value: []byte("version 2")}}},
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
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{{Value: []byte("version 0")}}},
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
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{{Value: []byte("version 0")}}},
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
		_, err = tree.Mutate([]LabelUpdate{
			{Label: label, Values: []structs.UpdateValue{{Value: []byte{byte(i)}}}},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Removing the label fails because it was modified too recently. Labels
	// being removed are processed after labels being added, so the additions
	// are written before the removal fails.
	newLabels := test.RandomLabels(20)
	add := make([]LabelUpdate, len(newLabels))
	for i, newLabel := range newLabels {
		add[i] = LabelUpdate{Label: newLabel, Values: []structs.UpdateValue{{Value: []byte("new")}}}
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
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{{Value: []byte("version 0")}}},
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

func TestCheckMutationSize(t *testing.T) {
	tree, err := NewTree(test.Config(t), test.MemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	maxEntries := uint64(math.MaxUint32) / (8 * uint64(tree.config.Suite.HashSize()))

	// Removed entries count twice, since each may also move a leaf.
	ok := []labelMutation{{remove: true, index: make([]uint64, maxEntries/2)}}
	if err := tree.checkMutationSize(ok); err != nil {
		t.Fatal(err)
	}
	tooMany := []labelMutation{{remove: true, index: make([]uint64, maxEntries/2+1)}}
	if err := tree.checkMutationSize(tooMany); err == nil {
		t.Fatal("expected oversized mutation to be rejected")
	}

	// Only labels being removed count towards removals.
	notRemoved := []labelMutation{{index: make([]uint64, maxEntries/2+1)}}
	if err := tree.checkMutationSize(notRemoved); err != nil {
		t.Fatal(err)
	}
}

// signed returns an UpdateValue with a placeholder Service Operator signature,
// which Mutate doesn't verify.
func signed(value []byte) structs.UpdateValue {
	return structs.UpdateValue{Value: value, UpdateSuffix: structs.UpdateSuffix{Signature: []byte("signature")}}
}

func TestSkippedVersions(t *testing.T) {
	store, kv := test.MemStoreCounting()

	var label = []byte("label")

	config, _ := test.ConfigWithManager(t)
	tree, err := NewTree(config, store, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add version 0 without giving a starting version.
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{signed([]byte("version 0"))}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Start at version 3, which requires skipping versions 1 and 2.
	update, err := tree.Mutate([]LabelUpdate{{
		Label:           label,
		StartingVersion: new(uint32(3)),
		Values:          []structs.UpdateValue{signed([]byte("version 3")), signed([]byte("version 4"))},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	} else if len(update.Added) != 4 {
		t.Fatalf("unexpected number of prefix tree entries added: %d", len(update.Added))
	}

	// Check that only non-dummy versions have stored values, and that the
	// index covers the dummy versions.
	if kv.Count("v") != 3 {
		t.Fatal("unexpected number of label versions")
	}
	index, err := tree.getIndex(label)
	if err != nil {
		t.Fatal(err)
	} else if !slices.Equal(index, []uint64{0, 1, 1, 1, 1}) {
		t.Fatalf("unexpected index: %v", index)
	}

	// Check that dummy versions have an all-zero commitment in the prefix
	// tree, and that real versions don't.
	ladder, _, err := tree.getBinaryLadder(label, []uint32{0, 1, 2, 3, 4}, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, tree.config.Suite.HashSize())
	for ver, step := range ladder {
		isDummy := ver == 1 || ver == 2
		if bytes.Equal(step.Commitment, zero) != isDummy {
			t.Fatalf("unexpected commitment for version %d: %x", ver, step.Commitment)
		}
	}
	for _, ver := range []uint32{0, 3, 4} {
		if _, err := tree.getVersion(label, ver); err != nil {
			t.Fatal(err)
		}
	}

	// Starting at the next version exactly doesn't skip anything.
	update, err = tree.Mutate([]LabelUpdate{{
		Label:           label,
		StartingVersion: new(uint32(5)),
		Values:          []structs.UpdateValue{signed([]byte("version 5"))},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	} else if len(update.Added) != 1 {
		t.Fatal("unexpected number of prefix tree entries added")
	}
}

func TestSkippedVersionsNewLabel(t *testing.T) {
	var label = []byte("label")

	config, _ := test.ConfigWithManager(t)
	tree, err := NewTree(config, test.MemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	update, err := tree.Mutate([]LabelUpdate{{
		Label:           label,
		StartingVersion: new(uint32(2)),
		Values:          []structs.UpdateValue{signed([]byte("version 2"))},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	} else if len(update.Added) != 3 {
		t.Fatal("unexpected number of prefix tree entries added")
	}
	index, err := tree.getIndex(label)
	if err != nil {
		t.Fatal(err)
	} else if !slices.Equal(index, []uint64{0, 0, 0}) {
		t.Fatalf("unexpected index: %v", index)
	}
}

func TestMutateRejected(t *testing.T) {
	var label = []byte("label")

	config, _ := test.ConfigWithManager(t)
	tree, err := NewTree(config, test.MemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tree.Mutate([]LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{signed([]byte("version 0")), signed([]byte("version 1"))}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	testCases := map[string][]LabelUpdate{
		"less than next version": {
			{Label: label, StartingVersion: new(uint32(1)), Values: []structs.UpdateValue{signed([]byte("a"))}},
		},
		"version counter overflow": {
			{Label: label, StartingVersion: new(uint32(math.MaxUint32)), Values: []structs.UpdateValue{signed([]byte("a")), signed([]byte("b"))}},
		},
		"starting version without values": {
			{Label: label, StartingVersion: new(uint32(2))},
		},
		"duplicate label": {
			{Label: label, Values: []structs.UpdateValue{signed([]byte("a"))}},
			{Label: label, Values: []structs.UpdateValue{signed([]byte("b"))}},
		},
	}
	for name, add := range testCases {
		if _, err := tree.Mutate(add, nil); err == nil {
			t.Fatalf("%s: expected mutation to be rejected", name)
		}
	}
	if tree.n() != 1 {
		t.Fatal("rejected mutations modified tree")
	}
}

func TestStartingVersionWithoutManager(t *testing.T) {
	tree, err := NewTree(test.Config(t), test.MemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tree.Mutate([]LabelUpdate{{
		Label:           []byte("label"),
		StartingVersion: new(uint32(0)),
		Values:          []structs.UpdateValue{{Value: []byte("a")}},
	}}, nil)
	if err == nil {
		t.Fatal("expected starting version to be rejected outside third party management")
	}
}
