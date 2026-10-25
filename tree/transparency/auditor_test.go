package transparency

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/auditor"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/test"
)

// auditedTree returns a Tree in Third-Party Auditing mode, along with an
// auditor for it. The tree's clock is fixed so that every log entry has the
// same timestamp.
func auditedTree(t *testing.T) (*Tree, db.TransparencyStore, *auditor.Auditor) {
	config, auditorKey := test.ConfigWithAuditor(t)
	store := test.MemStore()
	tree, err := NewTree(config, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	tree.now = func() time.Time { return time.UnixMilli(1000) }
	a, err := auditor.NewAuditor(config.Public(), auditorKey, db.NewMemoryAuditorStore(), false)
	if err != nil {
		t.Fatal(err)
	}
	return tree, store, a
}

// auditedMutate adds a new log entry to the tree, has the auditor process it,
// and returns a copy of the auditor's new tree head.
func auditedMutate(t *testing.T, tree *Tree, a *auditor.Auditor, add []LabelUpdate) structs.AuditorTreeHead {
	update, err := tree.Mutate(add, nil)
	if err != nil {
		t.Fatal(err)
	} else if err := a.Process(update); err != nil {
		t.Fatal(err)
	}
	head, err := a.Commit()
	if err != nil {
		t.Fatal(err)
	}
	return *head
}

func TestSetAuditorTreeHead(t *testing.T) {
	tree, store, a := auditedTree(t)
	labels := test.RandomLabels(3)

	var heads []structs.AuditorTreeHead
	for i, label := range labels {
		heads = append(heads, auditedMutate(t, tree, a, []LabelUpdate{
			{Label: label, Values: []structs.UpdateValue{{Value: []byte{byte(i)}}}},
		}))
	}

	// Older tree heads are accepted until a newer one has been set.
	if err := tree.SetAuditorTreeHead(&heads[0]); err != nil {
		t.Fatal(err)
	} else if err := tree.SetAuditorTreeHead(&heads[2]); err != nil {
		t.Fatal(err)
	} else if tree.nP() == nil || *tree.nP() != 3 {
		t.Fatal("auditor tree head not applied")
	}
	err := tree.SetAuditorTreeHead(&heads[1])
	if err == nil || !strings.Contains(err.Error(), "previous auditor tree size") {
		t.Fatalf("expected older auditor tree head to be rejected, got: %v", err)
	}

	// The auditor tree head is persisted.
	reloaded, err := NewTree(tree.config, store, nil)
	if err != nil {
		t.Fatal(err)
	} else if reloaded.nP() == nil || *reloaded.nP() != 3 {
		t.Fatal("auditor tree head not persisted")
	}
}

func TestSetAuditorTreeHeadInvalid(t *testing.T) {
	tree, _, a := auditedTree(t)
	head := auditedMutate(t, tree, a, nil)
	auditedMutate(t, tree, a, nil)

	tamper := func(f func(h *structs.AuditorTreeHead)) *structs.AuditorTreeHead {
		out := head
		out.Signature = append([]byte(nil), head.Signature...)
		f(&out)
		return &out
	}
	testCases := []struct {
		name string
		head *structs.AuditorTreeHead
		err  string
	}{
		{"nil", nil, "no auditor tree head"},
		{"zero tree size", tamper(func(h *structs.AuditorTreeHead) { h.TreeSize = 0 }), "start position"},
		{"tree size too large", tamper(func(h *structs.AuditorTreeHead) { h.TreeSize = 3 }), "greater than transparency log"},
		{"wrong timestamp", tamper(func(h *structs.AuditorTreeHead) { h.Timestamp++ }), "timestamp does not match"},
		{"wrong tree size", tamper(func(h *structs.AuditorTreeHead) { h.TreeSize = 2 }), "signature"},
		{"bad signature", tamper(func(h *structs.AuditorTreeHead) { h.Signature[0] ^= 1 }), "signature"},
	}
	for _, tc := range testCases {
		err := tree.SetAuditorTreeHead(tc.head)
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("%s: expected error containing %q, got: %v", tc.name, tc.err, err)
		}
	}
	if tree.nP() != nil {
		t.Fatal("invalid auditor tree head was applied")
	}
}

func TestSetAuditorTreeHeadWrongMode(t *testing.T) {
	tree, err := NewTree(test.Config(t), test.MemStore(), nil)
	if err != nil {
		t.Fatal(err)
	} else if _, err := tree.Mutate(nil, nil); err != nil {
		t.Fatal(err)
	}
	err = tree.SetAuditorTreeHead(&structs.AuditorTreeHead{TreeSize: 1})
	if err == nil || !strings.Contains(err.Error(), "third party auditing") {
		t.Fatalf("expected error about mode, got: %v", err)
	}
}

func TestFullTreeHeadRequiresAuditorTreeHead(t *testing.T) {
	tree, _, a := auditedTree(t)
	label := test.RandomLabels(1)[0]
	head := auditedMutate(t, tree, a, []LabelUpdate{
		{Label: label, Values: []structs.UpdateValue{{Value: []byte{0}}}},
	})

	// No tree head is provided until an auditor tree head has been set.
	req := &structs.SearchRequest{Label: label}
	_, err := tree.Search(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "auditor tree head") {
		t.Fatalf("expected error about auditor tree head, got: %v", err)
	}

	if err := tree.SetAuditorTreeHead(&head); err != nil {
		t.Fatal(err)
	}
	res, err := tree.Search(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	} else if res.FullTreeHead.AuditorTreeHead == nil {
		t.Fatal("no auditor tree head provided")
	}
}
