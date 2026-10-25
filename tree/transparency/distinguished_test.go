package transparency

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/test"
)

// distinguishedTree returns a Tree with `n` log entries, each one Reasonable
// Monitoring Window after the previous, such that every log entry is
// distinguished. It also returns a function that advances the tree's clock by
// one Reasonable Monitoring Window and adds a log entry.
func distinguishedTree(t *testing.T, n int, recent structs.RecentFunc) (*Tree, func()) {
	config := test.Config(t)
	config.Recent = recent
	tree, err := NewTree(config, test.MemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.UnixMilli(1000)
	tree.now = func() time.Time { return clock }

	add := func() {
		clock = clock.Add(time.Duration(config.ReasonableMonitoringWindow) * time.Millisecond)
		if _, err := tree.Mutate(nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	for range n {
		add()
	}
	return tree, add
}

func newTestClient(t *testing.T, tree *Tree, recent structs.RecentFunc) *Client {
	config := tree.config.Public()
	config.Recent = recent
	client, err := NewClient(config, db.NewMemoryClientStore())
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return tree.now() }
	return client
}

// walk runs a WalkDistinguished request from `client` against `tree`. It checks
// that the returned DistinguishedHead contains the correct root value for each
// recent distinguished log entry.
func walk(client *Client, tree *Tree, stop *uint64) ([]uint64, *structs.DistinguishedResponse, error) {
	req, verify, err := client.WalkDistinguished(stop)
	if err != nil {
		return nil, nil, err
	}
	res, err := tree.WalkDistinguished(context.Background(), req)
	if err != nil {
		return nil, nil, err
	}
	found, head, err := verify(res)
	if err != nil {
		return nil, nil, err
	} else if len(head.Heads) != len(found) {
		return nil, nil, fmt.Errorf("unexpected number of heads: %d", len(head.Heads))
	}
	for i, x := range found {
		expected, err := logRoot(tree, x+1)
		if err != nil {
			return nil, nil, err
		} else if !bytes.Equal(head.Heads[i], expected) {
			return nil, nil, fmt.Errorf("unexpected root value for log entry %d", x)
		}
	}
	return found, res, nil
}

// logRoot returns the root value of the tree's log tree at size `n`.
func logRoot(tree *Tree, n uint64) ([]byte, error) {
	fullSubtrees, err := log.NewTree(tree.config.Suite, tree.tx.LogStore()).GetFullSubtrees(n)
	if err != nil {
		return nil, err
	}
	return log.Root(tree.config.Suite, n, fullSubtrees)
}

func TestWalkDistinguished(t *testing.T) {
	recent := algorithms.RecentCount(3)
	tree, add := distinguishedTree(t, 15, recent)
	client := newTestClient(t, tree, recent)

	// A client with no state gets a full tree head.
	found, res, err := walk(client, tree, nil)
	if err != nil {
		t.Fatal(err)
	} else if !slices.Equal(found, []uint64{12, 13, 14}) {
		t.Fatalf("unexpected distinguished log entries: %v", found)
	} else if res.FullTreeHead.TreeHead == nil {
		t.Fatal("expected full tree head")
	}

	// A client whose state is up-to-date gets the same tree head, and can stop
	// early.
	found, res, err = walk(client, tree, new(uint64(12)))
	if err != nil {
		t.Fatal(err)
	} else if !slices.Equal(found, []uint64{13, 14}) {
		t.Fatalf("unexpected distinguished log entries: %v", found)
	} else if res.FullTreeHead.TreeHead != nil {
		t.Fatal("expected same tree head to be reused")
	}

	// A client with stale state sees the new log entries.
	add()
	add()
	found, _, err = walk(client, tree, nil)
	if err != nil {
		t.Fatal(err)
	} else if !slices.Equal(found, []uint64{14, 15, 16}) {
		t.Fatalf("unexpected distinguished log entries: %v", found)
	}
}

func TestWalkDistinguishedRejected(t *testing.T) {
	recent := algorithms.RecentCount(3)
	tree, _ := distinguishedTree(t, 15, recent)

	// The stopping position must be in the tree.
	client := newTestClient(t, tree, recent)
	req, _, err := client.WalkDistinguished(new(uint64(15)))
	if err != nil {
		t.Fatal(err)
	} else if _, err := tree.WalkDistinguished(context.Background(), req); err == nil {
		t.Fatal("expected stopping position outside of tree to be rejected")
	}

	// A client whose definition of "recent" includes more log entries than
	// the Transparency Log's can't verify the response.
	client = newTestClient(t, tree, algorithms.RecentCount(5))
	if _, _, err := walk(client, tree, nil); err == nil {
		t.Fatal("expected response to fail verification")
	}

	// A client whose definition of "recent" includes fewer log entries than
	// the Transparency Log's rejects the extra proof data.
	client = newTestClient(t, tree, algorithms.RecentCount(1))
	if _, _, err := walk(client, tree, nil); err == nil {
		t.Fatal("expected response to fail verification")
	}

	// Walking distinguished log entries requires a definition of "recent".
	client = newTestClient(t, tree, nil)
	if _, _, err := client.WalkDistinguished(nil); err == nil {
		t.Fatal("expected client without definition of recent to fail")
	}
	tree.config.Recent = nil
	if _, err := tree.WalkDistinguished(context.Background(), &structs.DistinguishedRequest{}); err == nil {
		t.Fatal("expected tree without definition of recent to fail")
	}
}
