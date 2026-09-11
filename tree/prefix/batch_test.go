package prefix

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
)

// recordingStore wraps an in-memory key-value store and records the keys of
// every lookup that reaches it, so that tests can assert on which tiles were
// actually fetched from the database.
type recordingStore struct {
	inner   db.KeyValueStore
	Lookups [][]string
}

func newRecordingStore() *recordingStore {
	return &recordingStore{inner: db.NewMemoryKeyValueStore()}
}

func (kv *recordingStore) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	kv.Lookups = append(kv.Lookups, keys)
	return kv.inner.BatchGet(ctx, keys)
}

func (kv *recordingStore) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	return kv.inner.Commit(ctx, batch, treeHead)
}

func batchTestSetup() (suites.CipherSuite, *recordingStore, db.PrefixStore, node, node) {
	cs := suites.KTSha256P256{}

	// Build up two versions of the same tree.
	subtree := &parentNode{
		left:  leafNode{makeBytes(0b01000000), makeBytes(1)},
		right: leafNode{makeBytes(0b01100000), makeBytes(2)},
	}
	tree0 := &parentNode{
		left: &parentNode{
			left:  emptyNode{},
			right: subtree,
		},
		right: emptyNode{},
	}
	tree1 := &parentNode{
		left: &parentNode{
			left:  leafNode{makeBytes(0b00000000), makeBytes(3)},
			right: externalNode{subtree.Hash(cs), tileId{ver: 0, ctr: 0}},
		},
		right: emptyNode{},
	}
	brokenTile := &parentNode{
		left:  leafNode{makeBytes(0b10000000), makeBytes(4)},
		right: leafNode{makeBytes(0b11000000), makeBytes(5)},
	}
	tree2 := &parentNode{
		left:  externalNode{tree1.left.Hash(cs), tileId{ver: 1, ctr: 0}},
		right: externalNode{brokenTile.Hash(cs), tileId{ver: 2, ctr: 1}},
	}

	// Marshal and write trees to a prefix store.
	tile0 := tile{id: tileId{ver: 0, ctr: 0}, depth: 0, root: tree0}
	bytes0, err := tile0.Marshal(cs)
	if err != nil {
		panic(err)
	}

	tile1 := tile{id: tileId{ver: 1, ctr: 0}, depth: 0, root: tree1}
	bytes1, err := tile1.Marshal(cs)
	if err != nil {
		panic(err)
	}

	tile2 := tile{id: tileId{ver: 2, ctr: 0}, depth: 0, root: tree2}
	bytes2, err := tile2.Marshal(cs)
	if err != nil {
		panic(err)
	}

	tile3 := tile{id: tileId{ver: 2, ctr: 1}, depth: 1, root: brokenTile}
	bytes3, err := tile3.Marshal(cs)
	if err != nil {
		panic(err)
	}

	// A version of the tree whose only tile is a reference to the previous
	// version. Mutate doesn't produce tiles like this, but search should still
	// handle them correctly.
	tile4 := tile{
		id:    tileId{ver: 3, ctr: 0},
		depth: 0,
		root:  externalNode{tree2.Hash(cs), tileId{ver: 2, ctr: 0}},
	}
	bytes4, err := tile4.Marshal(cs)
	if err != nil {
		panic(err)
	}

	// Write the tiles through a writable store and commit them, so that the
	// searches under test read from the key-value store instead of being served
	// out of an uncommitted write batch.
	kv := newRecordingStore()
	writer := db.NewTransparencyStore(context.Background(), kv, false)
	ps := writer.PrefixStore()
	ps.Put(tile0.id.String(), bytes0)
	ps.Put(tile1.id.String(), bytes1)
	ps.Put(tile2.id.String(), bytes2)
	ps.Put(tile3.id.String(), bytes3)
	ps.Put(tile4.id.String(), bytes4)
	writer.PutTreeHead([]byte("tree head"))
	if err := writer.Commit(); err != nil {
		panic(err)
	}
	kv.Lookups = nil // Ignore the lookups made while setting up.

	// Reads go through a read-only store, which has no write batch of its own.
	store := db.NewTransparencyStore(context.Background(), kv, true).PrefixStore()

	return cs, kv, store, tree1, tree2
}

func TestSearchDepth0(t *testing.T) {
	cs, kv, store, tree1, _ := batchTestSetup()
	want := tree1.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{1: {makeBytes(0b00000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(kv.Lookups) != "[[p1:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[1].root
	_ = root.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(externalNode)
	_ = root.(*parentNode).right.(emptyNode)

	if got := root.Hash(cs); !bytes.Equal(got, want) {
		t.Fatal("tree hashes do not match")
	}
}

func TestSearchDepth1(t *testing.T) {
	cs, kv, store, tree1, _ := batchTestSetup()
	want := tree1.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{1: {makeBytes(0b01000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(kv.Lookups) != "[[p1:0] [p0:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[1].root
	_ = root.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).right.(leafNode)
	_ = root.(*parentNode).right.(emptyNode)

	if got := root.Hash(cs); !bytes.Equal(got, want) {
		t.Fatal("tree hashes do not match")
	}
}

func TestSearchDepth2(t *testing.T) {
	cs, kv, store, _, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{2: {makeBytes(0b01000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(kv.Lookups) != "[[p2:0] [p1:0] [p0:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[2].root
	_ = root.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).right.(leafNode)
	_ = root.(*parentNode).right.(externalNode)

	if got := root.Hash(cs); !bytes.Equal(want, got) {
		t.Fatal("tree hashes do not match")
	}
}

func TestBrokenTile(t *testing.T) {
	cs, kv, store, _, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{2: {makeBytes(0b11000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(kv.Lookups) != "[[p2:0] [p2:1]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[2].root
	_ = root.(*parentNode).left.(externalNode)
	_ = root.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).right.(*parentNode).right.(leafNode)

	if got := root.Hash(cs); !bytes.Equal(want, got) {
		t.Fatal("tree hashes do not match")
	}
}

func TestMultiVersionSearch(t *testing.T) {
	cs, kv, store, tree1, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	b := newBatch(cs, store)
	b.cache["1:0"] = &tile{id: tileId{ver: 1, ctr: 0}, depth: 0, root: tree1}
	res, state := b.initialize(map[uint64][][]byte{
		1: {makeBytes(0b01000000)},
		2: {makeBytes(0b01000000)},
	})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if lookups := fmt.Sprint(kv.Lookups); lookups != "[[p0:0 p2:0]]" && lookups != "[[p2:0 p0:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root1, root2 := res[1].root, res[2].root
	if root2.(*parentNode).left.(*parentNode) != root1.(*parentNode).left.(*parentNode) {
		t.Fatal("root1 was not correctly inserted as left child of root2")
	}
	_ = root2.(*parentNode).right.(externalNode)

	_ = root1.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = root1.(*parentNode).left.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = root1.(*parentNode).left.(*parentNode).right.(*parentNode).right.(leafNode)
	_ = root1.(*parentNode).right.(emptyNode)

	if got := root2.Hash(cs); !bytes.Equal(want, got) {
		t.Fatal("tree hashes do not match")
	}
}

// TestSearchExternalRootedTile checks that a search descends correctly through
// a tile whose root is an external node.
func TestSearchExternalRootedTile(t *testing.T) {
	cs, kv, store, _, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{3: {makeBytes(0b01000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(kv.Lookups) != "[[p3:0] [p2:0] [p1:0] [p0:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[3].root
	_ = root.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).right.(leafNode)
	_ = root.(*parentNode).right.(externalNode)

	if got := root.Hash(cs); !bytes.Equal(want, got) {
		t.Fatal("tree hashes do not match")
	}
}
