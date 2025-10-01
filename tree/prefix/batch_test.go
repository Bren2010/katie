package prefix

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
)

func dup(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

type memoryPrefixStore struct {
	data    map[string][]byte
	lookups [][]string
}

func newMemoryPrefixStore() *memoryPrefixStore {
	return &memoryPrefixStore{data: make(map[string][]byte)}
}

func (m *memoryPrefixStore) BatchGet(keys []string) (map[string][]byte, error) {
	m.lookups = append(m.lookups, keys)

	out := make(map[string][]byte)
	for _, key := range keys {
		if val, ok := m.data[key]; ok {
			out[key] = dup(val)
		}
	}
	return out, nil
}

func (m *memoryPrefixStore) BatchPut(data map[string][]byte) error {
	for key, val := range data {
		m.data[key] = dup(val)
	}
	return nil
}

func batchTestSetup() (suites.CipherSuite, *memoryPrefixStore, node, node) {
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

	store := newMemoryPrefixStore()
	store.BatchPut(map[string][]byte{
		tile0.id.String(): bytes0,
		tile1.id.String(): bytes1,
		tile2.id.String(): bytes2,
		tile3.id.String(): bytes3,
	})

	return cs, store, tree1, tree2
}

func TestSearchDepth0(t *testing.T) {
	cs, store, tree1, _ := batchTestSetup()
	want := tree1.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{1: {makeBytes(0b00000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(store.lookups) != "[[1:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[0].root
	_ = root.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(externalNode)
	_ = root.(*parentNode).right.(emptyNode)

	if got := root.Hash(cs); !bytes.Equal(got, want) {
		t.Fatal("tree hashes do not match")
	}
}

func TestSearchDepth1(t *testing.T) {
	cs, store, tree1, _ := batchTestSetup()
	want := tree1.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{1: {makeBytes(0b01000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(store.lookups) != "[[1:0] [0:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[0].root
	_ = root.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).right.(leafNode)
	_ = root.(*parentNode).right.(emptyNode)

	if got := root.Hash(cs); !bytes.Equal(got, want) {
		t.Fatal("tree hashes do not match")
	}
}

func TestSearchDepth2(t *testing.T) {
	cs, store, _, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{2: {makeBytes(0b01000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(store.lookups) != "[[2:0] [1:0] [0:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[0].root
	_ = root.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).left.(*parentNode).right.(*parentNode).right.(leafNode)
	_ = root.(*parentNode).right.(externalNode)

	if got := root.Hash(cs); !bytes.Equal(want, got) {
		t.Fatal("tree hashes do not match")
	}
}

func TestBrokenTile(t *testing.T) {
	cs, store, _, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	b := newBatch(cs, store)
	res, state := b.initialize(map[uint64][][]byte{2: {makeBytes(0b11000000)}})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(store.lookups) != "[[2:0] [2:1]]" {
		t.Fatal("unexpected database lookups")
	}

	root := res[0].root
	_ = root.(*parentNode).left.(externalNode)
	_ = root.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = root.(*parentNode).right.(*parentNode).right.(leafNode)

	if got := root.Hash(cs); !bytes.Equal(want, got) {
		t.Fatal("tree hashes do not match")
	}
}

func TestMultiVersionSearch(t *testing.T) {
	cs, store, tree1, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	b := newBatch(cs, store)
	b.cache["1:0"] = tile{id: tileId{ver: 1, ctr: 0}, depth: 0, root: tree1}
	res, state := b.initialize(map[uint64][][]byte{
		1: {makeBytes(0b01000000)},
		2: {makeBytes(0b01000000)},
	})
	if err := b.search(state); err != nil {
		t.Fatal(err)
	} else if lookups := fmt.Sprint(store.lookups); lookups != "[[0:0 2:0]]" && lookups != "[[2:0 0:0]]" {
		t.Fatal("unexpected database lookups")
	}

	root1, root2 := res[0].root, res[1].root
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
