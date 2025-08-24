package prefix

import (
	"bytes"
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

func dupNode(cs suites.CipherSuite, n node) node {
	buf := &bytes.Buffer{}
	if err := n.Marshal(buf); err != nil {
		panic(err)
	}
	m, err := unmarshalNode(cs, buf)
	if err != nil {
		panic(err)
	}
	return m
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
	bytes0, err := tile0.Marshal()
	if err != nil {
		panic(err)
	}

	tile1 := tile{id: tileId{ver: 1, ctr: 0}, depth: 0, root: tree1}
	bytes1, err := tile1.Marshal()
	if err != nil {
		panic(err)
	}

	tile2 := tile{id: tileId{ver: 2, ctr: 0}, depth: 0, root: tree2}
	bytes2, err := tile2.Marshal()
	if err != nil {
		panic(err)
	}

	tile3 := tile{id: tileId{ver: 2, ctr: 1}, depth: 1, root: brokenTile}
	bytes3, err := tile3.Marshal()
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

	var tree node = dupNode(cs, tree1)
	b := &batch{cs: cs, tx: store}
	err := b.search(map[node][]cursor{
		tree: {{vrfOutput: makeBytes(0b00000000), depth: 0}},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(store.lookups) > 0 {
		t.Fatal("no database lookups expected")
	}
	_ = tree.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = tree.(*parentNode).left.(*parentNode).right.(externalNode)
	_ = tree.(*parentNode).right.(emptyNode)

	if got := tree.Hash(cs); !bytes.Equal(got, want) {
		t.Fatal("tree hashes do not match")
	}
}

func TestSearchDepth1(t *testing.T) {
	cs, store, tree1, _ := batchTestSetup()
	want := tree1.Hash(cs)

	var tree node = dupNode(cs, tree1)
	b := &batch{cs: cs, tx: store}
	err := b.search(map[node][]cursor{
		tree: {{vrfOutput: makeBytes(0b01000000), depth: 0}},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(store.lookups) != 1 {
		t.Fatal("exactly one database lookup expected")
	}
	_ = tree.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = tree.(*parentNode).left.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = tree.(*parentNode).left.(*parentNode).right.(*parentNode).right.(leafNode)
	_ = tree.(*parentNode).right.(emptyNode)

	if got := tree.Hash(cs); !bytes.Equal(got, want) {
		t.Fatal("tree hashes do not match")
	}
}

func TestSearchDepth2(t *testing.T) {
	cs, store, _, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	var tree node = dupNode(cs, tree2)
	b := &batch{cs: cs, tx: store}
	err := b.search(map[node][]cursor{
		tree: {{vrfOutput: makeBytes(0b01000000), depth: 0}},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(store.lookups) != 2 {
		t.Fatal("exactly two database lookups expected")
	}
	_ = tree.(*parentNode).left.(*parentNode).left.(leafNode)
	_ = tree.(*parentNode).left.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = tree.(*parentNode).left.(*parentNode).right.(*parentNode).right.(leafNode)
	_ = tree.(*parentNode).right.(externalNode)

	if got := tree.Hash(cs); !bytes.Equal(want, got) {
		t.Fatal("tree hashes do not match")
	}
}

func TestBrokenTile(t *testing.T) {
	cs, store, _, tree2 := batchTestSetup()
	want := tree2.Hash(cs)

	var tree node = dupNode(cs, tree2)
	b := &batch{cs: cs, tx: store}
	err := b.search(map[node][]cursor{
		tree: {{vrfOutput: makeBytes(0b11000000), depth: 0}},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(store.lookups) != 1 {
		t.Fatal("exactly one database lookup expected")
	}
	_ = tree.(*parentNode).left.(externalNode)
	_ = tree.(*parentNode).right.(*parentNode).left.(leafNode)
	_ = tree.(*parentNode).right.(*parentNode).right.(leafNode)

	if got := tree.Hash(cs); !bytes.Equal(want, got) {
		t.Fatal("tree hashes do not match")
	}
}
