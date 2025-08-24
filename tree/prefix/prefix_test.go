package prefix

import (
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
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

func newMemoryPrefixStore() db.PrefixStore {
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

func TestBatchSearch(t *testing.T) {
	cs := suites.KTSha256P256{}

	// Build up two versions of the same tree.
	subtree := parentNode{
		left:  leafNode{makeBytes(0b01000000), makeBytes(1)},
		right: leafNode{makeBytes(0b01100000), makeBytes(2)},
	}
	tree0 := parentNode{
		left: parentNode{
			left:  emptyNode{},
			right: subtree,
		},
		right: emptyNode{},
	}
	tree1 := parentNode{
		left: parentNode{
			left:  leafNode{makeBytes(0b00000000), makeBytes(3)},
			right: externalNode{subtree.Hash(cs), tileId{ver: 0, ctr: 0}},
		},
		right: emptyNode{},
	}

	// Marshal and write trees to a prefix store.
	tile0 := tile{id: tileId{ver: 0, ctr: 0}, depth: 0, root: tree0}
	bytes0, err := tile0.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tile1 := tile{id: tileId{ver: 1, ctr: 0}, depth: 0, root: tree1}
	bytes1, err := tile1.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryPrefixStore()
	store.BatchPut(map[string][]byte{
		tile0.id.String(): bytes0,
		tile1.id.String(): bytes1,
	})

	// Try search.
	var tree node = tree1
	b := &batch{cs: cs, tx: store}
	err = b.search(map[*node][]cursor{
		&tree: []cursor{{vrfOutput: makeBytes(0b00000000), depth: 0}},
	})
	if err != nil {
		t.Fatal(err)
	}
}
