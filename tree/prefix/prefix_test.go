package prefix

import (
	"testing"

	"crypto/rand"
	"encoding/json"
	"errors"
)

func random() []byte {
	out := make([]byte, 32)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

func assert(ok bool) {
	if !ok {
		panic("assertion failed")
	}
}

// memoryStore implements db.PrefixStore over an in-memory map.
type memoryStore struct {
	Data map[uint64][]byte
}

func (m *memoryStore) Get(key uint64) ([]byte, error) {
	out, ok := m.Data[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return out, nil
}

func (m *memoryStore) Put(key uint64, data []byte) error {
	if m.Data == nil {
		m.Data = make(map[uint64][]byte)
	}

	buf := make([]byte, len(data))
	copy(buf, data)
	m.Data[key] = buf

	return nil
}

func TestSearchInclusionProof(t *testing.T) {
	var (
		tree   = NewTree(new(memoryStore))
		leaves = make([][]byte, 0)

		root []byte
		err  error
	)

	for i := 0; i < 200; i++ {
		key := random()
		leaves = append(leaves, key)
		root, _, err = tree.Insert(uint64(len(leaves)-1), key)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < len(leaves); i++ {
		res, err := tree.Search(uint64(len(leaves)), leaves[i])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		parsed := &SearchResult{}
		if err := json.Unmarshal(raw, parsed); err != nil {
			t.Fatal(err)
		} else if _, ok := parsed.inner.(inclusionProof); !ok {
			t.Fatalf("inclusion proof not given: %T", parsed.inner)
		} else if err = Verify(root, leaves[i], parsed); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSearchNonInclusionProof(t *testing.T) {
	tree := NewTree(new(memoryStore))

	key := random()
	root, _, err := tree.Insert(0, key)
	if err != nil {
		t.Fatal(err)
	}
	key2 := random()
	key2[0] = key[0]
	root, _, err = tree.Insert(1, key2)
	if err != nil {
		t.Fatal(err)
	}

	// By leaf.
	key3 := make([]byte, 32)
	copy(key3, key)
	key3[31] ^= 1
	res, err := tree.Search(2, key3)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	parsed := &SearchResult{}
	if err := json.Unmarshal(raw, parsed); err != nil {
		t.Fatal(err)
	} else if _, ok := parsed.inner.(nonInclusionLeaf); !ok {
		t.Fatalf("non-inclusion-leaf proof not given: %T", parsed.inner)
	} else if err = Verify(root, key3, parsed); err != nil {
		t.Fatal(err)
	}

	// By parent.
	key4 := random()
	key4[0] = key[0] ^ byte(1<<4)
	res, err = tree.Search(2, key4)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(raw, parsed); err != nil {
		t.Fatal(err)
	} else if _, ok := parsed.inner.(nonInclusionParent); !ok {
		t.Fatalf("non-inclusion-parent proof not given: %T", parsed.inner)
	} else if err = Verify(root, key4, parsed); err != nil {
		t.Fatal(err)
	}
}

func TestInsert(t *testing.T) {
	tree := NewTree(new(memoryStore))

	key := random()  // Reference key.
	key2 := random() // Different from reference from the first bit.
	if (key[0] >> 7) == (key2[0] >> 7) {
		key2[0] ^= 1 << 7
	}
	key3 := random() // Same for the first bit then differs at second.
	key3[0] = (key[0] & 0x80) | (key3[0] & 0x7f)
	if (key[0] >> 6) == (key3[0] >> 6) {
		key3[0] ^= 1 << 6
	}
	key4 := random() // Same for the first 16 bytes then differs at next bit.
	copy(key4[:16], key[:16])
	if (key[16] >> 7) == (key4[16] >> 7) {
		key4[16] ^= 1 << 7
	}

	// Insert first item: one new db entry.
	root, _, err := tree.Insert(0, key)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tree.Search(1, key)
	if err != nil {
		t.Fatal(err)
	} else if _, ok := res.inner.(inclusionProof); !ok {
		t.Fatalf("inclusion proof not given: %T", res.inner)
	} else if err = Verify(root, key, res); err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 0)

	// Different first nibble: no new db entry.
	root, _, err = tree.Insert(1, key2)
	if err != nil {
		t.Fatal(err)
	}
	res, err = tree.Search(2, key2)
	if err != nil {
		t.Fatal(err)
	} else if _, ok := res.inner.(inclusionProof); !ok {
		t.Fatalf("inclusion proof not given: %T", res.inner)
	} else if err = Verify(root, key2, res); err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 1)

	// Same first nibble as another: new db entry.
	root, _, err = tree.Insert(2, key3)
	if err != nil {
		t.Fatal(err)
	}
	res, err = tree.Search(3, key3)
	if err != nil {
		t.Fatal(err)
	} else if _, ok := res.inner.(inclusionProof); !ok {
		t.Fatalf("inclusion proof not given: %T", res.inner)
	} else if err = Verify(root, key3, res); err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 2)

	// Many bytes in common: many new db entries.
	root, _, err = tree.Insert(3, key4)
	if err != nil {
		t.Fatal(err)
	}
	res, err = tree.Search(4, key4)
	if err != nil {
		t.Fatal(err)
	} else if _, ok := res.inner.(inclusionProof); !ok {
		t.Fatalf("inclusion proof not given: %T", res.inner)
	} else if err = Verify(root, key4, res); err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 129)

	// Duplicate entry: do nothing.
	root, _, err = tree.Insert(4, key)
	if err != nil {
		t.Fatal(err)
	}
	res, err = tree.Search(5, key)
	if err != nil {
		t.Fatal(err)
	} else if _, ok := res.inner.(inclusionProof); !ok {
		t.Fatalf("inclusion proof not given: %T", res.inner)
	} else if err = Verify(root, key, res); err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 129)
	assert(res.inner.(inclusionProof).value == 1)
}
