package prefix

import (
	"testing"

	"crypto/rand"
	"encoding/json"

	"github.com/JumpPrivacy/katie/db"
)

func random() []byte {
	out := make([]byte, 32)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

func dup(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func TestSearchInclusionProof(t *testing.T) {
	var (
		tree   = NewTree(db.NewMemoryKv(), 0)
		leaves = make([][]byte, 0)

		root []byte
		err  error
	)

	for i := 0; i < 200; i++ {
		key := random()
		leaves = append(leaves, dup(key))
		root, _, err = tree.Insert(key)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < len(leaves); i++ {
		res, err := tree.Search(leaves[i])
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
		}
		err = verifyInclusionProof(root, leaves[i], parsed.inner.(inclusionProof))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSearchNonInclusionProof(t *testing.T) {
	tree := NewTree(db.NewMemoryKv(), 0)

	key := random()
	root, _, err := tree.Insert(key)
	if err != nil {
		t.Fatal(err)
	}

	// By leaf.
	key2 := random()
	key2[0] = key[0] ^ byte(1<<3)
	res, err := tree.Search(key2)
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
	}
	err = verifyNonInclusionLeafProof(root, key2, parsed.inner.(nonInclusionLeaf))
	if err != nil {
		t.Fatal(err)
	}

	// By parent.
	key3 := random()
	key3[0] = key[0] ^ byte(1<<4)
	res, err = tree.Search(key3)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(raw, parsed); err != nil {
		t.Fatal(err)
	}
	err = verifyNonInclusionParentProof(root, key3, parsed.inner.(nonInclusionParent))
	if err != nil {
		t.Fatal(err)
	}
}

func TestInsert(t *testing.T) {
	tx := db.NewMemoryKv()
	tree := NewTree(tx, 0)

	key := random()  // Reference key.
	key2 := random() // Different from reference from the first nibble.
	if (key[0] >> 4) == (key2[0] >> 4) {
		key2[0] ^= 0x10
	}
	key3 := random() // Same for the first nibble then differs at second.
	key3[0] = (key[0] & 0xf0) | (key3[0] & 0x0f)
	if key[0] == key3[0] {
		key3[0] ^= 0x01
	}
	key4 := random() // Same for the first 16 bytes then differs at next nibble.
	copy(key4[:16], key[:16])
	if (key[16] >> 4) == (key4[16] >> 4) {
		key4[16] ^= 0x10
	}

	// Insert first item: one new db entry.
	root, _, err := tree.Insert(key)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tree.Search(key)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyInclusionProof(root, key, res.inner.(inclusionProof))
	if err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 4)
	assert(len(tx.Data) == 1)

	// Different first nibble: no new db entry.
	root, _, err = tree.Insert(key2)
	if err != nil {
		t.Fatal(err)
	}
	res, err = tree.Search(key2)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyInclusionProof(root, key2, res.inner.(inclusionProof))
	if err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 4)
	assert(len(tx.Data) == 1)

	// Same first nibble as another: new db entry.
	root, _, err = tree.Insert(key3)
	if err != nil {
		t.Fatal(err)
	}
	res, err = tree.Search(key3)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyInclusionProof(root, key3, res.inner.(inclusionProof))
	if err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 8)
	assert(len(tx.Data) == 2)

	// Many bytes in common: many new db entries.
	root, _, err = tree.Insert(key4)
	if err != nil {
		t.Fatal(err)
	}
	res, err = tree.Search(key4)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyInclusionProof(root, key4, res.inner.(inclusionProof))
	if err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 132)
	assert(len(tx.Data) == 33)

	// Duplicate entry: do nothing.
	root, _, err = tree.Insert(key)
	if err != nil {
		t.Fatal(err)
	}
	res, err = tree.Search(key)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyInclusionProof(root, key, res.inner.(inclusionProof))
	if err != nil {
		t.Fatal(err)
	}
	assert(len(res.inner.(inclusionProof).proof) == 132)
	assert(len(tx.Data) == 33)
}
