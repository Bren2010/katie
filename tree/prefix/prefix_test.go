package prefix

import (
	"testing"

	"bytes"
	"crypto/rand"

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

func verifyProof(root, key, value []byte, proof [][]byte) {
	for i := 0; i < len(proof); i++ {
		n := len(proof) - i - 1
		b := key[n/8] >> (7 - (n % 8)) & 1

		if b == 0 {
			value = parentHash(value, proof[n])
		} else {
			value = parentHash(proof[n], value)
		}
	}

	assert(bytes.Equal(root, value))
}

// verifyInclusionProof checks that `res`, which the output of search, is a
// valid inclusion proof for `key` in a tree with the given root.
func verifyInclusionProof(root, key []byte, res inclusionProof) {
	n := len(res.proof)
	assert(n > 0 && n%4 == 0)

	leaf := leafHash(buildSuffix(key, n/8, n%8 == 0))
	verifyProof(root, key, leaf, res.proof)
}

// verifyNonInclusionLeafProof checks that `res`, which the output of search, is
// a valid non-inclusion proof for `key` in a tree with the given root.
func verifyNonInclusionLeafProof(root, key []byte, res nonInclusionLeaf) {
	n := len(res.proof)

	assert(n > 0 && n%4 == 0)
	assert((n/8)+len(res.suffix) == 32)
	if n%8 == 4 {
		assert(res.suffix[0]>>4 == 0)
	}
	assert(!bytes.Equal(
		buildSuffix(key, n/8, n%8 == 0),
		res.suffix,
	))
	verifyProof(root, key, leafHash(res.suffix), res.proof)
}

// verifyNonInclusionParentProof checks that `res`, which the output of search,
// is a valid non-inclusion proof for `key` in a tree with the given root.
func verifyNonInclusionParentProof(root, key []byte, res nonInclusionParent) {
	n := len(res.proof)
	assert(n > 0)
	verifyProof(root, key, make([]byte, 32), res.proof)
}

func TestSearchInclusionProof(t *testing.T) {
	var (
		tree   = NewTree(db.NewMemoryTx(), 0)
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
		verifyInclusionProof(root, leaves[i], res.(inclusionProof))
	}
}

func TestSearchNonInclusionProof(t *testing.T) {
	tree := NewTree(db.NewMemoryTx(), 0)

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
	verifyNonInclusionLeafProof(root, key2, res.(nonInclusionLeaf))

	// By parent.
	key3 := random()
	key3[0] = key[0] ^ byte(1<<4)
	res, err = tree.Search(key3)
	if err != nil {
		t.Fatal(err)
	}
	verifyNonInclusionParentProof(root, key3, res.(nonInclusionParent))
}

func TestInsert(t *testing.T) {
	tx := db.NewMemoryTx()
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
	verifyInclusionProof(root, key, res.(inclusionProof))
	assert(len(res.(inclusionProof).proof) == 4)
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
	verifyInclusionProof(root, key2, res.(inclusionProof))
	assert(len(res.(inclusionProof).proof) == 4)
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
	verifyInclusionProof(root, key3, res.(inclusionProof))
	assert(len(res.(inclusionProof).proof) == 8)
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
	verifyInclusionProof(root, key4, res.(inclusionProof))
	assert(len(res.(inclusionProof).proof) == 132)
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
	verifyInclusionProof(root, key, res.(inclusionProof))
	assert(len(res.(inclusionProof).proof) == 132)
	assert(len(tx.Data) == 33)
}
