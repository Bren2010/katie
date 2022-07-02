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
