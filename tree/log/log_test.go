package log

import (
	"testing"

	"bytes"
	"crypto/rand"
	mrand "math/rand"

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

// verifyInclusionProof checks that `proof` is a valid inclusion proof for
// `value` at position `x` in a tree with the given root.
func verifyInclusionProof(x, n int, value []byte, proof *InclusionProof, root []byte) {
	for _, elem := range proof.Hashes {
		assert(len(elem) == 32)
	}
	for _, elem := range proof.Values {
		assert(len(elem) == 32)
	}
	for _, elem := range proof.Intermediates {
		assert(len(elem) == 32)
	}

	x = 2 * x
	path := copath(x, n)

	pn := len(path)
	pnl := len(noLeaves(path))
	assert(len(proof.Hashes) == pnl)
	assert(len(proof.Values) == pn)
	assert(len(proof.Intermediates) == pn-1)

	proofNodes := make([]*nodeData, len(path))
	j := 0
	for i := 0; i < len(path); i++ {
		leaf := isLeaf(path[i])

		var h []byte
		if !leaf {
			h = proof.Hashes[j]
			j++
		}

		proofNodes[i] = &nodeData{leaf: leaf, hash: h, value: proof.Values[i]}
	}

	acc := &nodeData{leaf: true, hash: nil, value: value}
	for i, nd := range proofNodes {
		var val []byte
		if i != len(proofNodes)-1 {
			val = proof.Intermediates[i]
		}
		var hash []byte
		if x < path[i] {
			hash = treeHash(acc, nd)
		} else {
			hash = treeHash(nd, acc)
		}

		acc = &nodeData{leaf: false, hash: hash, value: val}
		x = path[i]
	}

	assert(bytes.Equal(acc.hash, root))
}

func TestGet(t *testing.T) {
	tree := NewTree(db.NewMemoryTx())

	var (
		nodes [][]byte
		root  []byte
		err   error
	)
	for i := 0; i < 2000; i++ {
		path := directPath(2*i, i+1)

		// Generate new leaf and parent values.
		leaf := random()
		if len(nodes) == 0 {
			nodes = append(nodes, leaf)
		} else {
			nodes = append(nodes, nil, leaf)
		}
		parents := make([][]byte, len(path))
		for i, x := range path {
			intermediate := random()
			nodes[x] = dup(intermediate)
			parents[i] = intermediate
		}

		// Append to the tree.
		root, err = tree.Append(i, leaf, parents)
		if err != nil {
			t.Fatal(err)
		}
		n := i + 1

		// Do inclusion proofs for a few random entries.
		if n < 5 {
			continue
		}
		for j := 0; j < 5; j++ {
			x := mrand.Intn(n)
			value, proof, err := tree.Get(x, n)
			if err != nil {
				t.Fatal(err)
			}

			// Check that correct value was given and inclusion proof works.
			assert(bytes.Equal(value, nodes[2*x]))
			verifyInclusionProof(x, n, value, proof, root)

			// Check that the copath/intermediate values match as well.
			for i, id := range copath(2*x, n) {
				assert(bytes.Equal(proof.Values[i], nodes[id]))
			}
			dpath := directPath(2*x, n)
			for i, id := range dpath[:len(dpath)-1] {
				assert(bytes.Equal(proof.Intermediates[i], nodes[id]))
			}
		}
	}
}
