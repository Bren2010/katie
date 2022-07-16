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

func TestInclusionProof(t *testing.T) {
	tree := NewTree(db.NewMemoryTx())
	calc := newSimpleRootCalculator()
	var nodes [][]byte

	checkTree := func(x, n int, root []byte, latest bool) {
		value, proof, err := tree.Get(x, n)
		if err != nil {
			t.Fatal(err)
		}

		// Check that correct value was given and inclusion proof works.
		assert(bytes.Equal(value, nodes[2*x]))
		if err := VerifyInclusionProof(x, n, value, proof, root); err != nil {
			t.Fatal(err)
		}

		// Check that the copath/intermediate values match as well.
		if latest {
			for i, id := range copath(2*x, n) {
				assert(bytes.Equal(proof.Values[i], nodes[id]))
			}
			dpath := directPath(2*x, n)
			for i, id := range dpath[:len(dpath)-1] {
				assert(bytes.Equal(proof.Intermediates[i], nodes[id]))
			}
		}
	}

	var roots [][]byte
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
		root, err := tree.Append(i, leaf, parents)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, dup(root))
		n := i + 1

		if err := calc.Add(leaf, parents); err != nil {
			t.Fatal(err)
		} else if calculated, err := calc.Root(); err != nil {
			t.Fatal(err)
		} else {
			assert(bytes.Equal(root, calculated))
		}

		// Do inclusion proofs for a few random entries.
		if n < 5 {
			continue
		}
		for j := 0; j < 5; j++ {
			x := mrand.Intn(n)
			checkTree(x, n, root, true)

			m := mrand.Intn(n-1) + 1
			x = mrand.Intn(m)
			checkTree(x, m, roots[m-1], false)
		}
	}
}

func TestConsistencyProof(t *testing.T) {
	tree := NewTree(db.NewMemoryTx())

	var roots [][]byte
	for i := 0; i < 2000; i++ {
		path := directPath(2*i, i+1)

		// Generate new leaf and parent values.
		leaf := random()
		parents := make([][]byte, len(path))
		for i, _ := range path {
			intermediate := random()
			parents[i] = intermediate
		}

		// Append to the tree.
		root, err := tree.Append(i, leaf, parents)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, dup(root))
		n := i + 1

		// Do consistency proofs for a few random revisions.
		if n < 5 {
			continue
		}
		for j := 0; j < 5; j++ {
			m := mrand.Intn(n-1) + 1
			proof, err := tree.GetConsistencyProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyConsistencyProof(m, n, proof, roots[m-1], roots[n-1])
			if err != nil {
				t.Fatal(err)
			}

			if m > 1 {
				p := mrand.Intn(m-1) + 1
				proof, err := tree.GetConsistencyProof(p, m)
				if err != nil {
					t.Fatal(err)
				}
				err = VerifyConsistencyProof(p, m, proof, roots[p-1], roots[m-1])
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
