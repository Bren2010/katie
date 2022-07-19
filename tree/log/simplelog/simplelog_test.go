package simplelog

import (
	"testing"

	"bytes"
	"crypto/rand"
	mrand "math/rand"

	"github.com/JumpPrivacy/katie/db"
)

func assert(ok bool) {
	if !ok {
		panic("Assertion failed.")
	}
}

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
	tree := NewTree(db.NewMemoryKv())
	calc := newSimpleRootCalculator()
	var (
		nodes [][]byte
		roots [][]byte
	)

	checkTree := func(x, n int) {
		value, proof, err := tree.Get(x, n)
		if err != nil {
			t.Fatal(err)
		}
		assert(bytes.Equal(value, nodes[x]))
		if err := VerifyInclusionProof(x, n, value, proof, roots[n-1]); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 2000; i++ {
		leaf := random()
		nodes = append(nodes, leaf)

		// Append to the tree.
		root, err := tree.Append(i, leaf)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, dup(root))
		n := i + 1

		calc.Add(leaf)
		if calculated, err := calc.Root(); err != nil {
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
			checkTree(x, n)

			m := mrand.Intn(n-1) + 1
			x = mrand.Intn(m)
			checkTree(x, m)
		}
	}
}

func TestConsistencyProof(t *testing.T) {
	tree := NewTree(db.NewMemoryKv())

	var roots [][]byte
	for i := 0; i < 2000; i++ {
		leaf := random()

		// Append to the tree.
		root, err := tree.Append(i, leaf)
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
