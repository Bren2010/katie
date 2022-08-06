package log

import (
	"sort"
	"testing"

	"bytes"
	"crypto/rand"
	mrand "math/rand"
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

// memoryStore implements db.LogStore over an in-memory map.
type memoryStore struct {
	Data map[int][]byte
}

func (m *memoryStore) BatchGet(keys []int) (map[int][]byte, error) {
	out := make(map[int][]byte)

	for _, key := range keys {
		if d, ok := m.Data[key]; ok {
			out[key] = d
		}
	}

	return out, nil
}

func (m *memoryStore) BatchPut(data map[int][]byte) error {
	if m.Data == nil {
		m.Data = make(map[int][]byte)
	}
	for key, d := range data {
		buf := make([]byte, len(d))
		copy(buf, d)
		m.Data[key] = buf
	}
	return nil
}

func TestInclusionProof(t *testing.T) {
	tree := NewTree(new(memoryStore))
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

func TestBatchInclusionProof(t *testing.T) {
	tree := NewTree(new(memoryStore))
	var (
		leaves [][]byte
		root   []byte
		err    error
	)
	for i := 0; i < 2000; i++ {
		leaf := random()
		leaves = append(leaves, leaf)

		root, err = tree.Append(i, leaf)
		if err != nil {
			t.Fatal(err)
		}
	}

	xDedup := make(map[int]struct{})
	for i := 0; i < 10; i++ {
		xDedup[mrand.Intn(2000)] = struct{}{}
	}
	x := make([]int, 0)
	for id := range xDedup {
		x = append(x, id)
	}
	sort.Ints(x)

	values := make([][]byte, 0)
	for id := range x {
		values = append(values, leaves[id])
	}

	proof, err := tree.GetBatch(x, 2000)
	if err != nil {
		t.Fatal(err)
	} else if err := VerifyBatchProof(x, 2000, values, proof, root); err != nil {
		t.Fatal(err)
	}
}

func TestConsistencyProof(t *testing.T) {
	tree := NewTree(new(memoryStore))

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
