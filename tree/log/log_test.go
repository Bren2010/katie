package log

import (
	"slices"
	"testing"

	"bytes"
	"crypto/rand"
	mrand "math/rand"

	"github.com/Bren2010/katie/crypto/suites"
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
	Data map[uint64][]byte
}

func (m *memoryStore) BatchGet(keys []uint64) (map[uint64][]byte, error) {
	out := make(map[uint64][]byte)

	for _, key := range keys {
		if d, ok := m.Data[key]; ok {
			out[key] = d
		}
	}

	return out, nil
}

func (m *memoryStore) BatchPut(data map[uint64][]byte) error {
	if m.Data == nil {
		m.Data = make(map[uint64][]byte)
	}
	for key, d := range data {
		buf := make([]byte, len(d))
		copy(buf, d)
		m.Data[key] = buf
	}
	return nil
}

func TestInclusionProof(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, new(memoryStore))
	calc := newSimpleRootCalculator(cs)
	var (
		nodes [][]byte
		roots [][]byte
	)

	checkTree := func(x, n int) {
		value, proof, err := tree.Get(uint64(x), uint64(n))
		if err != nil {
			t.Fatal(err)
		}
		assert(bytes.Equal(value, nodes[x]))
		if err := VerifyInclusionProof(cs, uint64(x), uint64(n), value, proof, roots[n-1]); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 2000; i++ {
		leaf := random()
		nodes = append(nodes, leaf)

		// Append to the tree.
		root, err := tree.Append(uint64(i), leaf)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, dup(root))
		n := i + 1

		calc.Add(leaf)
		assert(bytes.Equal(root, calc.Root()))

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
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, new(memoryStore))
	var (
		leaves [][]byte
		root   []byte
		err    error
	)
	for i := 0; i < 2000; i++ {
		leaf := random()
		leaves = append(leaves, leaf)

		root, err = tree.Append(uint64(i), leaf)
		if err != nil {
			t.Fatal(err)
		}
	}

	xDedup := make(map[uint64]struct{})
	for i := 0; i < 10; i++ {
		xDedup[uint64(mrand.Intn(2000))] = struct{}{}
	}
	x := make([]uint64, 0)
	for id := range xDedup {
		x = append(x, id)
	}
	slices.Sort(x)

	values := make([][]byte, 0)
	for _, id := range x {
		values = append(values, leaves[id])
	}

	proof, err := tree.GetBatch(x, 2000)
	if err != nil {
		t.Fatal(err)
	} else if err := VerifyBatchProof(cs, x, 2000, values, proof, root); err != nil {
		t.Fatal(err)
	}
}

func TestConsistencyProof(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, new(memoryStore))

	var roots [][]byte
	for i := 0; i < 2000; i++ {
		leaf := random()

		// Append to the tree.
		root, err := tree.Append(uint64(i), leaf)
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
			proof, err := tree.GetConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyConsistencyProof(cs, uint64(m), uint64(n), proof, roots[m-1], roots[n-1])
			if err != nil {
				t.Fatal(err)
			}

			if m > 1 {
				p := mrand.Intn(m-1) + 1
				proof, err := tree.GetConsistencyProof(uint64(p), uint64(m))
				if err != nil {
					t.Fatal(err)
				}
				err = VerifyConsistencyProof(cs, uint64(p), uint64(m), proof, roots[p-1], roots[m-1])
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
