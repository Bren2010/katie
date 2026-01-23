package log

import (
	"bytes"
	"slices"
	"testing"

	"crypto/rand"
	mrand "math/rand"

	"github.com/Bren2010/katie/crypto/suites"
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

// memoryStore implements LogStore over an in-memory map.
type memoryStore struct {
	Data map[uint64][]byte
}

func (m *memoryStore) BatchGet(keys []uint64) (map[uint64][]byte, error) {
	out := make(map[uint64][]byte)

	for _, key := range keys {
		if d, ok := m.Data[key]; ok {
			out[key] = dup(d)
		}
	}

	return out, nil
}

func (m *memoryStore) BatchPut(data map[uint64][]byte) error {
	if m.Data == nil {
		m.Data = make(map[uint64][]byte)
	}
	for key, d := range data {
		m.Data[key] = dup(d)
	}
	return nil
}

func TestGetBatch(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, new(memoryStore))

	// Populate tree with random leaves. Retain leaf and full subtree values
	// after each append.
	var (
		leaves       [][]byte
		fullSubtrees [][][]byte
	)
	for i := range uint64(2000) {
		leaf := random()
		leaves = append(leaves, leaf)

		subtrees, err := tree.Append(i, leaf)
		if err != nil {
			t.Fatal(err)
		}
		fullSubtrees = append(fullSubtrees, subtrees)
	}
	root, err := Root(cs, 2000, fullSubtrees[len(fullSubtrees)-1])
	if err != nil {
		t.Fatal(err)
	}

	for range 10 {
		// Choose 10 random leaf values to request inclusion for.
		dedup := make(map[uint64]struct{})
		for range 10 {
			dedup[uint64(mrand.Intn(2000))] = struct{}{}
		}
		entries := make([]uint64, 0)
		for x := range dedup {
			entries = append(entries, x)
		}
		slices.Sort(entries)

		values := make([][]byte, 0, len(entries))
		for _, x := range entries {
			values = append(values, leaves[x])
		}

		// Request inclusion proof for chosen leaves, with previously observed
		// tree size increasing in increments of 10.
		for i := uint64(0); i <= 2000; i += 10 {
			verifier := NewVerifier(cs)

			var m *uint64
			if i > 0 {
				m = &i
				if err := verifier.Retain(*m, fullSubtrees[*m-1]); err != nil {
					t.Fatal(err)
				}
			}

			proof, err := tree.GetBatch(entries, 2000, nil, m)
			if err != nil {
				t.Fatal(err)
			}
			subtrees, addl, err := verifier.Evaluate(entries, 2000, nil, values, proof)
			if err != nil {
				t.Fatal(err)
			} else if addl != nil {
				t.Fatal("expected additional full subtree values to be nil")
			}
			cand, err := Root(cs, 2000, subtrees)
			if err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(root, cand) {
				t.Fatal("root hash does not match")
			}
		}
	}
}

func TestAdditional(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, new(memoryStore))

	var (
		n, m     uint64 = 2000, 1000
		retained [][]byte
		roots    [][]byte
	)
	for i := range n {
		subtrees, err := tree.Append(i, random())
		if err != nil {
			t.Fatal(err)
		}
		if i+1 == m {
			retained = subtrees
		}
		root, err := Root(cs, i+1, subtrees)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
	}

	for nP := uint64(1); nP <= 2000; nP++ {
		proof, err := tree.GetBatch(nil, n, &nP, &m)
		if err != nil {
			t.Fatal(err)
		}

		verifier := NewVerifier(cs)
		if err := verifier.Retain(m, retained); err != nil {
			t.Fatal(err)
		}
		subtrees, addl, err := verifier.Evaluate(nil, n, &nP, nil, proof)
		if err != nil {
			t.Fatal(err)
		}
		root1, err := Root(cs, n, subtrees)
		if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(root1, roots[n-1]) {
			t.Fatal("unexpected root value computed")
		}
		root2, err := Root(cs, nP, addl)
		if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(root2, roots[nP-1]) {
			t.Fatal("unexpected root value computed")
		}
	}
}
