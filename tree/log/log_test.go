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

	// Populate tree with random leaves. Retain leaf values and frontier after
	// each append.
	var (
		leaves   [][]byte
		frontier [][]byte
		err      error
	)
	for i := range uint64(2000) {
		leaf := random()
		leaves = append(leaves, leaf)

		frontier, err = tree.Append(i, leaf)
		if err != nil {
			t.Fatal(err)
		}
	}
	root, err := Root(cs, 2000, frontier)
	if err != nil {
		t.Fatal(err)
	}

	for range 100 {
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

		// Request inclusion proof for chosen leaves, with previously-observed
		// tree size increasing in increments of 10.
		for i := uint64(0); i <= 2000; i += 10 {
			var m *uint64
			if i > 0 {
				m = &i
			}
			proof, err := tree.GetBatch(entries, 2000, m)
			if err != nil {
				t.Fatal(err)
			}
			frontier, err := NewVerifier(cs).Evaluate(entries, 2000, values, proof)
			if err != nil {
				t.Fatal(err)
			}
			cand, err := Root(cs, 2000, frontier)
			if err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(root, cand) {
				t.Fatal("root hash does not match")
			}
		}
	}
}
