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

func TestGetBatchStateless(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, new(memoryStore))
	var (
		leaves [][]byte
		root   []byte
		err    error
	)
	for i := range 2000 {
		leaf := random()
		leaves = append(leaves, leaf)

		root, err = tree.Append(uint64(i), leaf)
		if err != nil {
			t.Fatal(err)
		}
	}

	for range 100 {
		xDedup := make(map[uint64]struct{})
		for range 10 {
			xDedup[uint64(mrand.Intn(2000))] = struct{}{}
		}
		x := make([]uint64, 0)
		for id := range xDedup {
			x = append(x, id)
		}
		slices.Sort(x)

		values := make([][]byte, 0, len(x))
		for _, id := range x {
			values = append(values, leaves[id])
		}

		proof, err := tree.GetBatch(x, 2000, nil)
		if err != nil {
			t.Fatal(err)
		}
		frontier, err := NewVerifier(cs).Evaluate(x, 2000, values, proof)
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
