// Package log implements a Log Tree where new data is added as the rightmost
// leaf.
package log

import (
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log/math"
)

// treeHash returns the intermediate hash of left and right.
func treeHash(cs suites.CipherSuite, left, right *nodeData) []byte {
	h := cs.Hash()
	h.Write(left.marshal())
	h.Write(right.marshal())
	return h.Sum(nil)
}

// Tree is an implementation of a Log Tree where all new data is added as the
// rightmost leaf.
type Tree struct {
	cs suites.CipherSuite
	tx db.LogStore
}

func NewTree(cs suites.CipherSuite, tx db.LogStore) *Tree {
	return &Tree{cs: cs, tx: tx}
}

// fetch loads the chunks for the requested nodes from the database. It returns
// an error if not all chunks are found.
func (t *Tree) fetch(nodes []uint64) (*chunkSet, error) {
	dedup := make(map[uint64]struct{})
	for _, id := range nodes {
		dedup[math.Chunk(id)] = struct{}{}
	}
	ids := make([]uint64, 0, len(dedup))
	for id := range dedup {
		ids = append(ids, id)
	}

	data, err := t.tx.BatchGet(ids)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if _, ok := data[id]; !ok {
			return nil, errors.New("not all expected data was found in the database")
		}
	}

	return newChunkSet(t.cs, data)
}

// fetchSpecific returns the values for the requested nodes.
func (t *Tree) fetchSpecific(n uint64, nodes []uint64) ([][]byte, error) {
	set, err := t.fetch(nodes)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(nodes))
	for i, id := range nodes {
		out[i] = set.get(id).value
	}
	return out, nil
}

// GetBatch returns a batch proof for the given set of log entries.
func (t *Tree) GetBatch(entries []uint64, n uint64, m *uint64) ([][]byte, error) {
	if n == 0 || n > math.MaxTreeSize {
		return nil, errors.New("invalid value for current tree size")
	} else if m != nil && (*m == 0 || *m > n || *m > math.MaxTreeSize) {
		return nil, errors.New("invalid value for previous tree size")
	} else if len(entries) == 0 {
		return nil, nil
	}
	slices.Sort(entries)
	for i, x := range entries {
		if x >= n {
			return nil, errors.New("can not get leaf beyond right edge of tree")
		} else if i > 0 && entries[i-1] == x {
			return nil, errors.New("duplicate leaf index found")
		}
	}
	return t.fetchSpecific(n, math.BatchCopath(entries, n, m))
}

// Append adds a new element to the end of the log and returns the new root
// value. n is the current value; after this operation is complete, methods to
// this class should be called with n+1.
func (t *Tree) Append(n uint64, value []byte) ([]byte, error) {
	if n >= math.MaxTreeSize {
		return nil, errors.New("invalid value for current tree size")
	} else if len(value) != t.cs.HashSize() {
		return nil, errors.New("value has wrong length")
	}

	// Calculate the set of nodes that we'll need to update / create.
	leaf := 2 * n
	path := []uint64{leaf}
	for _, x := range math.DirectPath(leaf, n+1) {
		if !math.IsFullSubtree(x, n+1) {
			break
		} else if math.Level(x)%4 == 0 {
			path = append(path, x)
		}
	}

	alreadyExists := make(map[uint64]struct{})
	if n > 0 {
		alreadyExists[math.Chunk(leaf-2)] = struct{}{}
		for _, id := range math.DirectPath(leaf-2, n) {
			alreadyExists[math.Chunk(id)] = struct{}{}
		}
	}

	updateChunks := make([]uint64, 0)
	createChunks := make(map[uint64]struct{})
	for _, id := range path {
		id = math.Chunk(id)
		if _, ok := alreadyExists[id]; ok {
			updateChunks = append(updateChunks, id)
		} else {
			createChunks[id] = struct{}{}
		}
	}

	// Fetch the chunks we'll need to update along with nodes we'll need to know
	// to compute the new root or updated intermediates.
	set, err := t.fetch(append(updateChunks, math.Copath(leaf, n+1)...))
	if err != nil {
		return nil, err
	}

	// Add any new chunks to the set and set the correct hashes everywhere.
	for id := range createChunks {
		set.add(id)
	}
	set.set(leaf, value)
	for _, x := range path[1:] {
		l, r := math.Left(x), math.RightStep(x)
		intermediate := treeHash(t.cs, set.get(l), set.get(r))
		set.set(x, intermediate)
	}

	// Commit to database and return new root.
	data := set.marshal()
	if err := t.tx.BatchPut(data); err != nil {
		return nil, err
	}

	// Compute root hash.
	fullSubtrees := math.FullSubtrees(math.Root(n+1), n+1)
	slices.Reverse(fullSubtrees)

	acc := set.get(fullSubtrees[0])
	for _, x := range fullSubtrees[1:] {
		acc = &nodeData{leaf: false, value: treeHash(t.cs, set.get(x), acc)}
	}
	return acc.value, nil
}
