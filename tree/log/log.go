// Package log implements a log-based Merkle tree where new data is added
// as the right-most leaf.
package log

import (
	"crypto/sha256"
	"fmt"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log/math"
)

// treeHash returns the intermediate hash of left and right.
func treeHash(left, right *nodeData) []byte {
	if err := left.validate(); err != nil {
		panic(err)
	} else if err := right.validate(); err != nil {
		panic(err)
	}

	input := append(left.marshal(), right.marshal()...)
	output := sha256.Sum256(input)
	return output[:]
}

// Tree is an implementation of a log-based Merkle tree where all new data is
// added as the right-most leaf.
type Tree struct {
	tx db.LogStore
}

func NewTree(tx db.LogStore) *Tree {
	return &Tree{tx: tx}
}

// fetch loads the chunks for the requested nodes from the database. It returns
// an error if not all chunks are found.
func (t *Tree) fetch(n int, nodes []int) (*chunkSet, error) {
	dedup := make(map[int]struct{})
	for _, id := range nodes {
		dedup[math.Chunk(id)] = struct{}{}
	}
	ids := make([]int, 0, len(dedup))
	for id := range dedup {
		ids = append(ids, id)
	}

	data, err := t.tx.BatchGet(ids)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if _, ok := data[id]; !ok {
			return nil, fmt.Errorf("not all expected data was found in the database")
		}
	}

	// Parse chunk set.
	set, err := newChunkSet(n, data)
	if err != nil {
		return nil, err
	}
	return set, nil
}

// fetchSpecific returns the values for the requested nodes, accounting for the
// ragged right-edge of the tree.
func (t *Tree) fetchSpecific(n int, nodes []int) ([][]byte, error) {
	lookup := make([]int, 0)

	// Add the nodes that we need to compute the requested hashes.
	rightEdge := make(map[int][]int)
	for _, id := range nodes {
		if math.IsFullSubtree(id, n) {
			lookup = append(lookup, id)
		} else {
			subtrees := math.FullSubtrees(id, n)
			rightEdge[id] = subtrees
			lookup = append(lookup, subtrees...)
		}
	}

	// Load everything from the database in one roundtrip.
	set, err := t.fetch(n, lookup)
	if err != nil {
		return nil, err
	}

	// Extract the data we want to return.
	out := make([][]byte, len(nodes))
	for i, id := range nodes {
		if subtrees, ok := rightEdge[id]; ok {
			// Manually calculate the intermediate.
			nd := set.get(subtrees[len(subtrees)-1])
			for i := len(subtrees) - 2; i >= 0; i-- {
				nd = &nodeData{
					leaf:  false,
					value: treeHash(set.get(subtrees[i]), nd),
				}
			}
			out[i] = nd.value
		} else {
			out[i] = set.get(id).value
		}
	}

	return out, nil
}

// Get returns the value of log entry number `x` along with its proof of
// inclusion.
func (t *Tree) Get(x, n int) ([]byte, [][]byte, error) {
	if n == 0 {
		return nil, nil, fmt.Errorf("empty tree")
	} else if x >= n {
		return nil, nil, fmt.Errorf("can not get leaf beyond right edge of tree")
	}

	leaf := 2 * x
	cpath := math.Copath(leaf, n)
	data, err := t.fetchSpecific(n, append([]int{leaf}, cpath...))
	if err != nil {
		return nil, nil, err
	}

	return data[0], data[1:], nil
}

// GetBatch returns a batch proof for the given set of log entries.
func (t *Tree) GetBatch(entries []int, n int) ([][]byte, error) {
	if n == 0 {
		return nil, fmt.Errorf("empty tree")
	} else if len(entries) == 0 {
		return nil, nil
	}
	for _, x := range entries {
		if x >= n {
			return nil, fmt.Errorf("can not get leaf beyond right edge of tree")
		}
	}
	return t.fetchSpecific(n, math.BatchCopath(entries, n))
}

// GetConsistencyProof returns a proof that the current log with n elements is
// an extension of a previous log root with m elements, 0 < m < n.
func (t *Tree) GetConsistencyProof(m, n int) ([][]byte, error) {
	if m <= 0 {
		return nil, fmt.Errorf("first parameter must be greater than zero")
	} else if m >= n {
		return nil, fmt.Errorf("second parameter must be greater than first")
	}
	return t.fetchSpecific(n, math.ConsistencyProof(m, n))
}

// Append adds a new element to the end of the log and returns the new root
// value. n is the current value; after this operation is complete, methods to
// this class should be called with n+1.
func (t *Tree) Append(n int, value []byte) ([]byte, error) {
	if len(value) != 32 {
		return nil, fmt.Errorf("value has wrong length: %v", len(value))
	}

	// Calculate the set of nodes that we'll need to update / create.
	leaf := 2 * n
	path := []int{leaf}
	for _, id := range math.DirectPath(leaf, n+1) {
		path = append(path, id)
	}

	alreadyExists := make(map[int]struct{})
	if n > 0 {
		alreadyExists[math.Chunk(leaf-2)] = struct{}{}
		for _, id := range math.DirectPath(leaf-2, n) {
			alreadyExists[math.Chunk(id)] = struct{}{}
		}
	}

	updateChunks := make([]int, 0) // These are dedup'ed by fetch.
	createChunks := make(map[int]struct{})
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
	set, err := t.fetch(n+1, append(updateChunks, math.Copath(leaf, n+1)...))
	if err != nil {
		return nil, err
	}

	// Add any new chunks to the set and set the correct hashes everywhere.
	for id := range createChunks {
		set.add(id)
	}

	set.set(leaf, value)
	for _, x := range path[1:] {
		if math.Level(x)%4 == 0 {
			l, r := math.Left(x), math.Right(x, n+1)
			intermediate := treeHash(set.get(l), set.get(r))
			set.set(x, intermediate)
		}
	}

	// Commit to database and return new root.
	data := set.marshal()
	if err := t.tx.BatchPut(data); err != nil {
		return nil, err
	}

	return set.get(math.Root(n + 1)).value, nil
}
