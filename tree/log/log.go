package log

import (
	"fmt"
	"strconv"

	"github.com/JumpPrivacy/katie/db"
)

// Tree is an implementation of a Merkle tree where all new data is added to the
// right-most edge of the tree.
type Tree struct {
	tx db.Tx
}

func NewTree(tx db.Tx) *Tree {
	return &Tree{tx: tx}
}

// fetch loads the chunks for the requested nodes from the database. It returns
// an error if not all chunks are found.
func (t *Tree) fetch(n int, nodes []int) (*chunkSet, error) {
	dedup := make(map[int]struct{})
	for _, id := range nodes {
		dedup[chunk(id)] = struct{}{}
	}
	strs := make([]string, 0, len(dedup))
	for id, _ := range dedup {
		strs = append(strs, strconv.Itoa(id))
	}

	data, err := t.tx.BatchGet(strs)
	if err != nil {
		return nil, err
	}
	for _, id := range strs {
		if _, ok := data[id]; !ok {
			return nil, fmt.Errorf("not all expected chunks were found in the database")
		}
	}

	dataInt := make(map[int][]byte, len(data))
	for idStr, raw := range data {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return nil, err
		}
		dataInt[id] = raw
	}
	return newChunkSet(n, dataInt)
}

// Get returns the value of log entry number `x` along with its proof of
// inclusion.
func (t *Tree) Get(x, n int) ([]byte, [][]byte, error) {
	if n == 0 {
		return nil, nil, nil
	}

	// Fetch the leaf we want, along with its copath.
	leaf := 2 * x
	nodes := append([]int{leaf}, copath(leaf, n)...)

	set, err := t.fetch(n, nodes)
	if err != nil {
		return nil, nil, err
	}

	// Extract the information we need and return.
	value := set.get(leaf)

	proof := make([][]byte, 0)
	for i := 1; i < len(nodes); i++ {
		proof = append(proof, set.get(nodes[i]))
	}

	return value, proof, nil
}

// GetConsistencyProof returns a proof that the current log with n elements is
// an extension of a previous log root with m elements, 0 < m < n.
func (t *Tree) GetConsistencyProof(m, n int) ([][]byte, error) {
	if m <= 0 {
		return nil, fmt.Errorf("first parameter must be greater than zero")
	} else if m >= n {
		return nil, fmt.Errorf("second parameter must be greater than first")
	}

	// Compute the list of nodes that our output will consist of.
	nodes := consistencyProof(m, n)

	// Compute the list of nodes to read from the database, which has a special
	// case for the ragged right edge of the tree.
	lookup := make([]int, len(nodes)-1)
	copy(lookup, nodes)
	last := nodes[len(nodes)-1]
	lastSubtrees := fullSubtrees(last, n)

	// Load the nodes from `lookup` and `lastSubtrees` and build a chunk set.
	set, err := t.fetch(n, append(lookup, lastSubtrees...))
	if err != nil {
		return nil, err
	}

	// Manually calculate the last hash.
	isLeaf := (lastSubtrees[len(lastSubtrees)-1] & 1) == 0
	hash := set.get(lastSubtrees[len(lastSubtrees)-1])
	for i := len(lastSubtrees) - 2; i >= 0; i-- {
		hash = treeHash(false, set.get(lastSubtrees[i]), isLeaf, hash)
		isLeaf = false
	}

	// Extract the information we need and return.
	proof := make([][]byte, 0)
	for i := 0; i < len(nodes); i++ {
		if nodes[i] == last {
			proof = append(proof, hash)
		} else {
			proof = append(proof, set.get(nodes[i]))
		}
	}
	return proof, nil
}

func (t *Tree) store(data map[int][]byte) error {
	out := make(map[string][]byte, len(data))
	for id, raw := range data {
		out[strconv.Itoa(id)] = raw
	}
	return t.tx.BatchPut(out)
}

// Append adds a new element to the end of the log and returns the new root
// value. n is the current value; after this operation is complete, methods to
// this class should be called with n+1.
func (t *Tree) Append(n int, value []byte) ([]byte, error) {
	// Calculate the set of nodes that we'll need to update / create.
	leaf := 2 * n
	path := make([]int, 1)
	path[0] = leaf
	for _, id := range directPath(leaf, n+1) {
		if level(id)%4 == 0 {
			path = append(path, id)
		}
	}

	alreadyExists := make(map[int]struct{})
	if n > 0 {
		alreadyExists[chunk(leaf-2)] = struct{}{}
		for _, id := range directPath(leaf-2, n) {
			alreadyExists[chunk(id)] = struct{}{}
		}
	}

	updateChunks := make([]int, 0) // These are dedup'ed by fetch.
	createChunks := make(map[int]struct{})
	for _, id := range path {
		id = chunk(id)
		if _, ok := alreadyExists[id]; ok {
			updateChunks = append(updateChunks, id)
		} else {
			createChunks[id] = struct{}{}
		}
	}

	// Fetch the chunks we'll need to update along with nodes we'll need to know
	// to compute the new root or updated intermediates.
	set, err := t.fetch(n+1, append(updateChunks, copath(leaf, n+1)...))
	if err != nil {
		return nil, err
	}

	// Add any new chunks to the set and set the correct hashes everywhere.
	for id, _ := range createChunks {
		set.add(id)
	}

	set.set(leaf, value)
	for i := 1; i < len(path); i++ {
		x := path[i]
		l, r := left(x), right(x, n+1)

		intermediate := treeHash((l&1) == 0, set.get(l), (r&1) == 0, set.get(r))
		set.set(x, intermediate)
	}

	if err := t.store(set.marshal()); err != nil {
		return nil, err
	}
	return set.get(root(n + 1)), nil
}
