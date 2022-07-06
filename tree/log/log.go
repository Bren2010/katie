package log

import (
	"fmt"
	"strconv"

	"github.com/JumpPrivacy/katie/db"
)

// Proof wraps all of the information necessary to verify a proof of
// inclusion/consistency for the log.
type Proof struct {
	Hashes        [][]byte // The copath hashes.
	Values        [][]byte // The copath values.
	Intermediates [][]byte // The intermediate node values.
}

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
func (t *Tree) fetch(n int, nodes []int, getParents bool) (*chunkSet, [][]byte, error) {
	dedup := make(map[int]struct{})
	for _, id := range nodes {
		dedup[chunk(id)] = struct{}{}
	}
	strs := make([]string, 0, len(dedup))
	for id, _ := range dedup {
		strs = append(strs, strconv.Itoa(id))
	}
	var parentKey string
	if getParents {
		parentKey = "p" + strconv.Itoa(n-1)
		strs = append(strs, parentKey)
	}

	data, err := t.tx.BatchGet(strs)
	if err != nil {
		return nil, nil, err
	}
	for _, id := range strs {
		if _, ok := data[id]; !ok {
			return nil, nil, fmt.Errorf("not all expected data was found in the database")
		}
	}

	// Parse parents.
	var parents [][]byte
	if getParents {
		raw := data[parentKey]
		if len(raw) != 32*filteredParents(n-1) {
			return nil, nil, fmt.Errorf("log entry is malformed")
		}
		for len(raw) > 0 {
			parents = append(parents, raw[:32])
			raw = raw[32:]
		}
	}

	// Parse chunk set.
	dataInt := make(map[int][]byte, len(data))
	for idStr, raw := range data {
		if idStr == parentKey {
			continue
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return nil, nil, err
		}
		dataInt[id] = raw
	}
	set, err := newChunkSet(n, dataInt)
	if err != nil {
		return nil, nil, err
	}

	return set, parents, nil
}

// fetchNodes takes a list of node ids as input and returns the data for those
// nodes in the same order. It automatically handles special-casing for the
// ragged right edge of the tree.
func (t *Tree) fetchNodes(n int, nodes []int) ([]*nodeData, error) {
	lookup := make([]int, 0)
	rightEdge := make(map[int][]int)

	for _, id := range nodes {
		if isFullSubtree(id, n) {
			lookup = append(lookup, id)
		} else {
			subtrees := fullSubtrees(id, n)
			rightEdge[id] = subtrees
			lookup = append(lookup, subtrees...)
		}
	}

	set, parents, err := t.fetch(n, lookup, true)
	if err != nil {
		return nil, err
	}

	out := make([]*nodeData, 0, len(nodes))
	for _, id := range nodes {
		if subtrees, ok := rightEdge[id]; ok {
			// Manually calculate the intermediate.
			nd := set.get(subtrees[len(subtrees)-1])
			for i := len(subtrees) - 2; i >= 0; i-- {
				nd = &nodeData{
					leaf:  false,
					hash:  treeHash(set.get(subtrees[i]), nd),
					value: parents[len(subtrees)-2-i],
				}
			}
			out = append(out, nd)
		} else {
			out = append(out, set.get(id))
		}
	}
	return out, nil
}

// Get returns the value of log entry number `x` along with its proof of
// inclusion.
func (t *Tree) Get(x, n int) ([]byte, *Proof, error) {
	if n == 0 {
		return nil, nil, nil
	} else if x >= n {
		return nil, nil, fmt.Errorf("can not get leaf beyond right edge of tree")
	}

	leaf := 2 * x
	copathNodes := copath(leaf, n)
	pathNodes := directPath(leaf, n)
	pathNodes = pathNodes[:len(pathNodes)-1] // Remove root.
	lookup := append([]int{leaf}, append(copathNodes, pathNodes...)...)

	nds, err := t.fetchNodes(n, lookup)
	if err != nil {
		return nil, nil, err
	}

	proof := &Proof{}
	for i, _ := range copathNodes {
		proof.Hashes = append(proof.Hashes, nds[1+i].hash)
		proof.Values = append(proof.Values, nds[1+i].value)
	}
	for i, _ := range pathNodes {
		proof.Intermediates = append(proof.Intermediates, nds[1+len(copathNodes)+i].value)
	}

	return nds[0].value, proof, nil
}

// // GetConsistencyProof returns a proof that the current log with n elements is
// // an extension of a previous log root with m elements, 0 < m < n.
// func (t *Tree) GetConsistencyProof(m, n int) ([][]byte, error) {
// 	if m <= 0 {
// 		return nil, fmt.Errorf("first parameter must be greater than zero")
// 	} else if m >= n {
// 		return nil, fmt.Errorf("second parameter must be greater than first")
// 	}
// 	return t.fetchHashes(n, consistencyProof(m, n))
// }

func (t *Tree) store(n int, data map[int][]byte, parents [][]byte) error {
	out := make(map[string][]byte, len(data))

	for id, raw := range data {
		out[strconv.Itoa(id)] = raw
	}

	rawParents := make([]byte, 0, 32*len(parents))
	for _, raw := range parents {
		rawParents = append(rawParents, raw...)
	}
	out["p"+strconv.Itoa(n)] = rawParents

	return t.tx.BatchPut(out)
}

// Append adds a new element to the end of the log and returns the new root
// value. n is the current value; after this operation is complete, methods to
// this class should be called with n+1.
func (t *Tree) Append(n int, value []byte, parents [][]byte) ([]byte, error) {
	if expected := len(Parents(n)); expected != len(parents) {
		return nil, fmt.Errorf("wrong number of parent node values given: wanted=%v, got=%v", expected, len(parents))
	} else if len(value) != 32 {
		return nil, fmt.Errorf("value has wrong length: %v", len(value))
	}
	for _, val := range parents {
		if len(val) != 32 {
			return nil, fmt.Errorf("parent value has wrong length: %v", len(val))
		}
	}

	// Calculate the set of nodes that we'll need to update / create.
	leaf := 2 * n
	path := make([]int, 1)
	path[0] = leaf
	for _, id := range directPath(leaf, n+1) {
		path = append(path, id)
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
	set, _, err := t.fetch(n+1, append(updateChunks, copath(leaf, n+1)...), false)
	if err != nil {
		return nil, err
	}

	// Add any new chunks to the set and set the correct hashes everywhere.
	for id, _ := range createChunks {
		set.add(id)
	}

	set.set(leaf, nil, value)
	for i := 1; i < len(path); i++ {
		x := path[i]
		l, r := left(x), right(x, n+1)

		if level(x)%4 == 0 {
			intermediate := treeHash(set.get(l), set.get(r))
			set.set(x, intermediate, parents[i-1])
		} else {
			set.set(x, nil, parents[i-1])
		}
	}

	// Calculate filtered list of parent values for the log entry.
	filteredParents := make([][]byte, 0)
	for i, val := range parents {
		if !isFullSubtree(path[i+1], n+1) {
			filteredParents = append(filteredParents, val)
		}
	}

	// Commit to database and return new root.
	if err := t.store(n, set.marshal(), filteredParents); err != nil {
		return nil, err
	} else if n == 0 {
		return value, nil
	}
	return set.get(root(n + 1)).hash, nil
}
