package tree

import (
	"crypto/sha256"
	"fmt"
	"strconv"

	"github.com/JumpPrivacy/katie/db"
)

// chunk takes a node id as input and returns the id of the chunk that the node
// would be stored in, in the database.
//
// Chunks store 8 consecutive nodes from the same level of the tree,
// representing a subtree of height 4. The chunk is identified by the root of
// this subtree.
func chunk(x int) int {
	c := x
	for level(c)%4 != 3 {
		c = parentStep(c)
	}
	return c
}

// treeHash returns the intermediate hash of left and right.
//
// Both must be 32 bytes. leftLeaf is true if the left hash is a leaf and
// rightLeaf is true if the right hash is a leaf.
func treeHash(leftLeaf bool, left []byte, rightLeaf bool, right []byte) []byte {
	if len(left) != 32 {
		panic(fmt.Errorf("left hash is wrong length: %v", len(left)))
	} else if len(right) != 32 {
		panic(fmt.Errorf("right hash is wrong length: %v", len(right)))
	}

	input := make([]byte, 66)
	if !leftLeaf {
		input[0] = 1
	}
	copy(input[1:33], left[:])
	if !rightLeaf {
		input[33] = 1
	}
	copy(input[34:66], right[:])

	output := sha256.Sum256(input)
	return output[:]
}

// nodeChunk is a helper struct that handles computing/caching the intermediate
// nodes of a chunk.
type nodeChunk struct {
	ids   []int
	nodes [][]byte
}

func newChunk(id int, data []byte) (*nodeChunk, error) {
	if len(data) > 256 {
		return nil, fmt.Errorf("chunk is too large: %v", len(data))
	} else if len(data)%32 != 0 {
		return nil, fmt.Errorf("chunk has an unexpected size: %v", len(data))
	}

	// Split data into leaves.
	leaves := make([][]byte, 0)
	for i := 0; i < len(data); i += 32 {
		leaf := make([]byte, 32)
		copy(leaf, data[i:i+32])
		leaves = append(leaves, leaf)
	}
	// Convert leaves array into nodes array by adding space for parent nodes.
	nodes := make([][]byte, 0)
	for i := 0; i < 8; i++ {
		if i < len(leaves) {
			nodes = append(nodes, leaves[i])
		} else {
			nodes = append(nodes, nil)
		}
		if i != 7 {
			nodes = append(nodes, nil)
		}
	}

	// Create a map that shows the node id represented by each element of the
	// nodes array. This code is a little bit verbose but I like that it's easy
	// to check it's correct: run with id = 7 and the output is [0, 1, ..., 14].
	ids := make([]int, 15)
	ids[7] = id
	ids[3] = left(ids[7])
	ids[1] = left(ids[3])
	ids[0] = left(ids[1])
	ids[2] = rightStep(ids[1])
	ids[5] = rightStep(ids[3])
	ids[4] = left(ids[5])
	ids[6] = rightStep(ids[5])
	ids[11] = rightStep(ids[7])
	ids[9] = left(ids[11])
	ids[8] = left(ids[9])
	ids[10] = rightStep(ids[9])
	ids[13] = rightStep(ids[11])
	ids[12] = left(ids[13])
	ids[14] = rightStep(ids[13])

	return &nodeChunk{ids: ids, nodes: nodes}, nil
}

func (c *nodeChunk) findIndex(x int) int {
	index := -1

	for i := 0; i < len(c.ids); i++ {
		if c.ids[i] == x {
			index = i
			break
		}
	}

	return index
}

// get returns the hash of node x.
func (c *nodeChunk) get(x, n int, set *chunkSet) []byte {
	i := c.findIndex(x)
	if i == -1 {
		panic("requested hash not available in this chunk")
	} else if c.nodes[i] != nil {
		return c.nodes[i]
	}

	l, r := left(x), right(x, n)
	c.nodes[i] = treeHash(
		(l&1) == 0,
		set.get(l),
		(r&1) == 0,
		set.get(r),
	)

	return c.nodes[i]
}

// set updates the hash of node x to be the given value.
func (c *nodeChunk) set(x int, value []byte) {
	i := c.findIndex(x)
	if i == -1 {
		panic("requested hash not available in this chunk")
	} else if len(value) != 32 {
		panic("chunk values must be exactly 32 bytes")
	}

	c.nodes[i] = value
	for i != 7 {
		i = parentStep(i)
		c.nodes[i] = nil
	}
}

// marshal returns the serialized chunk.
func (c *nodeChunk) marshal() []byte {
	leaves := make([][]byte, 0)

	for i := 0; i < len(c.nodes); i += 2 {
		if c.nodes[i] != nil {
			leaves = append(leaves, c.nodes[i])
			continue
		}

		// Check that there are no other populated leaves.
		for i < len(c.nodes) {
			if c.nodes[i] != nil {
				panic("chunk has gaps")
			}
			i += 2
		}
		break
	}

	raw := make([]byte, 32*len(leaves))
	for i := 0; i < len(leaves); i++ {
		copy(raw[i*32:(i+1)*32], leaves[i])
	}
	return raw
}

// chunkSet is a helper struct for directing operations to the correct nodeChunk
// in a set.
type chunkSet struct {
	n        int
	chunks   map[int]*nodeChunk
	modified map[int]struct{}
}

func newChunkSet(n int, data map[int][]byte) (*chunkSet, error) {
	chunks := make(map[int]*nodeChunk)
	for id, raw := range data {
		c, err := newChunk(id, raw)
		if err != nil {
			return nil, err
		}
		chunks[id] = c
	}

	return &chunkSet{
		n:        n,
		chunks:   chunks,
		modified: make(map[int]struct{}),
	}, nil
}

// get returns the hash of node x.
func (s *chunkSet) get(x int) []byte {
	c, ok := s.chunks[chunk(x)]
	if !ok {
		panic("requested hash is not available in this chunk set")
	}
	return c.get(x, s.n, s)
}

// add initializes a new empty chunk for node x.
func (s *chunkSet) add(x int) {
	id := chunk(x)
	if _, ok := s.chunks[id]; ok {
		panic("cannot add chunk that already exists in set")
	}
	c, err := newChunk(id, make([]byte, 0))
	if err != nil {
		panic(err)
	}
	s.chunks[id] = c
}

// set changes node x to the given value.
func (s *chunkSet) set(x int, value []byte) {
	id := chunk(x)
	c, ok := s.chunks[id]
	if !ok {
		panic("requested hash is not available in this chunk set")
	}
	c.set(x, value)
	s.modified[id] = struct{}{}
}

func (s *chunkSet) marshal() map[int][]byte {
	out := make(map[int][]byte, 0)
	for id, _ := range s.modified {
		out[id] = s.chunks[id].marshal()
	}
	return out
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
