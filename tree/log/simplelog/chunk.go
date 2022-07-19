package simplelog

import (
	"fmt"
)

// The simplelog tree implementation is designed to work with a standard
// key-value database. The tree is stored in the database in "chunks", which are
// 8-node-wide (or 4-node-deep) subtrees. Chunks are addressed by the id of the
// root node in the chunk. Only the leaf values of each chunk are stored, which
// in the context of the full tree is either a leaf or a cached intermediate
// hash. These values are stored concatenated.

// nodeData is the primary wrapper struct for representing a single node (leaf
// or intermediate) in the tree.
type nodeData struct {
	leaf  bool
	value []byte
}

func (nd *nodeData) validate() error {
	if len(nd.value) != 32 {
		return fmt.Errorf("node value is wrong length: %v", len(nd.value))
	}
	return nil
}

func (nd *nodeData) marshal() []byte {
	out := make([]byte, 33)
	if nd.leaf {
		out[0] = 0
	} else {
		out[0] = 1
	}
	copy(out[1:33], nd.value)
	return out
}

func (nd *nodeData) isEmpty() bool {
	return nd.value == nil
}

// nodeChunk is a helper struct that handles computing/caching the intermediate
// nodes of a chunk.
type nodeChunk struct {
	ids   []int
	nodes []*nodeData
}

func newChunk(id int, data []byte) (*nodeChunk, error) {
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

	// Parse the serialized data.
	leafChunk := level(id) == 3
	nodes := make([]*nodeData, 0)

	for len(data) > 0 {
		if len(data) < 32 {
			return nil, fmt.Errorf("unable to parse chunk")
		}
		if len(nodes) > 0 {
			nodes = append(nodes, &nodeData{leaf: false, value: nil})
		}
		nodes = append(nodes, &nodeData{
			leaf:  leafChunk,
			value: data[:32],
		})
		data = data[32:]
	}
	for len(nodes) < 15 {
		nodes = append(nodes, &nodeData{
			leaf:  isLeaf(ids[len(nodes)]),
			value: nil,
		})
	}
	if len(nodes) != 15 {
		return nil, fmt.Errorf("unable to parse chunk")
	}

	return &nodeChunk{ids: ids, nodes: nodes}, nil
}

func (c *nodeChunk) findIndex(x int) int {
	for i := 0; i < len(c.ids); i++ {
		if c.ids[i] == x {
			return i
		}
	}
	panic("requested hash not available in this chunk")
}

// get returns the data of node x with the value populated.
func (c *nodeChunk) get(x, n int, set *chunkSet) *nodeData {
	i := c.findIndex(x)
	if isLeaf(x) || !c.nodes[i].isEmpty() {
		return c.nodes[i]
	}

	l, r := left(x), right(x, n)
	c.nodes[i].value = treeHash(set.get(l), set.get(r))

	return c.nodes[i]
}

// set updates node x to contain the given value.
func (c *nodeChunk) set(x int, value []byte) {
	nd := &nodeData{
		leaf:  isLeaf(x),
		value: value,
	}

	i := c.findIndex(x)
	c.nodes[i] = nd
	for i != 7 {
		i = parentStep(i)
		c.nodes[i].value = nil
	}
}

// marshal returns the serialized chunk.
func (c *nodeChunk) marshal() []byte {
	out := make([]byte, 0)

	for i := 0; i < len(c.nodes); i += 2 {
		if !c.nodes[i].isEmpty() {
			out = append(out, c.nodes[i].value...)
			continue
		}

		// Check that there are no other populated nodes.
		for i < len(c.nodes) {
			if !c.nodes[i].isEmpty() {
				panic("chunk has gaps")
			}
			i++
		}
	}

	return out
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

// get returns node x.
func (s *chunkSet) get(x int) *nodeData {
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
