package log

import (
	"fmt"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/log/math"
)

// The Log Tree implementation is designed to work with a standard key-value
// database. The tree is stored in the database in "chunks", which are
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

func (nd *nodeData) marshal() []byte {
	out := make([]byte, 1+len(nd.value))
	if nd.leaf {
		out[0] = 0
	} else {
		out[0] = 1
	}
	copy(out[1:], nd.value)
	return out
}

func (nd *nodeData) isEmpty() bool {
	return nd.value == nil
}

// nodeChunk is a helper struct that handles computing/caching the intermediate
// nodes of a chunk.
type nodeChunk struct {
	cs suites.CipherSuite

	ids   []uint64
	nodes []*nodeData
}

func newChunk(cs suites.CipherSuite, id uint64, data []byte) (*nodeChunk, error) {
	// Create a map that shows the node id represented by each element of the
	// nodes array. This code is a little bit verbose but I like that it's easy
	// to check it's correct: run with id = 7 and the output is [0, 1, ..., 14].
	ids := make([]uint64, 15)
	ids[7] = id
	ids[3] = math.Left(ids[7])
	ids[1] = math.Left(ids[3])
	ids[0] = math.Left(ids[1])
	ids[2] = math.RightStep(ids[1])
	ids[5] = math.RightStep(ids[3])
	ids[4] = math.Left(ids[5])
	ids[6] = math.RightStep(ids[5])
	ids[11] = math.RightStep(ids[7])
	ids[9] = math.Left(ids[11])
	ids[8] = math.Left(ids[9])
	ids[10] = math.RightStep(ids[9])
	ids[13] = math.RightStep(ids[11])
	ids[12] = math.Left(ids[13])
	ids[14] = math.RightStep(ids[13])

	// Parse the serialized data.
	hashSize := cs.HashSize()
	leafChunk := math.Level(id) == 3
	nodes := make([]*nodeData, 0)

	for len(data) > 0 {
		if len(data) < hashSize {
			return nil, fmt.Errorf("unable to parse chunk")
		}
		if len(nodes) > 0 {
			nodes = append(nodes, &nodeData{leaf: false, value: nil})
		}
		nodes = append(nodes, &nodeData{
			leaf:  leafChunk,
			value: data[:hashSize],
		})
		data = data[hashSize:]
	}
	if len(nodes) > 15 {
		return nil, fmt.Errorf("unable to parse chunk")
	}
	for len(nodes) < 15 {
		nodes = append(nodes, &nodeData{
			leaf:  math.IsLeaf(ids[len(nodes)]),
			value: nil,
		})
	}

	return &nodeChunk{cs: cs, ids: ids, nodes: nodes}, nil
}

func (c *nodeChunk) findIndex(x uint64) uint64 {
	for i := range len(c.ids) {
		if c.ids[i] == x {
			return uint64(i)
		}
	}
	panic("requested hash not available in this chunk")
}

// get returns the data of node x with the value populated.
func (c *nodeChunk) get(x, n uint64, set *chunkSet) *nodeData {
	i := c.findIndex(x)
	if math.IsLeaf(x) || !c.nodes[i].isEmpty() {
		return c.nodes[i]
	}

	l, r := math.Left(x), math.Right(x, n)
	c.nodes[i].value = treeHash(c.cs, set.get(l), set.get(r))

	return c.nodes[i]
}

// set updates node x to contain the given value.
func (c *nodeChunk) set(x uint64, value []byte) {
	nd := &nodeData{
		leaf:  math.IsLeaf(x),
		value: value,
	}

	i := c.findIndex(x)
	c.nodes[i] = nd
	for i != 7 {
		i = math.ParentStep(i)
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
	cs suites.CipherSuite
	n  uint64

	chunks   map[uint64]*nodeChunk
	modified map[uint64]struct{}
}

func newChunkSet(cs suites.CipherSuite, n uint64, data map[uint64][]byte) (*chunkSet, error) {
	chunks := make(map[uint64]*nodeChunk)
	for id, raw := range data {
		c, err := newChunk(cs, id, raw)
		if err != nil {
			return nil, err
		}
		chunks[id] = c
	}

	return &chunkSet{
		cs: cs,
		n:  n,

		chunks:   chunks,
		modified: make(map[uint64]struct{}),
	}, nil
}

// get returns node x.
func (s *chunkSet) get(x uint64) *nodeData {
	c, ok := s.chunks[math.Chunk(x)]
	if !ok {
		panic("requested hash is not available in this chunk set")
	}
	return c.get(x, s.n, s)
}

// add initializes a new empty chunk for node x.
func (s *chunkSet) add(x uint64) {
	id := math.Chunk(x)
	if _, ok := s.chunks[id]; ok {
		panic("cannot add chunk that already exists in set")
	}
	c, err := newChunk(s.cs, id, make([]byte, 0))
	if err != nil {
		panic(err)
	}
	s.chunks[id] = c
}

// set changes node x to the given value.
func (s *chunkSet) set(x uint64, value []byte) {
	id := math.Chunk(x)
	c, ok := s.chunks[id]
	if !ok {
		panic("requested hash is not available in this chunk set")
	}
	c.set(x, value)
	s.modified[id] = struct{}{}
}

func (s *chunkSet) marshal() map[uint64][]byte {
	out := make(map[uint64][]byte, len(s.modified))
	for id := range s.modified {
		out[id] = s.chunks[id].marshal()
	}
	return out
}
