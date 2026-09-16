package log

import (
	"errors"

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

func (nd *nodeData) isEmpty() bool {
	return len(nd.value) == 0
}

func (nd *nodeData) marshal() []byte {
	if nd.isEmpty() {
		panic("can not marshal empty node")
	}
	out := make([]byte, 1+len(nd.value))
	if nd.leaf {
		out[0] = 0
	} else {
		out[0] = 1
	}
	copy(out[1:], nd.value)
	return out
}

// nodeChunk is a helper struct that handles computing/caching the intermediate
// nodes of a chunk.
type nodeChunk struct {
	cs suites.CipherSuite

	id    uint64 // Id of the chunk's root node.
	shift uint64 // Log2 of the spacing between adjacent nodes: Level(id)-3.
	nodes []*nodeData
}

func newChunk(cs suites.CipherSuite, id uint64, data []byte) (*nodeChunk, error) {
	level := math.Level(id)
	if level%4 != 3 {
		return nil, errors.New("invalid chunk id")
	}

	// Parse the serialized data.
	hashSize := cs.HashSize()
	leafChunk := level == 3
	nodes := make([]*nodeData, 0, 15)

	for len(data) > 0 {
		if len(data) < hashSize {
			return nil, errors.New("unable to parse chunk")
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
		return nil, errors.New("unable to parse chunk")
	}
	for len(nodes) < 15 {
		if len(nodes)%2 == 0 {
			nodes = append(nodes, &nodeData{leaf: leafChunk, value: nil})
		} else {
			nodes = append(nodes, &nodeData{leaf: false, value: nil})
		}
	}

	return &nodeChunk{cs: cs, id: id, shift: level - 3, nodes: nodes}, nil
}

// nodeId returns the id of the node held at index i of the chunk. The 15 nodes
// of a chunk are evenly spaced and centered on the chunk's root, so this is
// just a scaled offset: with id = 7 the output is [0, 1, ..., 14].
func (c *nodeChunk) nodeId(i uint64) uint64 {
	return c.id + (i-7)<<c.shift // Underflow of i-7 is intentional.
}

func (c *nodeChunk) findIndex(x uint64) uint64 {
	i := (x - c.id + 7<<c.shift) >> c.shift
	if i >= 15 || c.nodeId(i) != x {
		panic("requested hash not available in this chunk")
	}
	return i
}

// get returns the data of node x with the value populated.
func (c *nodeChunk) get(x uint64) *nodeData {
	i := c.findIndex(x)
	if math.IsLeaf(x) || !c.nodes[i].isEmpty() {
		return c.nodes[i]
	}

	l, r := math.Left(x), math.RightStep(x)
	c.nodes[i] = treeHash(c.cs, c.get(l), c.get(r))

	return c.nodes[i]
}

// set updates node x to contain the given value.
func (c *nodeChunk) set(x uint64, nd *nodeData) {
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

	chunks   map[uint64]*nodeChunk
	modified map[uint64]struct{}
}

func newChunkSet(cs suites.CipherSuite) *chunkSet {
	return &chunkSet{
		cs: cs,

		chunks:   make(map[uint64]*nodeChunk),
		modified: make(map[uint64]struct{}),
	}
}

func (s *chunkSet) parse(id uint64, raw []byte) error {
	if len(raw) == 0 {
		return errors.New("unable to parse empty chunk")
	} else if _, ok := s.chunks[id]; ok {
		return errors.New("unable to parse existing chunk")
	}

	c, err := newChunk(s.cs, id, raw)
	if err != nil {
		return err
	}
	s.chunks[id] = c

	return nil
}

// get returns node x.
func (s *chunkSet) get(x uint64) *nodeData {
	c, ok := s.chunks[math.Chunk(x)]
	if !ok {
		panic("requested hash is not available in this chunk set")
	}
	return c.get(x)
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
func (s *chunkSet) set(x uint64, nd *nodeData) {
	id := math.Chunk(x)
	c, ok := s.chunks[id]
	if !ok {
		panic("requested hash is not available in this chunk set")
	}
	c.set(x, nd)
	s.modified[id] = struct{}{}
}

func (s *chunkSet) marshal() map[uint64][]byte {
	out := make(map[uint64][]byte, len(s.modified))
	for id := range s.modified {
		out[id] = s.chunks[id].marshal()
	}
	return out
}
