package log

import (
	"fmt"
)

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
