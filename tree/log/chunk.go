package log

import (
	"fmt"
)

type nodeData struct {
	leaf  bool
	hash  []byte
	value []byte
}

func (nd *nodeData) reduce() []byte {
	if nd.leaf {
		return nd.value
	}
	return nd.hash
}

func (nd *nodeData) validate() error {
	if nd.leaf {
		if len(nd.hash) != 0 {
			return fmt.Errorf("leaf hash is wrong length: %v", len(nd.hash))
		} else if len(nd.value) != 32 {
			return fmt.Errorf("leaf value is wrong length: %v", len(nd.value))
		}
	} else {
		if len(nd.hash) != 32 {
			return fmt.Errorf("parent hash is wrong length: %v", len(nd.hash))
		} else if len(nd.value) != 32 {
			return fmt.Errorf("parent value is wrong length: %v", len(nd.value))
		}
	}
	return nil
}

func (nd *nodeData) marshal() []byte {
	if nd.leaf {
		out := make([]byte, 33)
		out[0] = 0
		copy(out[1:33], nd.value)
		return out
	} else {
		out := make([]byte, 65)
		out[0] = 1
		copy(out[1:33], nd.hash)
		copy(out[33:65], nd.value)
		return out
	}
}

func (nd *nodeData) isEmpty() bool {
	return nd.hash == nil && nd.value == nil
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
	isLeaf := level(id) == 3
	nodes := make([]*nodeData, 0)
	nodeSize := 64
	if isLeaf {
		nodeSize = 32
	}

	for len(data) > 0 {
		if len(data) < nodeSize {
			return nil, fmt.Errorf("unable to parse chunk")
		}
		if isLeaf {
			nodes = append(nodes, &nodeData{
				leaf:  true,
				hash:  nil,
				value: data[:32],
			})
			data = data[32:]
		} else {
			nodes = append(nodes, &nodeData{
				leaf:  false,
				hash:  data[:32],
				value: data[32:64],
			})
			data = data[64:]
		}

		if len(data) == 0 {
			break
		} else if len(data) < 32+nodeSize { // Plus nodeSize because a parent can't be last.
			return nil, fmt.Errorf("unable to parse chunk")
		}
		nodes = append(nodes, &nodeData{
			leaf:  false,
			hash:  nil,
			value: data[:32],
		})
		data = data[32:]
	}
	for len(nodes) < 15 {
		nodes = append(nodes, &nodeData{
			leaf:  (ids[len(nodes)] & 1) == 0,
			hash:  nil,
			value: nil,
		})
	}
	if len(nodes) != 15 {
		return nil, fmt.Errorf("unable to parse chunk")
	}

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
func (c *nodeChunk) get(x, n int, set *chunkSet) *nodeData {
	i := c.findIndex(x)
	if i == -1 {
		panic("requested hash not available in this chunk")
	} else if (x&1) == 0 || c.nodes[i].hash != nil {
		return c.nodes[i]
	}

	l, r := left(x), right(x, n)
	c.nodes[i].hash = treeHash(set.get(l), set.get(r))

	return c.nodes[i]
}

// set updates node x to contain the given hash and value.
func (c *nodeChunk) set(x int, hash, value []byte) {
	i := c.findIndex(x)
	if i == -1 {
		panic("requested hash not available in this chunk")
	}
	nd := &nodeData{
		leaf:  (x & 1) == 0,
		hash:  hash,
		value: value,
	}

	c.nodes[i] = nd
	for i != 7 {
		i = parentStep(i)
		c.nodes[i].hash = nil
	}
}

// marshal returns the serialized chunk.
func (c *nodeChunk) marshal() []byte {
	out := make([]byte, 0)

	for i := 0; i < len(c.nodes); i += 2 {
		if c.nodes[i].value != nil {
			out = append(out, c.nodes[i].hash...)
			out = append(out, c.nodes[i].value...)

			if i != len(c.nodes)-1 && c.nodes[i+1].value != nil {
				if c.nodes[i+2].isEmpty() {
					panic("chunk has gaps")
				}
				out = append(out, c.nodes[i+1].value...)
			}
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
func (s *chunkSet) set(x int, hash, value []byte) {
	id := chunk(x)
	c, ok := s.chunks[id]
	if !ok {
		panic("requested hash is not available in this chunk set")
	}
	c.set(x, hash, value)
	s.modified[id] = struct{}{}
}

func (s *chunkSet) marshal() map[int][]byte {
	out := make(map[int][]byte, 0)
	for id, _ := range s.modified {
		out[id] = s.chunks[id].marshal()
	}
	return out
}
