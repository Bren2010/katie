package tree

import (
	"crypto/sha256"
	"fmt"
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

// get returns the hash of node x, if it exists in this chunk.
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
		set.get(l, n),
		(r&1) == 0,
		set.get(r, n),
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

// // LogTree is an implementation of a Merkle tree where the leaves are the only
// // nodes that store data and all new data is added to the right-most edge of the
// // tree.
// type LogTree struct {
// 	conn db.Conn
// }
//
// func NewLogTree(conn db.Conn) *LogTree {
// 	return &LogTree{conn: conn}
// }
