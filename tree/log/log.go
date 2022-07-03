//go:build exclude

package tree

import (
	"crypto/sha256"

	"github.com/JumpPrivacy/katie/db"
)

// consistencyProof returns the list of node ids to return for a consistency
// proof between m and n.
func consistencyProof(m, n int) []int {
	// Algorithm from RFC 6962.
	return subProof(m, n, true)
}

func subProof(m, n int, b bool) []int {
	if m == n {
		if b {
			return []int{}
		}
		return []int{root(m)} // m is a power of two.
	}

	k := 1 << log2(n)
	if k == n {
		k = k / 2
	}
	if m <= k {
		proof := subProof(m, k, b)
		proof = append(proof, right(root(n), n))
		return proof
	}

	proof := subProof(m-k, n-k, false)
	for i := 0; i < len(proof); i++ {
		proof[i] = proof[i] + 2*k
	}
	proof = append([]int{left(root(n))}, proof...)
	return proof
}

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
	if leftLeaf {
		input[0] = 1
	}
	copy(input[1:33], left[:])
	if rightLeaf {
		input[33] = 1
	}
	copy(input[34:66], right[:])

	return sha256.Sum256(input)
}

// chunk is a helper struct that handles computing/caching the intermediate
// nodes of a chunk.
type chunk struct {
}

func newChunk(id int, data []byte) (*chunk, error) {
	if len(data) > 256 {
		return nil, fmt.Errorf("chunk is too large: %v", len(data))
	} else if len(data)%32 != 0 {
		return nil, fmt.Errorf("chunk has an unexpected size: %v", len(data))
	}

	// Split data into leaves.
	leaves := [][32]byte{}
	for i := 0; i < len(data); i += 32 {
		leaf := [32]byte{}
		copy(leaf[:], data[i:i+32])
		leaves = append(leaves, leaf)
	}
	// Convert leaves array into nodes array by adding space for parent nodes.
	nodes := [][32]byte{}

	return &chunk{}
}

// LogTree is an implementation of a Merkle tree where the leaves are the only
// nodes that store data and all new data is added to the right-most edge of the
// tree.
type LogTree struct {
	conn db.Conn
}

func NewLogTree(conn db.Conn) *LogTree {
	return &LogTree{conn: conn}
}
