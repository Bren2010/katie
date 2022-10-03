// Package math implements the mathematical operations for a log-based Merkle
// tree.
package math

import (
	"sort"
)

// IsLeaf returns true if x is the id of a leaf node.
func IsLeaf(x int) bool {
	return (x & 1) == 0
}

// Log2 returns the exponent of the largest power of 2 less than x.
func Log2(x int) int {
	if x == 0 {
		return 0
	}

	k := 0
	for (x >> k) > 0 {
		k += 1
	}
	return k - 1
}

// Level returns the level of a node in the tree. Leaves are level 0, their
// parents are level 1, and so on.
func Level(x int) int {
	if IsLeaf(x) {
		return 0
	}

	k := 0
	for ((x >> k) & 1) == 1 {
		k += 1
	}
	return k
}

// NodeWidth returns the number of nodes needed to store a tree with n leaves.
func NodeWidth(n int) int {
	if n == 0 {
		return 0
	}
	return 2*(n-1) + 1
}

// Root returns the id of the root node of a tree with n leaves.
func Root(n int) int {
	w := NodeWidth(n)
	return (1 << Log2(w)) - 1
}

// Left returns the left child of an intermediate node.
func Left(x int) int {
	k := Level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (1 << (k - 1))
}

func RightStep(x int) int {
	k := Level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (3 << (k - 1))
}

// Right returns the right child of an intermediate node.
func Right(x, n int) int {
	r := RightStep(x)
	w := NodeWidth(n)
	for r >= w {
		r = Left(r)
	}
	return r
}

func ParentStep(x int) int {
	k := Level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// Parent returns the id of the parent node x, if there are n nodes in the tree
// total.
func Parent(x, n int) int {
	if x == Root(n) {
		panic("root node has no parent")
	}

	width := NodeWidth(n)
	p := ParentStep(x)
	for p >= width {
		p = ParentStep(p)
	}
	return p
}

// Sibling returns the other child of the node's parent.
func Sibling(x, n int) int {
	p := Parent(x, n)
	if x < p {
		return Right(p, n)
	} else {
		return Left(p)
	}
}

// DirectPath returns the direct path of a node, ordered from leaf to root.
func DirectPath(x, n int) []int {
	r := Root(n)
	if x == r {
		return []int{}
	}

	d := []int{}
	for x != r {
		x = Parent(x, n)
		d = append(d, x)
	}
	return d
}

// Copath returns the copath of a node, ordered from leaf to root.
func Copath(x, n int) []int {
	if x == Root(n) {
		return []int{}
	}

	d := DirectPath(x, n)
	d = append([]int{x}, d...)
	d = d[:len(d)-1]
	for i := 0; i < len(d); i++ {
		d[i] = Sibling(d[i], n)
	}

	return d
}

// IsFullSubtree returns true if node x represents a full subtree.
func IsFullSubtree(x, n int) bool {
	rightmost := 2 * (n - 1)
	expected := x + (1 << Level(x)) - 1

	return expected <= rightmost
}

// FullSubtrees returns the list of full subtrees that x consists of.
func FullSubtrees(x, n int) []int {
	out := []int{}

	for {
		if IsFullSubtree(x, n) {
			out = append(out, x)
			return out
		} else {
			out = append(out, Left(x))
			x = Right(x, n)
		}
	}
}

// ConsistencyProof returns the list of node ids to return for a consistency
// proof between m and n.
func ConsistencyProof(m, n int) []int {
	// Algorithm from RFC 6962.
	return subProof(m, n, true)
}

func subProof(m, n int, b bool) []int {
	if m == n {
		if b {
			return []int{}
		}
		return []int{Root(m)} // m is a power of two.
	}

	k := 1 << Log2(n)
	if k == n {
		k = k / 2
	}
	if m <= k {
		proof := subProof(m, k, b)
		proof = append(proof, Right(Root(n), n))
		return proof
	}

	proof := subProof(m-k, n-k, false)
	for i := 0; i < len(proof); i++ {
		proof[i] = proof[i] + 2*k
	}
	proof = append([]int{Left(Root(n))}, proof...)
	return proof
}

// BatchCopath returns the copath nodes of a batch of leaves.
func BatchCopath(leaves []int, n int) []int {
	// Convert the leaf indices to node indices.
	nodes := make([]int, len(leaves))
	for i, x := range leaves {
		nodes[i] = 2 * x
	}
	sort.Ints(nodes)

	// Iteratively combine nodes until there's only one entry in the list (being
	// the root), keeping track of the extra nodes we needed to get there.
	out := make([]int, 0)
	root := Root(n)
	for {
		if len(nodes) == 1 && nodes[0] == root {
			break
		}

		nextLevel := make([]int, 0)
		for len(nodes) > 1 {
			p := Parent(nodes[0], n)
			if Right(p, n) == nodes[1] { // Sibling is already here.
				nodes = nodes[2:]
			} else { // Need to fetch sibling.
				out = append(out, Sibling(nodes[0], n))
				nodes = nodes[1:]
			}
			nextLevel = append(nextLevel, p)
		}
		if len(nodes) == 1 {
			if len(nextLevel) > 0 && Level(Parent(nodes[0], n)) > Level(nextLevel[0]) {
				nextLevel = append(nextLevel, nodes[0])
			} else {
				out = append(out, Sibling(nodes[0], n))
				nextLevel = append(nextLevel, Parent(nodes[0], n))
			}
		}

		nodes = nextLevel
	}
	sort.Ints(out)

	return out
}

// Chunk takes a node id as input and returns the id of the chunk that the node
// would be stored in, in the database.
//
// Chunks store 8 consecutive nodes from the same level of the tree,
// representing a subtree of height 4. The chunk is identified by the root of
// this subtree.
func Chunk(x int) int {
	c := x
	for Level(c)%4 != 3 {
		c = ParentStep(c)
	}
	return c
}
