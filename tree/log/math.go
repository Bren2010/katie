package log

import (
	"crypto/sha256"
)

// log2 returns the exponent of the largest power of 2 less than x.
func log2(x int) int {
	if x == 0 {
		return 0
	}

	k := 0
	for (x >> k) > 0 {
		k += 1
	}
	return k - 1
}

// level returns the level of a node in the tree. Leaves are level 0, their
// parents are level 1, and so on.
func level(x int) int {
	if (x & 1) == 0 {
		return 0
	}

	k := 0
	for ((x >> k) & 1) == 1 {
		k += 1
	}
	return k
}

// nodeWidth returns the number of nodes needed to store a tree with n leaves.
func nodeWidth(n int) int {
	if n == 0 {
		return 0
	}
	return 2*(n-1) + 1
}

// root returns the id of the root node of a tree with n leaves.
func root(n int) int {
	w := nodeWidth(n)
	return (1 << log2(w)) - 1
}

// left returns the left child of an intermediate node.
func left(x int) int {
	k := level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (1 << (k - 1))
}

func rightStep(x int) int {
	k := level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (3 << (k - 1))
}

// right returns the right child of an intermediate node.
func right(x, n int) int {
	r := rightStep(x)
	w := nodeWidth(n)
	for r >= w {
		r = left(r)
	}
	return r
}

func parentStep(x int) int {
	k := level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// parent returns the id of the parent node x, if there are n nodes in the tree
// total.
func parent(x, n int) int {
	if x == root(n) {
		panic("root node has no parent")
	}

	width := nodeWidth(n)
	p := parentStep(x)
	for p >= width {
		p = parentStep(p)
	}
	return p
}

// sibling returns the other child of the node's parent.
func sibling(x, n int) int {
	p := parent(x, n)
	if x < p {
		return right(p, n)
	} else {
		return left(p)
	}
}

// directPath returns the direct path of a node, ordered from leaf to root.
func directPath(x, n int) []int {
	r := root(n)
	if x == r {
		return []int{}
	}

	d := []int{}
	for x != r {
		x = parent(x, n)
		d = append(d, x)
	}
	return d
}

// copath returns the copath of a node, ordered from leaf to root.
func copath(x, n int) []int {
	if x == root(n) {
		return []int{}
	}

	d := directPath(x, n)
	d = append([]int{x}, d...)
	d = d[:len(d)-1]
	for i := 0; i < len(d); i++ {
		d[i] = sibling(d[i], n)
	}

	return d
}

// isFullSubtree returns true if node x represents a full subtree.
func isFullSubtree(x, n int) bool {
	rightmost := 2 * (n - 1)
	expected := x + (1 << level(x)) - 1

	return expected <= rightmost
}

// fullSubtrees returns the list of full subtrees that x consists of.
func fullSubtrees(x, n int) []int {
	out := []int{}

	for {
		if isFullSubtree(x, n) {
			out = append(out, x)
			return out
		} else {
			out = append(out, left(x))
			x = right(x, n)
		}
	}
}

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
func treeHash(left, right *nodeData) []byte {
	if err := left.validate(); err != nil {
		panic(err)
	} else if err := right.validate(); err != nil {
		panic(err)
	}

	input := append(left.marshal(), right.marshal()...)
	output := sha256.Sum256(input)
	return output[:]
}

// Parents returns a slice containing the height of each parent of the n-th
// element added to a log.
//
// This information helps applications decide what additional data to store in
// the parent nodes of the next Append operation.
func Parents(n int) []int {
	path := directPath(2*n, n+1)
	heights := make([]int, len(path))
	for i, x := range path {
		heights[i] = level(x)
	}
	return heights
}
