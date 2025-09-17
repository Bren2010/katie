// Package math implements the mathematical operations for a Log Tree.
package math

import (
	"slices"
)

const MaxTreeSize uint64 = 1 << 63

// IsLeaf returns true if x is the id of a leaf node.
func IsLeaf(x uint64) bool {
	return (x & 1) == 0
}

// log2 returns the exponent of the largest power of 2 less than x.
func log2(x uint64) uint64 {
	if x == 0 {
		return 0
	}
	k := uint64(0)
	for (x >> k) > 0 {
		k += 1
	}
	return k - 1
}

// Level returns the level of a node in the tree. Leaves are level 0, their
// parents are level 1, and so on.
func Level(x uint64) uint64 {
	if IsLeaf(x) {
		return 0
	}
	k := uint64(0)
	for ((x >> k) & 1) == 1 {
		k += 1
	}
	return k
}

// nodeWidth returns the number of nodes needed to store a tree with n leaves.
func nodeWidth(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return 2*(n-1) + 1
}

// Root returns the id of the root node of a tree with n leaves.
func Root(n uint64) uint64 {
	w := nodeWidth(n)
	return (1 << log2(w)) - 1
}

// Left returns the left child of an intermediate node.
func Left(x uint64) uint64 {
	k := Level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (1 << (k - 1))
}

func RightStep(x uint64) uint64 {
	k := Level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (3 << (k - 1))
}

// Right returns the right child of an intermediate node.
func Right(x, n uint64) uint64 {
	r := RightStep(x)
	w := nodeWidth(n)
	for r >= w {
		r = Left(r)
	}
	return r
}

func ParentStep(x uint64) uint64 {
	k := Level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// Parent returns the id of the parent node x, if there are n nodes in the tree
// total.
func Parent(x, n uint64) uint64 {
	if x == Root(n) {
		panic("root node has no parent")
	}
	width := nodeWidth(n)
	p := ParentStep(x)
	for p >= width {
		p = ParentStep(p)
	}
	return p
}

// Sibling returns the other child of the node's parent.
func Sibling(x, n uint64) uint64 {
	p := Parent(x, n)
	if x < p {
		return Right(p, n)
	} else {
		return Left(p)
	}
}

// DirectPath returns the direct path of a node, ordered from leaf to root.
func DirectPath(x, n uint64) []uint64 {
	d := make([]uint64, 0)
	r := Root(n)
	for x != r {
		x = Parent(x, n)
		d = append(d, x)
	}
	return d
}

// Copath returns the copath of a node, ordered from leaf to root.
func Copath(x, n uint64) []uint64 {
	if x == Root(n) {
		return make([]uint64, 0)
	}

	d := DirectPath(x, n)
	d = append([]uint64{x}, d...)
	d = d[:len(d)-1]
	for i := range len(d) {
		d[i] = Sibling(d[i], n)
	}

	return d
}

// IsFullSubtree returns true if node x represents a full subtree.
func IsFullSubtree(x, n uint64) bool {
	rightmost := 2 * (n - 1)
	expected := x + (1 << Level(x)) - 1

	return expected <= rightmost
}

// FullSubtrees returns the list of full subtrees that x consists of.
func FullSubtrees(x, n uint64) []uint64 {
	out := make([]uint64, 0)

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

// BatchCopath returns the copath nodes of a batch of leaves. `n` is the current
// number of leaves, and `m` is the optional previous log size to prove
// consistency with.
func BatchCopath(leaves []uint64, n uint64, m *uint64) []uint64 {
	// Compute the set of node indices to prove inclusion for. This is a
	// combination of the requested leaves and any retained subtrees from `m`.
	dedup := make(map[uint64]struct{})
	for _, x := range leaves {
		dedup[2*x] = struct{}{}
	}
	if m != nil {
		for _, x := range FullSubtrees(Root(*m), *m) {
			dedup[x] = struct{}{}
		}
	}
	nodes := make([]uint64, 0, len(dedup))
	for x := range dedup {
		nodes = append(nodes, x)
	}
	slices.Sort(nodes)

	return batchCopath(Root(n), n, nodes)
}

func batchCopath(x, n uint64, nodes []uint64) []uint64 {
	if len(nodes) == 0 {
		return FullSubtrees(x, n)
	} else if len(nodes) == 1 && nodes[0] == x {
		return nil
	}
	i, found := slices.BinarySearch(nodes, x)
	j := i
	if found {
		j++
	}
	return append(batchCopath(Left(x), n, nodes[:i]),
		batchCopath(Right(x, n), n, nodes[j:])...)
}

// Chunk takes a node id as input and returns the id of the chunk that the node
// would be stored in, in the database.
//
// Chunks store 8 consecutive nodes from the same level of the tree,
// representing a subtree of height 4. The chunk is identified by the root of
// this subtree.
func Chunk(x uint64) uint64 {
	c := x
	for Level(c)%4 != 3 {
		c = ParentStep(c)
	}
	return c
}
