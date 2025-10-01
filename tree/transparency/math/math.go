// Package math implements the mathematical operations for a Transparency Tree.
package math

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

// level returns the level of a node in the tree.
func level(x uint64) uint64 {
	if IsLeaf(x) {
		return 0
	}
	k := uint64(0)
	for ((x >> k) & 1) == 1 {
		k += 1
	}
	return k
}

// Root returns the id of the root node of a tree with n entries.
func Root(n uint64) uint64 {
	return (1 << log2(n)) - 1
}

// Left returns the left child of an intermediate node.
func Left(x uint64) uint64 {
	k := level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (1 << (k - 1))
}

func rightStep(x uint64) uint64 {
	k := level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (3 << (k - 1))
}

// Right returns the right child of an intermediate node.
func Right(x, n uint64) uint64 {
	r := rightStep(x)
	for r >= n {
		r = Left(r)
	}
	return r
}

func parentStep(x uint64) uint64 {
	k := level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// Parent returns the id of the parent node of x.
func Parent(x, n uint64) uint64 {
	if x == Root(n) {
		panic("root node has no parent")
	}
	p := parentStep(x)
	for p >= n {
		p = parentStep(p)
	}
	return p
}

// rightDirectPath returns the nodes which are in the direct path of a node and
// to its right, ordered from leaf to root.
func rightDirectPath(x, n uint64) []uint64 {
	d := make([]uint64, 0)
	r := Root(n)
	y := x
	for y != r {
		y = Parent(y, n)
		if y > x {
			d = append(d, y)
		}
	}
	return d
}

// UpdateView returns the indices of the log entries whose timestamps need to be
// provided for a verifier to update their view of the tree.
func UpdateView(m, n uint64) []uint64 {
	out := make([]uint64, 0)

	if m == 0 {
		out = append(out, Root(m))
	} else {
		out = append(out, rightDirectPath(m-1, n)...)
	}

	for out[len(out)-1] != n-1 {
		out = append(out, Right(out[len(out)-1], n))
	}

	return out
}
