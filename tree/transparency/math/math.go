// Package math implements the mathematical operations for a Transparency Tree.
package math

// isLeaf returns true if x is the id of a leaf node.
func isLeaf(x uint64) bool {
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
	if isLeaf(x) {
		return 0
	}
	k := uint64(0)
	for ((x >> k) & 1) == 1 {
		k += 1
	}
	return k
}

// root returns the id of the root node of a tree with n entries.
func root(n uint64) uint64 {
	return (1 << log2(n)) - 1
}

// left returns the left child of an intermediate node.
func left(x uint64) uint64 {
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

// right returns the right child of an intermediate node.
func right(x, n uint64) uint64 {
	r := rightStep(x)
	for r >= n {
		r = left(r)
	}
	return r
}

func parentStep(x uint64) uint64 {
	k := level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// parent returns the id of the parent node of x.
func parent(x, n uint64) uint64 {
	if x == root(n) {
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
	r := root(n)
	y := x
	for y != r {
		y = parent(y, n)
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
		out = append(out, root(m))
	} else {
		out = append(out, rightDirectPath(m-1, n)...)
	}

	for out[len(out)-1] != n-1 {
		out = append(out, right(out[len(out)-1], n))
	}

	return out
}
