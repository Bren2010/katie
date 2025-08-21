package prefix

import "github.com/Bren2010/katie/crypto/suites"

const TargetTileWeight = 2000

// makeOneTile performs a breadth-first search to produce the largest tile
// possible without exceeing TargetTileWeight. The tile is stored in root and
// ejected nodes are returned.
func makeOneTile(cs suites.CipherSuite, ver, ctrOffset uint64, root *node) []node {
	// Queue for the breadth-first search through the tree.
	queue := make([]*node, 1)
	queue[0] = root

	// Weight (approx. size in bytes) of the current tile.
	weight := (*root).Weight()

	// Nodes that were ejected from this tile because they don't fit.
	ejected := make([]node, 0)

	for len(queue) > 0 {
		ptr := queue[0]
		queue = queue[1:]

		pn, ok := (*ptr).(parentNode)
		if !ok {
			// If n is any type other than parentNode, then it is necessarily
			// included in the current tile.
			continue
		}

		newWeight := weight - pn.Weight() + pn.left.Weight() + pn.right.Weight()
		if newWeight <= TargetTileWeight {
			queue = append(queue, &pn.left, &pn.right)
			weight = newWeight
		} else {
			ejected = append(ejected, pn)
			*ptr = externalNode{
				hash: ([32]byte)(pn.Hash(cs)),
				ver:  ver,
				ctr:  ctrOffset + uint64(len(ejected)),
			}
		}
	}

	return ejected
}

// tiles converts a (possibly abridged) prefix tree in `root` into a series of
// tiles / subtrees that obey a maximum size limit.
func tiles(cs suites.CipherSuite, ver uint64, root node) []node {
	queue := make([]node, 0)
	queue[0] = root

	out := make([]node, 0)

	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]

		ejected := makeOneTile(cs, ver, uint64(len(out)), &n)
		queue = append(queue, ejected...)
		out = append(out, n)
	}

	return out
}
