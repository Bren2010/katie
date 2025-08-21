package prefix

const maxWeight = 2000

func makeOneTile(ver, ctrOffset uint64, root *node) ([]node, error) {
	// Queue for a breadth-first search through the prefix tree.
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
		if newWeight <= maxWeight {
			queue = append(queue, &pn.left, &pn.right)
			weight = newWeight
		} else {
			ejected = append(ejected, pn)
			*ptr = externalNode{
				hash: TODO,
				ver:  ver,
				ctr:  ctrOffset + uint64(len(ejected)),
			}
		}
	}

	return ejected, nil
}

func tiles(ver uint64, root node) ([]node, error) {
	queue := make([]node, 1)
	queue[0] = root

	weight := root.Weight()

	ejected := make([]node, 0)

	for len(queue) > 0 {
		pn, ok := queue[0].(*node)
		queue = queue[1:]
		if !ok {
			// If n is any type other than parentNode, then it is necessarily
			// included in the current tile.
			continue
		}

		newWeight := weight - pn.Weight() + pn.left.Weight() + pn.right.Weight()
		if newWeight <= maxWeight {
			queue = append(queue, pn.left, pn.right)
			weight = newWeight
		} else {

		}
	}
}
