package prefix

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
)

// terminalNode returns the node that `res` claims is at the end of the search
// path for `entry`. It returns an error if the search result is not internally
// consistent with the entry that was searched for.
func terminalNode(entry Entry, res PrefixSearchResult) (node, error) {
	switch res := res.(type) {
	case inclusionProof:
		// The commitment is part of the leaf that's being proved to exist, so
		// it must be known to evaluate the proof.
		if entry.Commitment == nil {
			return nil, errors.New("no commitment provided for entry proved to be included")
		}
		return leafNode{entry.VrfOutput, entry.Commitment}, nil

	case nonInclusionLeafProof:
		// The leaf presented must be different from the one that was searched
		// for, otherwise this would be an inclusion proof.
		if bytes.Equal(entry.VrfOutput, res.leaf.vrfOutput) {
			return nil, errors.New("non-inclusion proof presents the vrf output that was searched for")
		}
		return res.leaf, nil

	case nonInclusionParentProof:
		return emptyNode{}, nil

	default:
		panic("unexpected search result type found")
	}
}

// sameTerminalNode returns true if `a` and `b` are the same terminal (leaf or
// empty) node.
func sameTerminalNode(a, b node) bool {
	switch a := a.(type) {
	case emptyNode:
		_, ok := b.(emptyNode)
		return ok

	case leafNode:
		b, ok := b.(leafNode)
		return ok &&
			bytes.Equal(a.vrfOutput, b.vrfOutput) &&
			bytes.Equal(a.commitment, b.commitment)

	default:
		return false
	}
}

// addToSkeleton adds the terminal node for a single search result
// to the in-memory tree in `n`.
func addToSkeleton(n *node, entry Entry, res PrefixSearchResult) error {
	terminal, err := terminalNode(entry, res)
	if err != nil {
		return err
	}
	depth := 0

	for {
		switch m := (*n).(type) {
		case emptyNode, leafNode:
			// Another search result has already established which node is at
			// this position, so this search must agree with it: both that the
			// search terminates here, and on the contents of the node.
			if res.Depth() != depth || !sameTerminalNode(m, terminal) {
				return errors.New("malformed proof")
			}
			return nil

		case *parentNode:
			if getBit(entry.VrfOutput, depth) {
				n = &m.right
			} else {
				n = &m.left
			}
			depth++

		case externalNode:
			if depth > res.Depth() {
				return errors.New("current depth is greater than result depth")
			} else if depth == res.Depth() {
				*n = terminal
				return nil
			} else {
				*n = &parentNode{left: externalNode{}, right: externalNode{}}
			}

		default:
			panic("unexpected node type found")
		}
	}
}

// fillInCopath populates all of the empty copath nodes in `n` with `elements`
// in left-to-right order. Copath nodes with an all-zero hash are populated as
// emptyNodes, which allows EvaluateBeforeAfter to simplify the tree around them.
func fillInCopath(cs suites.CipherSuite, n *node, elements [][]byte) ([][]byte, error) {
	switch m := (*n).(type) {
	case emptyNode, leafNode:
		return elements, nil

	case *parentNode:
		var err error
		elements, err = fillInCopath(cs, &m.left, elements)
		if err != nil {
			return nil, err
		}
		elements, err = fillInCopath(cs, &m.right, elements)
		if err != nil {
			return nil, err
		}
		return elements, nil

	case externalNode:
		if len(elements) == 0 {
			return nil, errors.New("wrong number of copath nodes provided")
		}
		if bytes.Equal(elements[0], make([]byte, cs.HashSize())) {
			*n = emptyNode{}
		} else {
			*n = externalNode{hash: elements[0]}
		}
		return elements[1:], nil

	default:
		panic("unexpected node type found")
	}
}

func evaluate(cs suites.CipherSuite, entries []Entry, proof *PrefixProof) (node, error) {
	sortedEntries := make([]Entry, len(entries))
	copy(sortedEntries, entries)
	slices.SortFunc(sortedEntries, compareEntries)
	for i, entry := range sortedEntries {
		if len(entry.VrfOutput) != cs.HashSize() {
			return nil, errors.New("unexpected vrf output length")
		} else if entry.Commitment != nil && len(entry.Commitment) != cs.HashSize() {
			return nil, errors.New("unexpected commitment length")
		} else if i > 0 && bytes.Equal(sortedEntries[i-1].VrfOutput, entry.VrfOutput) {
			return nil, errors.New("same vrf output present multiple times")
		}
	}
	if len(entries) != len(proof.Results) {
		return nil, errors.New("number of entries searched for does not match number of results")
	}

	var root node = externalNode{}
	for i, entry := range entries {
		if err := addToSkeleton(&root, entry, proof.Results[i]); err != nil {
			return nil, err
		}
	}
	elements, err := fillInCopath(cs, &root, proof.Elements)
	if err != nil {
		return nil, err
	} else if len(elements) != 0 {
		return nil, errors.New("wrong number of copath nodes provided")
	}

	return root, nil
}

// Evaluate returns the root hash that `proof` corresponds to.
func Evaluate(cs suites.CipherSuite, entries []Entry, proof *PrefixProof) ([]byte, error) {
	root, err := evaluate(cs, entries, proof)
	if err != nil {
		return nil, err
	}
	return root.Hash(cs), nil
}

// Verify checks that the provided root hash matches `proof`.
func Verify(cs suites.CipherSuite, entries []Entry, proof *PrefixProof, root []byte) error {
	cand, err := Evaluate(cs, entries, proof)
	if err != nil {
		return err
	} else if !bytes.Equal(root, cand) {
		return errors.New("root hash does not match expected value")
	}
	return nil
}

// EvaluateBeforeAfter evaluates `proof` before and after making the requested
// additions and removals.
func EvaluateBeforeAfter(cs suites.CipherSuite, add, remove []Entry, proof *PrefixProof) ([]byte, []byte, error) {
	// Combine the `add` and `remove` slices and compute the prefix tree root
	// hash in the straightforward way.
	allEntries := make([]Entry, len(add)+len(remove))
	copy(allEntries, add)
	copy(allEntries[len(add):], remove)

	root, err := evaluate(cs, allEntries, proof)
	if err != nil {
		return nil, nil, err
	}

	// Check that the search results are consistent with the mutation that's
	// being made: entries that are being added must not be in the tree already,
	// and entries that are being removed must be in the tree.
	for i := range add {
		if proof.Results[i].Inclusion() {
			return nil, nil, errors.New("entry being added is already in the tree")
		}
	}
	for i := range remove {
		if !proof.Results[len(add)+i].Inclusion() {
			return nil, nil, errors.New("entry being removed is not in the tree")
		}
	}

	before := root.Hash(cs)

	// Perform the additions and removals and compute what the prefix tree root
	// hash would be then.
	sortedAdd := make([]Entry, len(add))
	copy(sortedAdd, add)
	slices.SortFunc(sortedAdd, compareEntries)

	sortedRemove := make([][]byte, len(remove))
	for i, entry := range remove {
		sortedRemove[i] = entry.VrfOutput
	}
	slices.SortFunc(sortedRemove, bytes.Compare)

	addRemoveEntries(cs, &root, sortedAdd, sortedRemove, 0)
	after := root.Hash(cs)

	return before, after, nil
}
