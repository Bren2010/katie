package prefix

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
)

// terminalNode returns the terminal node of the search.
func terminalNode(entry Entry, res PrefixSearchResult) node {
	switch res := res.(type) {
	case inclusionProof:
		return leafNode{entry.VrfOutput, entry.Commitment}
	case nonInclusionLeafProof:
		return res.leaf
	case nonInclusionParentProof:
		return emptyNode{}
	default:
		panic("unexpected search result type found")
	}
}

// addToSkeleton adds the terminal node for a single search result
// to the in-memory tree in `n`.
func addToSkeleton(n *node, entry Entry, res PrefixSearchResult) error {
	depth := 0

	for {
		switch m := (*n).(type) {
		case emptyNode:
			if res.Depth() != depth || res.Inclusion() {
				return errors.New("malformed proof")
			}
			return nil

		case leafNode:
			equal := bytes.Equal(entry.VrfOutput, m.vrfOutput)
			if res.Depth() != depth || res.Inclusion() != equal {
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
				*n = terminalNode(entry, res)
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
// in left-to-right order.
func fillInCopath(n *node, elements [][]byte) ([][]byte, error) {
	switch m := (*n).(type) {
	case emptyNode, leafNode:
		return elements, nil

	case *parentNode:
		var err error
		elements, err = fillInCopath(&m.left, elements)
		if err != nil {
			return nil, err
		}
		elements, err = fillInCopath(&m.right, elements)
		if err != nil {
			return nil, err
		}
		return elements, nil

	case externalNode:
		if len(elements) == 0 {
			return nil, errors.New("wrong number of copath nodes provided")
		}
		*n = externalNode{hash: elements[0]}
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
	elements, err := fillInCopath(&root, proof.Elements)
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
