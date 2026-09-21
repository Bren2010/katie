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
		// The leaf that supposedly shows non-inclusion should have the same
		// prefix as the VRF output we searched for, but differ at some point.
		depth := res.Depth()
		for i := range depth {
			if getBit(entry.VrfOutput, i) != getBit(res.leaf.vrfOutput, i) {
				return nil, errors.New("non-inclusion proof not consistent with the vrf output searched for")
			}
		}
		if bytes.Equal(entry.VrfOutput, res.leaf.vrfOutput) {
			return nil, errors.New("non-inclusion proof not consistent with the vrf output searched for")
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

// evaluate returns the in-memory tree that `proof` corresponds to.
func evaluate(cs suites.CipherSuite, entries []Entry, proof *PrefixProof) (node, error) {
	for _, entry := range entries {
		if len(entry.VrfOutput) != cs.HashSize() {
			return nil, errors.New("unexpected vrf output length")
		} else if entry.Commitment != nil && len(entry.Commitment) != cs.HashSize() {
			return nil, errors.New("unexpected commitment length")
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
// additions and removals. The leaves that move up in the tree as a result of
// the mutation, but that aren't on the search path of any added or removed
// entry, must be provided in `leaves`.
func EvaluateBeforeAfter(cs suites.CipherSuite, add, remove, leaves []Entry, proof *PrefixProof) ([]byte, []byte, error) {
	// Verify that the provided entries are well formed.
	if len(add) == 0 && len(remove) == 0 {
		return nil, nil, errors.New("no mutations requested")
	}

	for i, entry := range add {
		if len(entry.Commitment) != cs.HashSize() {
			return nil, nil, errors.New("unexpected commitment length")
		} else if i > 0 && bytes.Compare(add[i-1].VrfOutput, entry.VrfOutput) != -1 {
			return nil, nil, errors.New("duplicate or unsorted vrf output given")
		}
	}
	vrfOutputs := make([][]byte, len(remove))
	for i, entry := range remove {
		if i > 0 && bytes.Compare(remove[i-1].VrfOutput, entry.VrfOutput) != -1 {
			return nil, nil, errors.New("duplicate or unsorted vrf output given")
		}
		vrfOutputs[i] = entry.VrfOutput
	}

	// Compute the full combined slice of entries and evaluate the prefix proof.
	allEntries := make([]Entry, len(add)+len(remove)+len(leaves))
	copy(allEntries, add)
	copy(allEntries[len(add):], remove)
	copy(allEntries[len(add)+len(remove):], leaves)

	root, err := evaluate(cs, allEntries, proof)
	if err != nil {
		return nil, nil, err
	}

	// Every added entry should correspond to a non-inclusion proof, unless it's
	// also in remove.
	for i := range add {
		if proof.Results[i].Inclusion() {
			_, found := slices.BinarySearchFunc(remove, add[i], func(a, b Entry) int {
				return bytes.Compare(a.VrfOutput, b.VrfOutput)
			})
			if !found {
				return nil, nil, errors.New("unable to add leaf that already exists")
			}
		}
	}
	// Every removed entry should correspond to an inclusion proof.
	for i := range remove {
		if !proof.Results[len(add)+i].Inclusion() {
			return nil, nil, errors.New("entry being removed is not in the tree")
		}
	}

	// Perform the additions and removals.
	newRoot, expectedLeaves := addRemoveEntries(cs, root, add, vrfOutputs, 0)

	// The given set of moved leaves should exactly match what we computed
	// ourselves.
	if len(leaves) != len(expectedLeaves) {
		return nil, nil, errors.New("invalid set of moved leaves given")
	}
	for i, entry := range leaves {
		expected := expectedLeaves[i]
		if !bytes.Equal(entry.VrfOutput, expected.VrfOutput) {
			return nil, nil, errors.New("invalid set of moved leaves given")
		} else if !bytes.Equal(entry.Commitment, expected.Commitment) {
			return nil, nil, errors.New("invalid set of moved leaves given")
		} else if !proof.Results[len(add)+len(remove)+i].Inclusion() {
			return nil, nil, errors.New("moved leaf is not in the tree")
		}
	}

	return root.Hash(cs), newRoot.Hash(cs), nil
}
