package prefix

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
)

// extendToDepth handles the case where the terminal node of a search is at some
// specific depth in the tree. It follows the bits of the VRF output in `entry`
// and pushes down to that depth before inserting the terminal node.
func extendToDepth(entry Entry, res PrefixSearchResult, elements [][]byte, depth int) (node, [][]byte, error) {
	if res.Depth() > depth {
		return nil, nil, errors.New("current depth is greater than result depth")
	} else if res.Depth() == depth {
		return terminalNode(entry, res), elements, nil
	}

	if getBit(entry.VrfOutput, depth) {
		if len(elements) == 0 {
			return nil, nil, errors.New("malformed proof")
		}
		left := externalNode{hash: elements[0]}
		right, elements, err := extendToDepth(entry, res, elements[1:], depth+1)
		if err != nil {
			return nil, nil, err
		}

		return &parentNode{left: left, right: right}, elements, nil
	} else {
		left, elements, err := extendToDepth(entry, res, elements, depth+1)
		if err != nil {
			return nil, nil, err
		} else if len(elements) == 0 {
			return nil, nil, errors.New("malformed proof")
		}
		right := externalNode{hash: elements[0]}

		return &parentNode{left: left, right: right}, elements[1:], nil
	}
}

// terminalNode returns the terminal node of the search.
func terminalNode(entry Entry, res PrefixSearchResult) node {
	switch res := res.(type) {
	case inclusionProof:
		return leafNode{vrfOutput: entry.VrfOutput, commitment: entry.Commitment}
	case nonInclusionLeafProof:
		return res.leaf
	case nonInclusionParentProof:
		return emptyNode{}
	default:
		panic("unexpected search result type found")
	}
}

// evaluate recursively converts a PrefixProof structure into an in-memory tree
// of nodes. `entries` are the values that were searched for in the current
// subtree, `results` are the search results contained in the current subtree,
// `elements` is a queue of copath hash values, and `depth` is the current
// depth.
//
// It returns a node representing the subtree, and the queue of copath hash
// values with consumed values removed.
func evaluate(entries []Entry, results []PrefixSearchResult, elements [][]byte, depth int) (node, [][]byte, error) {
	switch len(entries) {
	case 0:
		if len(elements) == 0 {
			return nil, nil, errors.New("malformed proof")
		}
		return externalNode{hash: elements[0]}, elements[1:], nil

	case 1:
		return extendToDepth(entries[0], results[0], elements, depth)

	default:
		split, _ := slices.BinarySearchFunc(entries, true, func(entry Entry, _ bool) int {
			if getBit(entry.VrfOutput, depth) {
				return 0
			}
			return -1
		})

		left, elements, err := evaluate(entries[:split], results[:split], elements, depth+1)
		if err != nil {
			return nil, nil, err
		}
		right, elements, err := evaluate(entries[split:], results[split:], elements, depth+1)
		if err != nil {
			return nil, nil, err
		}

		return &parentNode{left: left, right: right}, elements, nil
	}
}

// Evaluate returns the root hash that `proof` corresponds to.
func Evaluate(cs suites.CipherSuite, entries []Entry, proof *PrefixProof) ([]byte, error) {
	slices.SortFunc(entries, func(a, b Entry) int {
		return bytes.Compare(a.VrfOutput, b.VrfOutput)
	})

	root, elements, err := evaluate(entries, proof.Results, proof.Elements, 0)
	if err != nil {
		return nil, err
	} else if len(elements) != 0 {
		return nil, errors.New("malformed proof")
	}

	return root.Hash(cs), nil
}
