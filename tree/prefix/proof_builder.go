package prefix

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
)

type indexedVrfOutput struct {
	index     int
	vrfOutput []byte
}

// sortVrfOutputs sorts the given VRF outputs but retains the original
// positions. Equal VRF outputs are sorted by their original position.
func sortVrfOutputs(vrfOutputs [][]byte) []indexedVrfOutput {
	indexed := make([]indexedVrfOutput, len(vrfOutputs))
	for i, vrfOutput := range vrfOutputs {
		indexed[i] = indexedVrfOutput{index: i, vrfOutput: vrfOutput}
	}
	slices.SortFunc(indexed, func(a, b indexedVrfOutput) int {
		if c := bytes.Compare(a.vrfOutput, b.vrfOutput); c != 0 {
			return c
		}
		return cmp.Compare(a.index, b.index)
	})
	return indexed
}

func splitVrfOutputs(vrfOutputs [][]byte, depth int) ([][]byte, [][]byte) {
	split, _ := slices.BinarySearchFunc(vrfOutputs, true, func(out []byte, _ bool) int {
		if getBit(out, depth) {
			return 0
		}
		return -1
	})
	return vrfOutputs[:split], vrfOutputs[split:]
}

func splitIndexed(indexed []indexedVrfOutput, depth int) ([]indexedVrfOutput, []indexedVrfOutput) {
	split, _ := slices.BinarySearchFunc(indexed, true, func(out indexedVrfOutput, _ bool) int {
		if getBit(out.vrfOutput, depth) {
			return 0
		}
		return -1
	})
	return indexed[:split], indexed[split:]
}

func splitEntries(entries []Entry, depth int) ([]Entry, []Entry) {
	split, _ := slices.BinarySearchFunc(entries, true, func(out Entry, _ bool) int {
		if getBit(out.VrfOutput, depth) {
			return 0
		}
		return -1
	})
	return entries[:split], entries[split:]
}

type proofBuilder struct {
	cs suites.CipherSuite

	proof       PrefixProof
	commitments [][]byte
}

// runProofBuilder builds a proof for the VRF outputs in `vrfOutputs`, which
// must be sorted. The search results and commitments are returned in the
// original order of the VRF outputs.
func runProofBuilder(cs suites.CipherSuite, root node, vrfOutputs []indexedVrfOutput) (PrefixProof, [][]byte) {
	pb := proofBuilder{
		cs: cs,

		proof:       PrefixProof{Results: make([]PrefixSearchResult, len(vrfOutputs))},
		commitments: make([][]byte, len(vrfOutputs)),
	}
	pb.build(root, vrfOutputs, 0)

	return pb.proof, pb.commitments
}

func (pb *proofBuilder) build(n node, vrfOutputs []indexedVrfOutput, depth int) {
	if len(vrfOutputs) == 0 {
		pb.proof.Elements = append(pb.proof.Elements, n.Hash(pb.cs))
		return
	}

	switch n := n.(type) {
	case emptyNode:
		for _, out := range vrfOutputs {
			pb.proof.Results[out.index] = nonInclusionParentProof{depth: depth}
		}

	case leafNode:
		for _, out := range vrfOutputs {
			if bytes.Equal(out.vrfOutput, n.vrfOutput) {
				pb.proof.Results[out.index] = inclusionProof{depth: depth}
				pb.commitments[out.index] = n.commitment
			} else {
				pb.proof.Results[out.index] = nonInclusionLeafProof{leaf: n, depth: depth}
			}
		}

	case *parentNode:
		left, right := splitIndexed(vrfOutputs, depth)
		pb.build(n.left, left, depth+1)
		pb.build(n.right, right, depth+1)

	default:
		panic("unexpected node type found")
	}
}

// addRemoveEntries adds and removes the requested entries from the subtree in
// `n`.
//

// The VRF outputs of the entries are given in `vrfOutputs`, which must be
// sorted with sortVrfOutputs. A VRF output with an index less than len(add) is
// for an entry being added, whose commitment is taken from `add`. Otherwise,
// it's for an entry being removed. It returns the leaves that moved up in the
// tree without being on the search path of any added or removed entry.
func addRemoveEntries(
	cs suites.CipherSuite,
	n node,
	add []Entry,
	remove [][]byte,
	depth int,
) (node, []Entry) {
	if len(add) == 0 && len(remove) == 0 {
		// Replace parent nodes that are unnecessary with external nodes. Other
		// node types are allowed to move into the new tile unchanged.
		if p, ok := n.(*parentNode); ok {
			return externalNode{hash: p.Hash(cs), id: *p.id}, nil
		}
		return n, nil
	}

	switch m := n.(type) {
	case emptyNode:
		if len(add) == 1 {
			return leafNode{vrfOutput: add[0].VrfOutput, commitment: add[0].Commitment}, nil
		} else if len(add) > 1 {
			temp := &parentNode{left: emptyNode{}, right: emptyNode{}}
			return addRemoveEntries(cs, temp, add, nil, depth)
		}
		return m, nil

	case leafNode:
		shouldRemove := false
		for _, vrfOutput := range remove {
			if bytes.Equal(m.vrfOutput, vrfOutput) {
				shouldRemove = true
				break
			}
		}

		if shouldRemove {
			// We're removing this leaf. Replace it with an emptyNode and
			// recurse to handle any additions that need to happen post-removal.
			return addRemoveEntries(cs, emptyNode{}, add, nil, depth)
		} else if len(add) > 0 {
			// We're keeping this leaf but it's in the way of other leaves we
			// want to add, so push it down one level and recurse.
			temp := &parentNode{left: emptyNode{}, right: emptyNode{}}
			if getBit(m.vrfOutput, depth) {
				temp.right = m
			} else {
				temp.left = m
			}
			return addRemoveEntries(cs, temp, add, nil, depth)
		}
		return m, nil

	case *parentNode:
		// Handle any additions / removals below this parent.
		leftAdd, rightAdd := splitEntries(add, depth)
		leftRemove, rightRemove := splitVrfOutputs(remove, depth)

		left, leaves := addRemoveEntries(cs, m.left, leftAdd, leftRemove, depth+1)
		right, rightLeaves := addRemoveEntries(cs, m.right, rightAdd, rightRemove, depth+1)
		var out node = &parentNode{left: left, right: right}

		// If our parent has two children that are emptyNodes, or one child
		// that's a leaf and one child that's an emptyNode, then simplify the
		// tree. Additionally return the moved leaf if a verifier wouldn't
		// otherwise be able to see that it should be moved.
		var (
			leftTouched  = len(leftAdd) > 0 || len(leftRemove) > 0
			rightTouched = len(rightAdd) > 0 || len(rightRemove) > 0

			leftLeaf, leftIsLeaf   = left.(leafNode)
			_, leftIsEmpty         = left.(emptyNode)
			rightLeaf, rightIsLeaf = right.(leafNode)
			_, rightIsEmpty        = right.(emptyNode)
		)
		if leftIsLeaf && rightIsEmpty {
			if !leftTouched {
				leaves = append(leaves, Entry{leftLeaf.vrfOutput, leftLeaf.commitment})
			}
			out = left
		} else if leftIsEmpty && rightIsLeaf {
			if !rightTouched {
				leaves = append(leaves, Entry{rightLeaf.vrfOutput, rightLeaf.commitment})
			}
			out = right
		} else if leftIsEmpty && rightIsEmpty {
			out = emptyNode{}
		}

		leaves = append(leaves, rightLeaves...)
		return out, leaves

	default:
		panic("unexpected node type found")
	}
}
