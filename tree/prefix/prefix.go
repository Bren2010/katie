// Package prefix implements a Prefix Tree that supports versioning and batch
// searches and insertions.
package prefix

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
)

type PrefixSearch struct {
	Version    uint64
	VrfOutputs [][]byte
}

type SearchResult struct {
	Proof       PrefixProof
	Commitments [][]byte
}

// Tree implements a Prefix Tree backed by a connection to a database.
type Tree struct {
	cs suites.CipherSuite
	tx db.PrefixStore
}

func NewTree(cs suites.CipherSuite, tx db.PrefixStore) *Tree {
	return &Tree{cs, tx}
}

// Search takes as input a map from each version of the tree to search, to the
// list of VRF outputs to search for in that version of the tree. It returns a
// map from the searched versions of the tree to a batch PrefixProof.
func (t *Tree) Search(searches []PrefixSearch) ([]SearchResult, error) {
	combined := make(map[uint64][][]byte)
	for _, search := range searches {
		if search.Version == 0 {
			return nil, errors.New("unable to search in version 0 of the tree")
		}
		for _, vrfOutput := range search.VrfOutputs {
			if len(vrfOutput) != t.cs.HashSize() {
				return nil, errors.New("unexpected vrf output length")
			}
		}
		combined[search.Version] = append(combined[search.Version], search.VrfOutputs...)
	}

	b := newBatch(t.cs, t.tx)
	res, state := b.initialize(combined)
	if err := b.search(state); err != nil {
		return nil, err
	}

	out := make([]SearchResult, len(searches))
	for i, search := range searches {
		tile, ok := res[search.Version]
		if !ok {
			return nil, errors.New("expected tile not found")
		}
		proof, commitments := runProofBuilder(t.cs, tile.root, search.VrfOutputs)
		out[i] = SearchResult{proof, commitments}
	}
	return out, nil
}

// Entry contains a new entry to be added to the tree.
type Entry struct {
	VrfOutput, Commitment []byte
}

// Mutate adds a set of new entries to the tree, removes the requested entries,
// and increments the version counter. It returns the new root hash, a batch
// proof from just before the additions and removals were applied, and the
// removed commitments.
//
// The current tree version is given in `ver`, which is 0 if the tree is empty.
// After this, version `ver+1` of the tree will exist.
func (t *Tree) Mutate(ver uint64, add []Entry, remove [][]byte) ([]byte, *PrefixProof, [][]byte, error) {
	// Sort the list of new entries to add and verify that they're well formed.
	sortedAdd := make([]Entry, len(add))
	copy(sortedAdd, add)
	slices.SortFunc(sortedAdd, func(a, b Entry) int {
		return bytes.Compare(a.VrfOutput, b.VrfOutput)
	})
	for i, entry := range sortedAdd {
		if len(entry.VrfOutput) != t.cs.HashSize() {
			return nil, nil, nil, errors.New("unexpected vrf output length")
		} else if len(entry.Commitment) != t.cs.HashSize() {
			return nil, nil, nil, errors.New("unexpected commitment length")
		} else if i > 0 && bytes.Equal(sortedAdd[i-1].VrfOutput, entry.VrfOutput) {
			return nil, nil, nil, errors.New("unable to insert same vrf output multiple times")
		}
	}

	// Sort the list of entries to remove and verify that they're well formed.
	sortedRemove := make([][]byte, len(remove))
	copy(sortedRemove, remove)
	slices.SortFunc(sortedRemove, bytes.Compare)
	for i, vrfOutput := range sortedRemove {
		if len(vrfOutput) != t.cs.HashSize() {
			return nil, nil, nil, errors.New("unexpected vrf output length")
		} else if i > 0 && bytes.Equal(sortedRemove[i-1], vrfOutput) {
			return nil, nil, nil, errors.New("unable to remove the same vrf output multiple times")
		}
	}

	// Check for intersection between sortedAdd and sortedRemove
	for i, j := 0, 0; i < len(sortedAdd) && j < len(sortedRemove); {
		cmp := bytes.Compare(sortedAdd[i].VrfOutput, sortedRemove[j])
		switch cmp {
		case -1:
			i++
		case 1:
			j++
		default:
			return nil, nil, nil, errors.New("can not add and remove the same vrf output")
		}
	}

	// Load necessary tiles into memory. Add new entries. Create tiles.
	root, proof, commitments, err := t.getMutationRoot(ver, add, remove)
	if err != nil {
		return nil, nil, nil, err
	}
	addRemoveEntries(t.cs, &root, sortedAdd, sortedRemove, 0)

	rootHash := root.Hash(t.cs)
	tiles := splitIntoTiles(t.cs, ver+1, root)

	// Write tiles to database.
	data := make(map[string][]byte, len(tiles))
	for _, tile := range tiles {
		raw, err := tile.Marshal(t.cs)
		if err != nil {
			return nil, nil, nil, err
		}
		data[tile.id.String()] = raw
	}
	if err := t.tx.BatchPut(data); err != nil {
		return nil, nil, nil, err
	}

	return rootHash, proof, commitments, nil
}

// getMutationRoot returns the node to operate on for our mutation. It also
// returns the prior-version PrefixProof.
func (t *Tree) getMutationRoot(ver uint64, add []Entry, remove [][]byte) (node, *PrefixProof, [][]byte, error) {
	vrfOutputs := make([][]byte, 0, len(add)+len(remove))
	for _, entry := range add {
		vrfOutputs = append(vrfOutputs, entry.VrfOutput)
	}
	vrfOutputs = append(vrfOutputs, remove...)

	if ver == 0 {
		if len(remove) > 0 {
			return nil, nil, nil, errors.New("can not remove vrf output that does not exist")
		}
		root := emptyNode{}
		proof, _ := runProofBuilder(t.cs, root, vrfOutputs)
		return root, &proof, nil, nil
	}

	b := newBatch(t.cs, t.tx)
	res, state := b.initialize(map[uint64][][]byte{ver: vrfOutputs})
	if err := b.search(state); err != nil {
		return nil, nil, nil, err
	}
	root := res[ver].root

	proof, commitments := runProofBuilder(t.cs, root, vrfOutputs)
	for _, commitment := range commitments[:len(add)] {
		if commitment != nil {
			return nil, nil, nil, errors.New("can not insert same vrf output twice")
		}
	}
	for _, commitment := range commitments[len(add):] {
		if commitment == nil {
			return nil, nil, nil, errors.New("can not remove vrf output that does not exist")
		}
	}

	return root, &proof, commitments[len(add):], nil
}

type indexedVrfOutput struct {
	index     int
	vrfOutput []byte
}

type proofBuilder struct {
	cs suites.CipherSuite

	proof       PrefixProof
	commitments [][]byte
}

func runProofBuilder(cs suites.CipherSuite, root node, vrfOutputs [][]byte) (PrefixProof, [][]byte) {
	// Sorts the given VRF outputs to make proof building efficient, but retains
	// the original positions so that we can give results in the same order.
	indexed := make([]indexedVrfOutput, len(vrfOutputs))
	for i, vrfOutput := range vrfOutputs {
		indexed[i] = indexedVrfOutput{index: i, vrfOutput: vrfOutput}
	}
	slices.SortFunc(indexed, func(a, b indexedVrfOutput) int {
		return bytes.Compare(a.vrfOutput, b.vrfOutput)
	})

	pb := proofBuilder{
		cs: cs,

		proof:       PrefixProof{Results: make([]PrefixSearchResult, len(indexed))},
		commitments: make([][]byte, len(indexed)),
	}
	pb.build(root, indexed, 0)

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
		split, _ := slices.BinarySearchFunc(vrfOutputs, true, func(out indexedVrfOutput, _ bool) int {
			if getBit(out.vrfOutput, depth) {
				return 0
			}
			return -1
		})
		pb.build(n.left, vrfOutputs[:split], depth+1)
		pb.build(n.right, vrfOutputs[split:], depth+1)

	default:
		panic("unexpected node type found")
	}
}

func addRemoveEntries(cs suites.CipherSuite, n *node, add []Entry, remove [][]byte, depth int) {
	if len(add) == 0 && len(remove) == 0 {
		// Replace parent nodes that are unnecessary with external nodes. Other
		// node types are allowed to move into the new tile unchanged.
		if p, ok := (*n).(*parentNode); ok {
			*n = externalNode{
				hash: p.Hash(cs),
				id:   *p.id,
			}
		}
		return
	}

	switch m := (*n).(type) {
	case emptyNode:
		if len(add) == 1 {
			*n = leafNode{vrfOutput: add[0].VrfOutput, commitment: add[0].Commitment}
		} else if len(add) > 1 {
			*n = &parentNode{left: emptyNode{}, right: emptyNode{}}
			addRemoveEntries(cs, n, add, nil, depth)
		}

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
			*n = emptyNode{}
			if len(add) > 0 {
				addRemoveEntries(cs, n, add, nil, depth)
			}
		} else if len(add) > 0 {
			// We're keeping this leaf but it's in the way of other leaves we
			// want to add, so push it down one level and recurse.
			if getBit(m.vrfOutput, depth) {
				*n = &parentNode{left: emptyNode{}, right: m}
			} else {
				*n = &parentNode{left: m, right: emptyNode{}}
			}
			addRemoveEntries(cs, n, add, nil, depth)
		}

	case *parentNode:
		m.hash, m.id = nil, nil

		// Handle any additions / removals below this parent.
		leftAdd, rightAdd := splitEntries(add, depth)
		leftRemove, rightRemove := splitVrfOutputs(remove, depth)
		addRemoveEntries(cs, &m.left, leftAdd, leftRemove, depth+1)
		addRemoveEntries(cs, &m.right, rightAdd, rightRemove, depth+1)

		// If this node has two children that are emptyNodes, or one child
		// that's a leaf and one child that's an emptyNode, then simplify the
		// tree a bit.
		_, leftLeaf := m.left.(leafNode)
		_, leftEmpty := m.left.(emptyNode)
		_, rightLeaf := m.right.(leafNode)
		_, rightEmpty := m.right.(emptyNode)

		if leftLeaf && rightEmpty {
			*n = m.left
		} else if leftEmpty && rightLeaf {
			*n = m.right
		} else if leftEmpty && rightEmpty {
			*n = emptyNode{}
		}

	default:
		panic("unexpected node type found")
	}
}

func splitEntries(entries []Entry, depth int) ([]Entry, []Entry) {
	if len(entries) == 0 {
		return nil, nil
	}
	split, _ := slices.BinarySearchFunc(entries, true, func(entry Entry, _ bool) int {
		if getBit(entry.VrfOutput, depth) {
			return 0
		}
		return -1
	})
	return entries[:split], entries[split:]
}

func splitVrfOutputs(vrfOutputs [][]byte, depth int) ([][]byte, [][]byte) {
	if len(vrfOutputs) == 0 {
		return nil, nil
	}
	split, _ := slices.BinarySearchFunc(vrfOutputs, true, func(vrfOutput []byte, _ bool) int {
		if getBit(vrfOutput, depth) {
			return 0
		}
		return -1
	})
	return vrfOutputs[:split], vrfOutputs[split:]
}
