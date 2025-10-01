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

// Tree implements a Prefix Tree backed by a connection to a database.
type Tree struct {
	cs suites.CipherSuite
	tx db.PrefixStore
}

func NewTree(cs suites.CipherSuite, tx db.PrefixStore) *Tree {
	return &Tree{cs: cs, tx: tx}
}

type SearchResult struct {
	Proof       PrefixProof
	Commitments [][]byte
}

// Search takes as input a map from each version of the tree to search, to the
// list of VRF outputs to search for in that version of the tree. It returns a
// map from the searched versions of the tree to a batch PrefixProof.
func (t *Tree) Search(searches map[uint64][][]byte) (map[uint64]SearchResult, error) {
	for ver, vrfOutputs := range searches {
		if ver == 0 {
			return nil, errors.New("unable to search in version 0 of the tree")
		}
		for _, vrfOutput := range vrfOutputs {
			if len(vrfOutput) != t.cs.HashSize() {
				return nil, errors.New("unexpected vrf output length")
			}
		}
	}

	b := newBatch(t.cs, t.tx)
	res, state := b.initialize(searches)
	if err := b.search(state); err != nil {
		return nil, err
	}

	out := make(map[uint64]SearchResult, len(searches))
	for _, tile := range res {
		vrfOutputs := searches[tile.id.ver]
		proof, commitments := runProofBuilder(t.cs, tile.root, vrfOutputs)
		out[tile.id.ver] = SearchResult{Proof: proof, Commitments: commitments}
	}
	return out, nil
}

// Entry contains a new entry to be added to the tree.
type Entry struct {
	VrfOutput, Commitment []byte
}

// Insert adds a set of new entries to the tree and increments the version
// counter. It returns the new root hash and a batch proof from just before the
// entries were added.
//
// The current tree version is given in `ver`, which is 0 if the tree is empty.
// After this, version `ver+1` of the tree will exist.
func (t *Tree) Insert(ver uint64, entries []Entry) ([]byte, *PrefixProof, error) {
	sortedEntries := make([]Entry, len(entries))
	copy(sortedEntries, entries)
	slices.SortFunc(sortedEntries, func(a, b Entry) int {
		return bytes.Compare(a.VrfOutput, b.VrfOutput)
	})
	for i, entry := range sortedEntries {
		if len(entry.VrfOutput) != t.cs.HashSize() {
			return nil, nil, errors.New("unexpected vrf output length")
		} else if len(entry.Commitment) != t.cs.HashSize() {
			return nil, nil, errors.New("unexpected commitment length")
		} else if i > 0 && bytes.Equal(sortedEntries[i-1].VrfOutput, entry.VrfOutput) {
			return nil, nil, errors.New("unable to insert same vrf output multiple times")
		}
	}

	// Load necessary tiles into memory. Add new entries. Create tiles.
	root, proof, err := t.getInsertionRoot(ver, entries)
	if err != nil {
		return nil, nil, err
	}
	insertEntries(t.cs, &root, sortedEntries, 0)
	rootHash := root.Hash(t.cs)
	tiles := splitIntoTiles(t.cs, ver+1, root)

	// Write tiles to database.
	data := make(map[string][]byte, len(tiles))
	for _, tile := range tiles {
		raw, err := tile.Marshal(t.cs)
		if err != nil {
			return nil, nil, err
		}
		data[tile.id.String()] = raw
	}
	if err := t.tx.BatchPut(data); err != nil {
		return nil, nil, err
	}

	return rootHash, proof, nil
}

// getInsertRoot returns the node to operate on for our insertion. It also
// returns the prior-version PrefixProof.
func (t *Tree) getInsertionRoot(ver uint64, entries []Entry) (node, *PrefixProof, error) {
	if ver == 0 {
		return &parentNode{left: emptyNode{}, right: emptyNode{}}, nil, nil
	}

	vrfOutputs := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		vrfOutputs = append(vrfOutputs, entry.VrfOutput)
	}

	b := newBatch(t.cs, t.tx)
	res, state := b.initialize(map[uint64][][]byte{ver: vrfOutputs})
	if err := b.search(state); err != nil {
		return nil, nil, err
	}
	root := res[0].root

	proof, commitments := runProofBuilder(t.cs, root, vrfOutputs)
	for _, commitment := range commitments {
		if commitment != nil {
			return nil, nil, errors.New("can not insert same vrf output twice")
		}
	}

	return root, &proof, nil
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
		indexed[i] = indexedVrfOutput{vrfOutput: vrfOutput, index: i}
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

func insertEntries(cs suites.CipherSuite, n *node, entries []Entry, depth int) {
	if len(entries) == 0 {
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
		if len(entries) == 1 {
			*n = leafNode{vrfOutput: entries[0].VrfOutput, commitment: entries[0].Commitment}
		} else {
			*n = &parentNode{left: emptyNode{}, right: emptyNode{}}
			insertEntries(cs, n, entries, depth)
		}

	case leafNode:
		if getBit(m.vrfOutput, depth) {
			*n = &parentNode{left: emptyNode{}, right: m}
		} else {
			*n = &parentNode{left: m, right: emptyNode{}}
		}
		insertEntries(cs, n, entries, depth)

	case *parentNode:
		m.hash, m.id = nil, nil
		split, _ := slices.BinarySearchFunc(entries, true, func(entry Entry, _ bool) int {
			if getBit(entry.VrfOutput, depth) {
				return 0
			}
			return -1
		})
		insertEntries(cs, &m.left, entries[:split], depth+1)
		insertEntries(cs, &m.right, entries[split:], depth+1)

	default:
		panic("unexpected node type found")
	}
}
