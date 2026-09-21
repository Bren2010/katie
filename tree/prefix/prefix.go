// Package prefix implements a Prefix Tree that supports versioning and batch
// searches, insertions, and deletions.
package prefix

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
)

// PrefixSearch represents a search for multiple VRF outputs in a single version
// of the Prefix Tree.
type PrefixSearch struct {
	Version    uint64   // The version of the tree to search.
	VrfOutputs [][]byte // The VRF outputs to search for.
}

// SearchResult contains the result of searching a single version of the Prefix
// Tree for multiple VRF outputs.
type SearchResult struct {
	Proof PrefixProof
	// Commitments contains the commitment corresponding to each VRF output in
	// the order requested, or nil if the VRF output doesn't exist.
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

// Search takes as input a slice, where each element identifies a version of the
// tree to search and one or more VRF outputs to search for in that version. It
// returns a same-sized slice with the result of each search in the same order.
func (t *Tree) Search(searches []PrefixSearch) ([]SearchResult, error) {
	combined := make(map[uint64][][]byte)
	for _, search := range searches {
		if len(search.VrfOutputs) == 0 {
			return nil, errors.New("no vrf outputs requested for search")
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
		proof, commitments := runProofBuilder(t.cs, tile.root, sortVrfOutputs(search.VrfOutputs))
		out[i] = SearchResult{proof, commitments}
	}
	return out, nil
}

// Entry contains a new entry to be added to the tree.
type Entry struct {
	VrfOutput, Commitment []byte
}

// MutateResult is the result of a single mutation to the tree.
type MutateResult struct {
	Root        []byte      // The new root value of the tree.
	Proof       PrefixProof // A batch proof from just before the mutation was applied.
	Commitments [][]byte    // The commitment of each removed leaf.
	Leaves      []Entry     // Leaves that were moved as a result of the mutation.
}

// Mutate adds and removes the requested entries from the tree and increments
// the version counter. The current tree version is given in `ver`, which is 0
// if the tree is empty. After this, version `ver+1` of the tree will exist.
//
// The inputs `add` and `remove` must not both be empty, must not have any
// duplicate VRF outputs (although a VRF output in one may also be in the
// other), and must be sorted by VRF output.
func (t *Tree) Mutate(ver uint64, add []Entry, remove [][]byte) (*MutateResult, error) {
	// Verify that the entries to add and remove are well formed.
	if len(add) == 0 && len(remove) == 0 {
		return nil, errors.New("no mutations requested")
	}

	vrfOutputs := make([][]byte, 0, len(add)+len(remove))
	for i, entry := range add {
		if len(entry.VrfOutput) != t.cs.HashSize() {
			return nil, errors.New("unexpected vrf output length")
		} else if len(entry.Commitment) != t.cs.HashSize() {
			return nil, errors.New("unexpected commitment length")
		} else if i > 0 && bytes.Compare(add[i-1].VrfOutput, entry.VrfOutput) != -1 {
			return nil, errors.New("duplicate or unsorted vrf output given")
		}
		vrfOutputs = append(vrfOutputs, entry.VrfOutput)
	}
	for i, vrfOutput := range remove {
		if len(vrfOutput) != t.cs.HashSize() {
			return nil, errors.New("unexpected vrf output length")
		} else if i > 0 && bytes.Compare(remove[i-1], vrfOutput) != -1 {
			return nil, errors.New("duplicate or unsorted vrf output given")
		}
		vrfOutputs = append(vrfOutputs, vrfOutput)
	}

	// Load necessary tiles into memory and mutate as requested.
	root, err := t.getMutationRoot(ver, vrfOutputs)
	if err != nil {
		return nil, err
	}
	newRoot, leaves := addRemoveEntries(t.cs, root, add, remove, 0)

	// Compute the proof from before the mutation. Check that the commitments
	// are as expected.
	merged := mergeVrfOutputs(add, remove, leaves)
	proof, commitments := runProofBuilder(t.cs, root, merged)
	for i, m := range merged {
		if m.index < len(add) {
			valid := commitments[m.index] == nil || (i+1 < len(merged) && bytes.Equal(m.vrfOutput, merged[i+1].vrfOutput))
			if !valid {
				return nil, errors.New("can not insert same vrf output twice")
			}
		} else if m.index < len(add)+len(remove) {
			if commitments[m.index] == nil {
				return nil, errors.New("can not remove vrf output that does not exist")
			}
		} else {
			if commitments[m.index] == nil {
				panic("unexpected error occurred")
			}
		}
	}

	// Create the new tiles and write them to the database.
	tiles := splitIntoTiles(t.cs, ver+1, newRoot)
	for _, tile := range tiles {
		raw, err := tile.Marshal(t.cs)
		if err != nil {
			return nil, err
		}
		t.tx.Put(tile.id.String(), raw)
	}

	return &MutateResult{
		Root:        newRoot.Hash(t.cs),
		Proof:       proof,
		Commitments: commitments[len(add) : len(add)+len(remove)],
		Leaves:      leaves,
	}, nil
}

func (t *Tree) getMutationRoot(ver uint64, vrfOutputs [][]byte) (node, error) {
	if ver == 0 {
		return emptyNode{}, nil
	}
	b := newBatch(t.cs, t.tx)
	res, state := b.initialize(map[uint64][][]byte{ver: vrfOutputs})
	if err := b.search(state); err != nil {
		return nil, err
	}
	return res[ver].root, nil
}
