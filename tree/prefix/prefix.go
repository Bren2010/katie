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

// Search takes as input a map from each version of the tree to search, to the
// list of VRF outputs to search for in that version of the tree. It returns a
// map from the searched versions of the tree to a batch PrefixProof.
func (t *Tree) Search(searches map[uint64][][]byte) (map[uint64]PrefixProof, error) {
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

	out := make(map[uint64]PrefixProof, len(searches))
	for _, tile := range res {
		proof := PrefixProof{}
		vrfOutputs := searches[tile.id.ver] // This is sorted already by search.
		buildProof(t.cs, &proof, tile.root, vrfOutputs, 0)
		out[tile.id.ver] = proof
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
	slices.SortFunc(entries, func(a, b Entry) int {
		return bytes.Compare(a.VrfOutput, b.VrfOutput)
	})
	for i, entry := range entries {
		if len(entry.VrfOutput) != t.cs.HashSize() {
			return nil, nil, errors.New("unexpected vrf output length")
		} else if len(entry.Commitment) != t.cs.HashSize() {
			return nil, nil, errors.New("unexpected commitment length")
		} else if i > 0 && bytes.Equal(entries[i-1].VrfOutput, entry.VrfOutput) {
			return nil, nil, errors.New("unable to insert same vrf output multiple times")
		}
	}

	// Load necessary tiles into memory. Add new entries. Create tiles.
	root, proof, err := t.getInsertionRoot(ver, entries)
	if err != nil {
		return nil, nil, err
	}
	insertEntries(t.cs, &root, entries, 0)
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

	proof := &PrefixProof{}
	buildProof(t.cs, proof, root, vrfOutputs, 0)
	return root, proof, nil
}

func buildProof(cs suites.CipherSuite, proof *PrefixProof, n node, vrfOutputs [][]byte, depth int) {
	if len(vrfOutputs) == 0 {
		proof.Elements = append(proof.Elements, n.Hash(cs))
		return
	}

	switch n := n.(type) {
	case emptyNode:
		for range vrfOutputs {
			proof.Results = append(proof.Results, nonInclusionParentProof{depth: depth})
		}

	case leafNode:
		for _, vrfOutput := range vrfOutputs {
			if bytes.Equal(vrfOutput, n.vrfOutput) {
				proof.Results = append(proof.Results, inclusionProof{commitment: n.commitment, depth: depth})
			} else {
				proof.Results = append(proof.Results, nonInclusionLeafProof{leaf: n, depth: depth})
			}
		}

	case *parentNode:
		split, _ := slices.BinarySearchFunc(vrfOutputs, true, func(s []byte, _ bool) int {
			if getBit(s, depth) {
				return 0
			}
			return -1
		})
		buildProof(cs, proof, n.left, vrfOutputs[:split], depth+1)
		buildProof(cs, proof, n.right, vrfOutputs[split:], depth+1)

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
		*n = &parentNode{left: emptyNode{}, right: emptyNode{}}
		insertEntries(cs, n, entries, depth)

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
