// Package prefix implements a Merkle prefix tree that supports proofs of
// inclusion and non-inclusion.
package prefix

import (
	"encoding/hex"
	"fmt"

	"github.com/JumpPrivacy/katie/db"
)

// SearchResult is the output from executing a search in the tree, containing a
// cryptographic proof of inclusion or non-inclusion.
type SearchResult interface {
	// Inclusion returns true if this is a proof of inclusion and false if this
	// is a proof of non-inclusion.
	Inclusion() bool
}

// nonInclusionParent is a proof of non-inclusion based on showing a null link
// in a parent node where the search path would normally proceed.
type nonInclusionParent struct {
	proof [][]byte
}

func (p nonInclusionParent) Inclusion() bool { return false }

// nonInclusionLeaf is a proof of non-inclusion based on showing a leaf node for
// a different key where the search path would normally proceed.
type nonInclusionLeaf struct {
	proof  [][]byte
	suffix []byte
}

func (p nonInclusionLeaf) Inclusion() bool { return false }

// inclusionProof is a proof of inclusion.
type inclusionProof struct {
	proof [][]byte
}

func (p inclusionProof) Inclusion() bool { return true }

// Tree is the high-level implementation of the Merkle prefix tree, backed by a
// connection to a persistent database.
type Tree struct {
	tx     db.Tx
	height int
}

// NewTree returns a new instance of a prefix tree with the given database
// transaction and where `height` is the last known max height of the tree.
func NewTree(tx db.Tx, height int) *Tree {
	return &Tree{tx: tx, height: height}
}

// fetch loads the search path for `key` into a chunkSet.
func (t *Tree) fetch(key []byte) (map[string][]byte, error) {
	fullKey := hex.EncodeToString(key)

	ids := []string{"root"}
	for i := 1; i < t.height; i++ {
		ids = append(ids, fullKey[0:i])
	}
	return t.tx.BatchGet(ids)
}

// Search executes a search for `key` in the tree, returning either a proof of
// inclusion or proof of non-inclusion.
func (t *Tree) Search(key []byte) (SearchResult, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key length must be 32 bytes")
	}

	data, err := t.fetch(key)
	if err != nil {
		return nil, err
	}
	chunkSet, err := newChunkSet(data)
	if err != nil {
		return nil, err
	}
	return chunkSet.search(key)
}

// Insert inserts `key` and returns the new root hash and max height of the
// tree.
func (t *Tree) Insert(key []byte) ([]byte, int, error) {
	if len(key) != 32 {
		return nil, 0, fmt.Errorf("key length must be 32 bytes")
	}

	data, err := t.fetch(key)
	if err != nil {
		return nil, 0, err
	}
	chunkSet, err := newChunkSet(data)
	if err != nil {
		return nil, 0, err
	}
	root, height, err := chunkSet.insert(key)
	if err != nil {
		return nil, 0, err
	}
	if err := t.tx.BatchPut(chunkSet.marshal()); err != nil {
		return nil, 0, err
	}

	if height > t.height {
		t.height = height
	}
	return root, t.height, nil
}
