// Package prefix implements a Merkle prefix tree that supports proofs of
// inclusion and non-inclusion.
package prefix

import (
	"encoding/json"
	"errors"

	"github.com/JumpPrivacy/katie/db"
)

// SearchResult is the output from executing a search in the tree, containing a
// cryptographic proof of inclusion or non-inclusion.
type SearchResult struct {
	inner interface{}
}

// Inclusion returns true if this is a proof of inclusion and false if this
// is a proof of non-inclusion.
func (sr *SearchResult) Inclusion() bool {
	switch sr.inner.(type) {
	case nonInclusionParent:
		return false
	case nonInclusionLeaf:
		return false
	case inclusionProof:
		return true
	default:
		panic("unreachable")
	}
}

// Counter returns the value of the counter of an inclusion proof, or -1 for a
// non-inclusion proof.
func (sr *SearchResult) Counter() int {
	switch inner := sr.inner.(type) {
	case nonInclusionParent:
		return -1
	case nonInclusionLeaf:
		return -1
	case inclusionProof:
		return int(inner.counter)
	default:
		panic("unreachable")
	}
}

type searchResultSchema struct {
	Typ     string   `json:"type"`
	Proof   [][]byte `json:"proof"`
	Key     []byte   `json:"key,omitempty"`
	Counter *uint32  `json:"counter,omitempty"`
}

func (sr *SearchResult) MarshalJSON() ([]byte, error) {
	switch inner := sr.inner.(type) {
	case nonInclusionParent:
		return json.Marshal(searchResultSchema{
			Typ:   "non-inclusion-parent",
			Proof: inner.proof,
		})
	case nonInclusionLeaf:
		return json.Marshal(searchResultSchema{
			Typ:     "non-inclusion-leaf",
			Proof:   inner.proof,
			Key:     inner.key,
			Counter: &inner.counter,
		})
	case inclusionProof:
		return json.Marshal(searchResultSchema{
			Typ:     "inclusion",
			Proof:   inner.proof,
			Counter: &inner.counter,
		})
	default:
		panic("unreachable")
	}
}

func (sr *SearchResult) UnmarshalJSON(b []byte) error {
	val := searchResultSchema{}
	if err := json.Unmarshal(b, &val); err != nil {
		return err
	} else if val.Typ != "non-inclusion-parent" && val.Counter == nil {
		return errors.New("malformed search result")
	}

	switch val.Typ {
	case "non-inclusion-parent":
		sr.inner = nonInclusionParent{proof: val.Proof}
	case "non-inclusion-leaf":
		sr.inner = nonInclusionLeaf{proof: val.Proof, key: val.Key, counter: *val.Counter}
	case "inclusion":
		sr.inner = inclusionProof{proof: val.Proof, counter: *val.Counter}
	default:
		return errors.New("unable to parse search result")
	}

	return nil
}

// nonInclusionParent is a proof of non-inclusion based on showing a null link
// in a parent node where the search path would normally proceed.
type nonInclusionParent struct {
	proof [][]byte
}

// nonInclusionLeaf is a proof of non-inclusion based on showing a leaf node for
// a different key where the search path would normally proceed.
type nonInclusionLeaf struct {
	proof   [][]byte
	key     []byte
	counter uint32
}

// inclusionProof is a proof of inclusion.
type inclusionProof struct {
	proof   [][]byte
	counter uint32
}

// Tree is the high-level implementation of the Merkle prefix tree, backed by a
// connection to a persistent database.
type Tree struct {
	tx db.PrefixStore
}

// NewTree returns a new instance of a prefix tree.
func NewTree(tx db.PrefixStore) *Tree {
	return &Tree{tx: tx}
}

func (t *Tree) search(version uint64, key [32]byte) (*logEntry, error) {
	path := make([]interface{}, 0)

	ptr := version - 1
	offset := uint8(0)
	for {
		raw, err := t.tx.Get(ptr)
		if err != nil {
			return nil, err
		}
		entry, err := newLogEntry(raw)
		if err != nil {
			return nil, err
		}

		for {
			if len(entry.path) <= int(offset) {
				return &logEntry{entry.leaf, path}, nil
			} else if getBit(entry.leaf.key, int(offset)) == getBit(key, len(path)) {
				path = append(path, entry.path[offset])
				offset += 1
			} else {
				path = append(path, entry.rollup(ptr, offset+1))
				switch nd := entry.path[offset].(type) {
				case leafNode:
					return &logEntry{&nd, path}, nil
				case parentNode:
					ptr, offset = nd.ptr, nd.offset
				case emptyNode:
					return &logEntry{nil, path}, nil
				default:
					return nil, errors.New("unexpected log entry found")
				}
				break
			}
		}
	}
}

// Search executes a search for `key` in the requested version of the tree,
// returning either a proof of inclusion or proof of non-inclusion.
func (t *Tree) Search(version uint64, key []byte) (*SearchResult, error) {
	if version == 0 {
		return nil, errors.New("tree is empty")
	} else if len(key) != 32 {
		return nil, errors.New("key length must be 32 bytes")
	}
	key32 := [32]byte{}
	copy(key32[:], key)
	entry, err := t.search(version, key32)
	if err != nil {
		return nil, err
	}

	proof := entry.proof()
	if entry.leaf == nil {
		return &SearchResult{nonInclusionParent{proof: proof}}, nil
	} else if entry.leaf.key != key32 {
		return &SearchResult{nonInclusionLeaf{proof, entry.leaf.key[:], entry.leaf.ctr}}, nil
	}
	return &SearchResult{inclusionProof{proof, entry.leaf.ctr}}, nil
}

// Insert adds a new key to the tree or increments its counter if it already
// exists, and returns the new root and search result.
//
// The current tree version is given in `version`; after this method returns
// successfully, the tree may be used with `version+1`.
func (t *Tree) Insert(version uint64, key []byte) ([]byte, *SearchResult, error) {
	if len(key) != 32 {
		return nil, nil, errors.New("key length must be 32 bytes")
	}
	key32 := [32]byte{}
	copy(key32[:], key)

	var entry *logEntry
	if version == 0 {
		entry = &logEntry{&leafNode{key32, 0}, nil}
	} else {
		res, err := t.search(version, key32)
		if err != nil {
			return nil, nil, err
		}

		if res.leaf == nil {
			res.leaf = &leafNode{key32, 0}
		} else if res.leaf.key != key32 {
			for getBit(key32, len(res.path)) == getBit(res.leaf.key, len(res.path)) {
				res.path = append(res.path, emptyNode{})
			}
			res.path = append(res.path, *res.leaf)
			res.leaf = &leafNode{key32, 0}
		} else {
			res.leaf.ctr += 1
		}
		entry = res
	}

	raw, err := entry.Marshal()
	if err != nil {
		return nil, nil, err
	} else if err := t.tx.Put(version, raw); err != nil {
		return nil, nil, err
	}

	root := entry.root()
	sr := &SearchResult{inclusionProof{entry.proof(), entry.leaf.ctr}}
	return root[:], sr, nil
}
