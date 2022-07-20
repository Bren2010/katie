package accumulator

import (
	"bytes"
	"fmt"

	"github.com/JumpPrivacy/katie/db"
	"github.com/JumpPrivacy/katie/tree/log/simplelog"
)

// SearchResult is the output from executing a search in the tree, containing a
// cryptographic proof of inclusion or exclusion.
type SearchResult struct {
	inclusion  bool
	searchPath [][]byte
	proof      [][]byte
}

// Tree is a read-only view of an accumulator.
type Tree struct {
	n     int             // The size of the log.
	tx    db.KvStore      // Database connection.
	inner *simplelog.Tree // Log of tree nodes.
}

func NewTree(n int, tx db.KvStore) *Tree {
	return &Tree{
		n:     n,
		tx:    tx,
		inner: simplelog.NewTree(tx),
	}
}

// Search executes a search for `key` in the tree and returns a proof of
// inclusion or exclusion.
func (t *Tree) Search(key []byte) (*SearchResult, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid size for search key: %v", len(key))
	}

	found := false
	pos := []int{0}
	path := make([][]byte, 0)
	for {
		k := fmt.Sprintf("t%v", pos[len(pos)-1])

		res, err := t.tx.BatchGet([]string{k})
		if err != nil {
			return nil, err
		}
		raw, ok := res[k]
		if !ok {
			return nil, fmt.Errorf("expected node was not found")
		}
		leaf, err := parseLeaf(raw)
		if err != nil {
			return nil, err
		}

		path = append(path, raw)

		cmp := bytes.Compare(key, leaf.value)
		if cmp == -1 {
			if leaf.left == 0 || leaf.left >= t.n {
				break
			} else {
				pos = append(pos, leaf.left)
			}
		} else if cmp == 0 {
			found = true
			break
		} else if cmp == 1 {
			if leaf.right == 0 || leaf.right >= t.n {
				break
			} else {
				pos = append(pos, leaf.right)
			}
		}
	}

	proof, err := t.inner.GetBatch(pos, t.n)
	if err != nil {
		return nil, err
	}
	return &SearchResult{
		inclusion:  found,
		searchPath: path,
		proof:      proof,
	}, nil
}

// GetConsistencyProof returns a consistency proof between the current version
// of this accumulator and a previous one that had `m` nodes.
func (t *Tree) GetConsistencyProof(m int) ([][]byte, error) {
	return t.inner.GetConsistencyProof(m, t.n)
}
