// Package prefix implements a Prefix Tree that supports versioning and batch
// searches and insertions.
package prefix

import (
	"bytes"
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
