// Package prefix implements a Merkle prefix tree.
package prefix

type SearchResult interface{}

// nonInclusionParent is a proof of non-inclusion based on showing a null link
// in a parent node where the search path would normally proceed.
type nonInclusionParent struct {
	proof [][]byte
}

// nonInclusionLeaf is a proof of non-inclusion based on showing a leaf node for
// a different key where the search path would normally proceed.
type nonInclusionLeaf struct {
	proof  [][]byte
	suffix []byte
	value  []byte
}

// inclusionLeaf is a proof of inclusion containing the leaf value.
type inclusionLeaf struct {
	proof [][]byte
	value []byte
}
