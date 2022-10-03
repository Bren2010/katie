package prefix

import (
	"bytes"
	"errors"
)

func evaluateProof(key, value [32]byte, proof [][]byte) ([]byte, error) {
	for i := 0; i < len(proof); i++ {
		n := len(proof) - i - 1
		b := key[n/8] >> (7 - (n % 8)) & 1

		if len(proof[n]) != 32 {
			return nil, errors.New("proof is malformed")
		}
		proof32 := [32]byte{}
		copy(proof32[:], proof[n])
		if b == 0 {
			value = parentHash(value, proof32)
		} else {
			value = parentHash(proof32, value)
		}
	}

	return value[:], nil
}

// evaluateInclusionProof checks that `res`, which the output of search, is a
// valid inclusion proof for `key`.
func evaluateInclusionProof(key [32]byte, res inclusionProof) ([]byte, error) {
	leaf := leafHash(&leafNode{key, res.counter})
	return evaluateProof(key, leaf, res.proof)
}

// evaluateNonInclusionLeafProof checks that `res`, which the output of search,
// is a valid non-inclusion proof for `key`.
func evaluateNonInclusionLeafProof(key [32]byte, res nonInclusionLeaf) ([]byte, error) {
	if len(res.key) != 32 {
		return nil, errors.New("proof is malformed")
	}
	key32 := [32]byte{}
	copy(key32[:], res.key)

	if key == key32 {
		return nil, errors.New("non-inclusion-leaf proof given but keys match")
	}
	return evaluateProof(key, leafHash(&leafNode{key32, res.counter}), res.proof)
}

// evaluateNonInclusionParentProof checks that `res`, which the output of
// search, is a valid non-inclusion proof for `key`.
func evaluateNonInclusionParentProof(key [32]byte, res nonInclusionParent) ([]byte, error) {
	n := len(res.proof)
	if n == 0 {
		return nil, errors.New("non-inclusion-parent proof is not correctly formed")
	}
	return evaluateProof(key, [32]byte{}, res.proof)
}

// Evaluate takes a search result `res` as input, which was returned by
// searching for `key`, and returns the root that would make the proof valid.
func Evaluate(key []byte, res *SearchResult) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key length must be 32 bytes")
	}
	key32 := [32]byte{}
	copy(key32[:], key)

	switch inner := res.inner.(type) {
	case inclusionProof:
		return evaluateInclusionProof(key32, inner)
	case nonInclusionLeaf:
		return evaluateNonInclusionLeafProof(key32, inner)
	case nonInclusionParent:
		return evaluateNonInclusionParentProof(key32, inner)
	default:
		return nil, errors.New("unknown proof type")
	}
}

// Verify takes a search result `res` as input, which was returned by searching
// for `key` in a tree with root `root`, and returns an error if it's invalid.
func Verify(root, key []byte, res *SearchResult) error {
	if len(root) != 32 {
		return errors.New("root length must be 32 bytes")
	}
	cand, err := Evaluate(key, res)
	if err != nil {
		return err
	} else if !bytes.Equal(root, cand) {
		return errors.New("root does not match proof")
	}
	return nil
}
