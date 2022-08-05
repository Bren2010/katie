package prefix

import (
	"errors"
)

func verifyProof(root, key, value [32]byte, proof [][]byte) error {
	for i := 0; i < len(proof); i++ {
		n := len(proof) - i - 1
		b := key[n/8] >> (7 - (n % 8)) & 1

		if len(proof[n]) != 32 {
			return errors.New("proof is malformed")
		}
		proof32 := [32]byte{}
		copy(proof32[:], proof[n])
		if b == 0 {
			value = parentHash(value, proof32)
		} else {
			value = parentHash(proof32, value)
		}
	}

	if root != value {
		return errors.New("root does not equal expected value")
	}
	return nil
}

// verifyInclusionProof checks that `res`, which the output of search, is a
// valid inclusion proof for `key` in a tree with the given root.
func verifyInclusionProof(root, key [32]byte, res inclusionProof) error {
	leaf := leafHash(&leafNode{key, res.counter})
	return verifyProof(root, key, leaf, res.proof)
}

// verifyNonInclusionLeafProof checks that `res`, which the output of search, is
// a valid non-inclusion proof for `key` in a tree with the given root.
func verifyNonInclusionLeafProof(root, key [32]byte, res nonInclusionLeaf) error {
	if len(res.key) != 32 {
		return errors.New("proof is malformed")
	}
	key32 := [32]byte{}
	copy(key32[:], res.key)

	if key == key32 {
		return errors.New("non-inclusion-leaf proof given but keys match")
	}
	return verifyProof(root, key, leafHash(&leafNode{key32, res.counter}), res.proof)
}

// verifyNonInclusionParentProof checks that `res`, which the output of search,
// is a valid non-inclusion proof for `key` in a tree with the given root.
func verifyNonInclusionParentProof(root, key [32]byte, res nonInclusionParent) error {
	n := len(res.proof)
	if n == 0 {
		return errors.New("non-inclusion-parent proof is not correctly formed")
	}
	return verifyProof(root, key, [32]byte{}, res.proof)
}

// Verify takes a search result `res` as input, which was returned by searching
// for `key` in a tree with root `root`, and returns an error if it's invalid.
func Verify(root, key []byte, res *SearchResult) error {
	if len(root) != 32 {
		return errors.New("root length must be 32 bytes")
	} else if len(key) != 32 {
		return errors.New("key length must be 32 bytes")
	}
	root32, key32 := [32]byte{}, [32]byte{}
	copy(root32[:], root)
	copy(key32[:], key)

	switch inner := res.inner.(type) {
	case inclusionProof:
		return verifyInclusionProof(root32, key32, inner)
	case nonInclusionLeaf:
		return verifyNonInclusionLeafProof(root32, key32, inner)
	case nonInclusionParent:
		return verifyNonInclusionParentProof(root32, key32, inner)
	default:
		return errors.New("unknown proof type")
	}
}
