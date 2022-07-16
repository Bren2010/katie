package prefix

import (
	"bytes"
	"errors"
)

func verifyProof(root, key, value []byte, proof [][]byte) error {
	for i := 0; i < len(proof); i++ {
		n := len(proof) - i - 1
		b := key[n/8] >> (7 - (n % 8)) & 1

		if b == 0 {
			value = parentHash(value, proof[n])
		} else {
			value = parentHash(proof[n], value)
		}
	}

	if !bytes.Equal(root, value) {
		return errors.New("root does not equal expected value")
	}
	return nil
}

// verifyInclusionProof checks that `res`, which the output of search, is a
// valid inclusion proof for `key` in a tree with the given root.
func verifyInclusionProof(root, key []byte, res inclusionProof) error {
	n := len(res.proof)
	if n == 0 || n%4 != 0 {
		return errors.New("inclusion proof is not correctly formed")
	}

	leaf := leafHash(buildSuffix(key, n/8, n%8 == 0))
	return verifyProof(root, key, leaf, res.proof)
}

// verifyNonInclusionLeafProof checks that `res`, which the output of search, is
// a valid non-inclusion proof for `key` in a tree with the given root.
func verifyNonInclusionLeafProof(root, key []byte, res nonInclusionLeaf) error {
	n := len(res.proof)
	if n == 0 || n%4 != 0 || (n/8)+len(res.suffix) != 32 {
		return errors.New("non-inclusion-leaf proof is not correctly formed")
	} else if n%8 == 4 && res.suffix[0]>>4 != 0 {
		return errors.New("non-inclusion-leaf proof is not correctly formed")
	}

	keysMatch := bytes.Equal(
		buildSuffix(key, n/8, n%8 == 0),
		res.suffix,
	)
	if keysMatch {
		return errors.New("non-inclusion-leaf proof given but keys match")
	}
	return verifyProof(root, key, leafHash(res.suffix), res.proof)
}

// verifyNonInclusionParentProof checks that `res`, which the output of search,
// is a valid non-inclusion proof for `key` in a tree with the given root.
func verifyNonInclusionParentProof(root, key []byte, res nonInclusionParent) error {
	n := len(res.proof)
	if n == 0 {
		return errors.New("non-inclusion-parent proof is not correctly formed")
	}
	return verifyProof(root, key, make([]byte, 32), res.proof)
}

// Verify takes a search result `res` as input, which was returned by searching
// for `key` in a tree with root `root`, and returns an error if it's invalid.
func Verify(root, key []byte, res SearchResult) error {
	switch res := res.(type) {
	case inclusionProof:
		return verifyInclusionProof(root, key, res)
	case nonInclusionLeaf:
		return verifyNonInclusionLeafProof(root, key, res)
	case nonInclusionParent:
		return verifyNonInclusionParentProof(root, key, res)
	default:
		return errors.New("unknown proof type")
	}
}
