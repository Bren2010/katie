package log

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/log/math"
)

// simpleRootCalculator is an alternative implementation of the root-calculation
// logic in the log tree which we use to double-check things are implemented
// correctly.
type simpleRootCalculator struct {
	cs    suites.CipherSuite
	chain []*nodeData
}

func newSimpleRootCalculator(cs suites.CipherSuite) *simpleRootCalculator {
	return &simpleRootCalculator{cs: cs, chain: make([]*nodeData, 0)}
}

func (c *simpleRootCalculator) Add(leaf []byte) {
	c.Insert(0, leaf)
}

func (c *simpleRootCalculator) Insert(level int, value []byte) {
	for len(c.chain) < level+1 {
		c.chain = append(c.chain, nil)
	}

	acc := &nodeData{
		leaf:  level == 0,
		value: value,
	}

	i := level
	for i < len(c.chain) && c.chain[i] != nil {
		acc = &nodeData{
			leaf:  false,
			value: treeHash(c.cs, c.chain[i], acc),
		}
		c.chain[i] = nil
		i++
	}
	if i == len(c.chain) {
		c.chain = append(c.chain, acc)
	} else {
		c.chain[i] = acc
	}
}

func (c *simpleRootCalculator) Root() []byte {
	if len(c.chain) == 0 {
		panic("empty chain")
	}

	// Find first non-null element of chain.
	var (
		rootPos int
		root    *nodeData
	)
	for i := range len(c.chain) {
		if c.chain[i] != nil {
			rootPos = i
			root = c.chain[i]
			break
		}
	}
	if root == nil {
		panic("malformed chain")
	}

	// Fold the hashes above what we just found into one.
	for i := rootPos + 1; i < len(c.chain); i++ {
		if c.chain[i] != nil {
			root = &nodeData{
				leaf:  false,
				value: treeHash(c.cs, c.chain[i], root),
			}
		}
	}

	return root.value
}

// EvaluateInclusionProof returns the root that would result in the given proof
// being valid for the given value.
func EvaluateInclusionProof(cs suites.CipherSuite, x, n uint64, value []byte, proof [][]byte) ([]byte, error) {
	if len(value) != cs.HashSize() {
		return nil, errors.New("value is unexpected size")
	}
	for _, elem := range proof {
		if len(elem) != cs.HashSize() {
			return nil, errors.New("malformed proof")
		}
	}

	x = 2 * x
	path := math.Copath(x, n)
	if len(proof) != len(path) {
		return nil, errors.New("malformed proof")
	}

	acc := &nodeData{leaf: true, value: value}
	for i := range len(path) {
		nd := &nodeData{leaf: math.IsLeaf(path[i]), value: proof[i]}

		var hash []byte
		if x < path[i] {
			hash = treeHash(cs, acc, nd)
		} else {
			hash = treeHash(cs, nd, acc)
		}

		acc = &nodeData{leaf: false, value: hash}
		x = path[i]
	}

	return acc.value, nil
}

// VerifyInclusionProof checks that `proof` is a valid inclusion proof for
// `value` at position `x` in a tree with the given root.
func VerifyInclusionProof(cs suites.CipherSuite, x, n uint64, value []byte, proof [][]byte, root []byte) error {
	cand, err := EvaluateInclusionProof(cs, x, n, value, proof)
	if err != nil {
		return err
	} else if !bytes.Equal(root, cand) {
		return errors.New("root does not match proof")
	}
	return nil
}

// EvaluateBatchProof returns the root that would result in the given proof
// being valid for the given values.
func EvaluateBatchProof(cs suites.CipherSuite, x []uint64, n uint64, values [][]byte, proof [][]byte) ([]byte, error) {
	if len(x) != len(values) {
		return nil, errors.New("expected same number of indices and values")
	} else if !slices.IsSorted(x) {
		return nil, errors.New("input entries must be in sorted order")
	}
	for _, value := range values {
		if len(value) != cs.HashSize() {
			return nil, errors.New("value is unexpected size")
		}
	}
	for _, elem := range proof {
		if len(elem) != cs.HashSize() {
			return nil, errors.New("malformed proof")
		}
	}

	copath := math.BatchCopath(x, n)
	if len(proof) != len(copath) {
		return nil, errors.New("malformed proof")
	}

	calc := newSimpleRootCalculator(cs)
	i, j := 0, 0
	for i < len(x) && j < len(copath) {
		if 2*x[i] < copath[j] {
			calc.Insert(0, values[i])
			i++
		} else {
			calc.Insert(int(math.Level(copath[j])), proof[j])
			j++
		}
	}
	for i < len(x) {
		calc.Insert(0, values[i])
		i++
	}
	for j < len(copath) {
		calc.Insert(int(math.Level(copath[j])), proof[j])
		j++
	}

	return calc.Root(), nil
}

// VerifyBatchProof checks that `proof` is a valid batch inclusion proof for the
// given values in a tree with the given root.
func VerifyBatchProof(cs suites.CipherSuite, x []uint64, n uint64, values [][]byte, proof [][]byte, root []byte) error {
	cand, err := EvaluateBatchProof(cs, x, n, values, proof)
	if err != nil {
		return err
	} else if !bytes.Equal(root, cand) {
		return errors.New("root does not match proof")
	}
	return nil
}

// VerifyConsistencyProof checks that `proof` is a valid consistency proof
// between `mRoot` and `nRoot` where `m` < `n`.
func VerifyConsistencyProof(cs suites.CipherSuite, m, n uint64, proof [][]byte, mRoot, nRoot []byte) error {
	for _, elem := range proof {
		if len(elem) != cs.HashSize() {
			return errors.New("malformed proof")
		}
	}

	ids := math.ConsistencyProof(m, n)
	calc := newSimpleRootCalculator(cs)

	if len(proof) != len(ids) {
		return errors.New("malformed proof")
	}

	// Step 1: Verify that the consistency proof aligns with mRoot.
	path := math.FullSubtrees(math.Root(m), m)
	if len(path) == 1 {
		// m is a power of two so we don't need to verify anything.
		calc.Insert(int(math.Level(math.Root(m))), mRoot)
	} else {
		for i := 0; i < len(path); i++ {
			if ids[i] != path[i] {
				return errors.New("unexpected error")
			}
			calc.Insert(int(math.Level(path[i])), proof[i])
		}
		if !bytes.Equal(mRoot, calc.Root()) {
			return errors.New("first root does not match proof")
		}
	}

	// Step 2: Verify that the consistency proof aligns with nRoot.
	i := len(path)
	if i == 1 {
		i = 0
	}
	for ; i < len(ids); i++ {
		calc.Insert(int(math.Level(ids[i])), proof[i])
	}
	if !bytes.Equal(nRoot, calc.Root()) {
		return errors.New("second root does not match proof")
	}
	return nil
}
