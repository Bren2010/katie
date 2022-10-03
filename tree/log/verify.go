package log

import (
	"bytes"
	"errors"
	"sort"

	"github.com/Bren2010/katie/tree/log/math"
)

// simpleRootCalculator is an alternative implementation of the root-calculation
// logic in the log tree which we use to double-check things are implemented
// correctly.
type simpleRootCalculator struct {
	chain []*nodeData
}

func newSimpleRootCalculator() *simpleRootCalculator {
	return &simpleRootCalculator{chain: make([]*nodeData, 0)}
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
			value: treeHash(c.chain[i], acc),
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

func (c *simpleRootCalculator) Root() ([]byte, error) {
	if len(c.chain) == 0 {
		return nil, errors.New("empty chain")
	}

	// Find first non-null element of chain.
	var (
		rootPos int
		root    *nodeData
	)
	for i := 0; i < len(c.chain); i++ {
		if c.chain[i] != nil {
			rootPos = i
			root = c.chain[i]
			break
		}
	}
	if root == nil {
		return nil, errors.New("malformed chain")
	}

	// Fold the hashes above what we just found into one.
	for i := rootPos + 1; i < len(c.chain); i++ {
		if c.chain[i] != nil {
			root = &nodeData{
				leaf:  false,
				value: treeHash(c.chain[i], root),
			}
		}
	}

	return root.value, nil
}

// EvaluateInclusionProof returns the root that would result in the given proof
// being valid for the given value.
func EvaluateInclusionProof(x, n int, value []byte, proof [][]byte) ([]byte, error) {
	for _, elem := range proof {
		if len(elem) != 32 {
			return nil, errors.New("malformed proof")
		}
	}

	x = 2 * x
	path := math.Copath(x, n)
	if len(proof) != len(path) {
		return nil, errors.New("malformed proof")
	}

	acc := &nodeData{leaf: true, value: value}
	for i := 0; i < len(path); i++ {
		nd := &nodeData{leaf: math.IsLeaf(path[i]), value: proof[i]}

		var hash []byte
		if x < path[i] {
			hash = treeHash(acc, nd)
		} else {
			hash = treeHash(nd, acc)
		}

		acc = &nodeData{leaf: false, value: hash}
		x = path[i]
	}

	return acc.value, nil
}

// VerifyInclusionProof checks that `proof` is a valid inclusion proof for
// `value` at position `x` in a tree with the given root.
func VerifyInclusionProof(x, n int, value []byte, proof [][]byte, root []byte) error {
	cand, err := EvaluateInclusionProof(x, n, value, proof)
	if err != nil {
		return err
	} else if !bytes.Equal(root, cand) {
		return errors.New("root does not match proof")
	}
	return nil
}

// EvaluateBatchProof returns the root that would result in the given proof
// being valid for the given values.
func EvaluateBatchProof(x []int, n int, values [][]byte, proof [][]byte) ([]byte, error) {
	if len(x) != len(values) {
		return nil, errors.New("expected same number of indices and values")
	} else if !sort.IsSorted(sort.IntSlice(x)) {
		return nil, errors.New("input entries must be in sorted order")
	}
	for _, elem := range proof {
		if len(elem) != 32 {
			return nil, errors.New("malformed proof")
		}
	}

	copath := math.BatchCopath(x, n)
	if len(proof) != len(copath) {
		return nil, errors.New("malformed proof")
	}

	calc := newSimpleRootCalculator()
	i, j := 0, 0
	for i < len(x) && j < len(copath) {
		if 2*x[i] < copath[j] {
			calc.Insert(0, values[i])
			i++
		} else {
			calc.Insert(math.Level(copath[j]), proof[j])
			j++
		}
	}
	for i < len(x) {
		calc.Insert(0, values[i])
		i++
	}
	for j < len(copath) {
		calc.Insert(math.Level(copath[j]), proof[j])
		j++
	}

	return calc.Root()
}

// VerifyBatchProof checks that `proof` is a valid batch inclusion proof for the
// given values in a tree with the given root.
func VerifyBatchProof(x []int, n int, values [][]byte, proof [][]byte, root []byte) error {
	cand, err := EvaluateBatchProof(x, n, values, proof)
	if err != nil {
		return err
	} else if !bytes.Equal(root, cand) {
		return errors.New("root does not match proof")
	}
	return nil
}

// VerifyConsistencyProof checks that `proof` is a valid consistency proof
// between `mRoot` and `nRoot` where `m` < `n`.
func VerifyConsistencyProof(m, n int, proof [][]byte, mRoot, nRoot []byte) error {
	for _, elem := range proof {
		if len(elem) != 32 {
			return errors.New("malformed proof")
		}
	}

	ids := math.ConsistencyProof(m, n)
	calc := newSimpleRootCalculator()

	if len(proof) != len(ids) {
		return errors.New("malformed proof")
	}

	// Step 1: Verify that the consistency proof aligns with mRoot.
	path := math.FullSubtrees(math.Root(m), m)
	if len(path) == 1 {
		// m is a power of two so we don't need to verify anything.
		calc.Insert(math.Level(math.Root(m)), mRoot)
	} else {
		for i := 0; i < len(path); i++ {
			if ids[i] != path[i] {
				return errors.New("unexpected error")
			}
			calc.Insert(math.Level(path[i]), proof[i])
		}
		if root, err := calc.Root(); err != nil {
			return err
		} else if !bytes.Equal(mRoot, root) {
			return errors.New("first root does not match proof")
		}
	}

	// Step 2: Verify that the consistency proof aligns with nRoot.
	i := len(path)
	if i == 1 {
		i = 0
	}
	for ; i < len(ids); i++ {
		calc.Insert(math.Level(ids[i]), proof[i])
	}
	if root, err := calc.Root(); err != nil {
		return err
	} else if !bytes.Equal(nRoot, root) {
		return errors.New("second root does not match proof")
	}
	return nil
}
