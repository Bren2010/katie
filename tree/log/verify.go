package log

import (
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

// Verifier is a stateful verifier for inclusion and consistency proofs from a
// Log Tree.
type Verifier struct {
	cs suites.CipherSuite

	prev     *uint64 // Previously observed tree size, or nil if none.
	frontier [][]byte
}

func NewVerifier(cs suites.CipherSuite) *Verifier {
	return &Verifier{cs: cs}
}

func NewVerifierFromState(cs suites.CipherSuite, prev uint64, frontier [][]byte) (*Verifier, error) {
	if prev == 0 || prev > math.MaxTreeSize {
		return nil, errors.New("invalid value for previous tree size")
	}
	fullSubtrees := math.FullSubtrees(math.Root(prev), prev)
	if len(frontier) != len(fullSubtrees) {
		return nil, errors.New("frontier has unexpected length")
	}
	for _, val := range frontier {
		if len(val) != cs.HashSize() {
			return nil, errors.New("hash has wrong size")
		}
	}

	// Create the "padded" frontier by reversing the order and adding gaps for
	// missing levels, as expected by simpleRootCalculator.
	paddedFrontier := make([][]byte, math.Level(fullSubtrees[0])+1)
	for i, x := range fullSubtrees {
		paddedFrontier[math.Level(x)] = frontier[i]
	}

	return &Verifier{cs: cs, prev: &prev, frontier: paddedFrontier}, nil
}

// Previous returns the previously observed tree size.
func (v *Verifier) Previous() *uint64 { return v.prev }

// Frontier returns the retained frontier of the tree.
func (v *Verifier) Frontier() [][]byte {
	if len(v.frontier) == 0 {
		return nil
	}

	out := make([][]byte, 0)
	for _, val := range v.frontier {
		if val != nil {
			out = append(out, val)
		}
	}
	slices.Reverse(out)

	return out
}

// Evaluate returns the root that would result in `proof` being valid.
func (v *Verifier) Evaluate(entries []uint64, n uint64, values [][]byte, proof [][]byte) ([]byte, error) {
	if n == 0 || n > math.MaxTreeSize {
		return nil, errors.New("invalid value for current tree size")
	} else if len(entries) != len(values) {
		return nil, errors.New("number of leaves must equal number of leaf values")
	} else if !slices.IsSorted(entries) {
		return nil, errors.New("leaves must be provided in sorted order")
	}
	for i, x := range entries {
		if x >= n {
			return nil, errors.New("leaf is beyond right edge of tree")
		} else if i > 0 && entries[i-1] == x {
			return nil, errors.New("duplicate leaf index found")
		}
	}
	for _, val := range values {
		if len(val) != v.cs.HashSize() {
			return nil, errors.New("value is unexpected size")
		}
	}
	for _, elem := range proof {
		if len(elem) != v.cs.HashSize() {
			return nil, errors.New("malformed proof")
		}
	}
	copath := math.BatchCopath(entries, n, v.prev)
	if len(proof) != len(copath) {
		return nil, errors.New("malformed proof")
	}

	// ???
}

// // EvaluateProof returns the root that would result in `proof“ being valid for
// // the given values.
// func EvaluateBatchProof(cs suites.CipherSuite, x []uint64, n uint64, m *uint64, values [][]byte, proof [][]byte) ([]byte, error) {
// 	if len(x) != len(values) {
// 		return nil, errors.New("expected same number of indices and values")
// 	} else if !slices.IsSorted(x) {
// 		return nil, errors.New("input entries must be in sorted order")
// 	}
// 	for _, value := range values {
// 		if len(value) != cs.HashSize() {
// 			return nil, errors.New("value is unexpected size")
// 		}
// 	}
// 	for _, elem := range proof {
// 		if len(elem) != cs.HashSize() {
// 			return nil, errors.New("malformed proof")
// 		}
// 	}

// 	copath := math.BatchCopath(x, n)
// 	if len(proof) != len(copath) {
// 		return nil, errors.New("malformed proof")
// 	}

// 	calc := newSimpleRootCalculator(cs)
// 	i, j := 0, 0
// 	for i < len(x) && j < len(copath) {
// 		if 2*x[i] < copath[j] {
// 			calc.Insert(0, values[i])
// 			i++
// 		} else {
// 			calc.Insert(int(math.Level(copath[j])), proof[j])
// 			j++
// 		}
// 	}
// 	for i < len(x) {
// 		calc.Insert(0, values[i])
// 		i++
// 	}
// 	for j < len(copath) {
// 		calc.Insert(int(math.Level(copath[j])), proof[j])
// 		j++
// 	}

// 	return calc.Root(), nil
// }

// // VerifyProof checks that `proof` is a valid batch inclusion proof for the
// // given values in a tree with the given root.
// func VerifyProof(cs suites.CipherSuite, x []uint64, n uint64, values [][]byte, proof [][]byte, root []byte) error {
// 	cand, err := EvaluateBatchProof(cs, x, n, values, proof)
// 	if err != nil {
// 		return err
// 	} else if !bytes.Equal(root, cand) {
// 		return errors.New("root does not match proof")
// 	}
// 	return nil
// }
