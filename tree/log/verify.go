package log

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/log/math"
)

// Verifier is a stateful verifier for inclusion and consistency proofs from a
// Log Tree.
type Verifier struct {
	cs suites.CipherSuite

	prev     *uint64 // Previously observed tree size, or nil if none.
	subtrees []uint64
	values   [][]byte
}

func NewVerifier(cs suites.CipherSuite) *Verifier {
	return &Verifier{cs: cs}
}

// Last returns the previously observed tree size.
func (v *Verifier) Last() *uint64 { return v.prev }

// FullSubtrees returns the retained full subtree values of the tree.
func (v *Verifier) FullSubtrees() [][]byte { return v.values }

// Retain updates the verifier's retained state.
func (v *Verifier) Retain(prev uint64, fullSubtrees [][]byte) error {
	if prev == 0 || prev > math.MaxTreeSize {
		return errors.New("invalid value for previous tree size")
	}
	subtrees := math.FullSubtrees(math.Root(prev), prev)
	if len(fullSubtrees) != len(subtrees) {
		return errors.New("unexpected number of full subtree values provided")
	}
	for _, val := range fullSubtrees {
		if len(val) != v.cs.HashSize() {
			return errors.New("hash has wrong size")
		}
	}

	v.prev = &prev
	v.subtrees = subtrees
	v.values = fullSubtrees
	return nil
}

// Evaluate returns the root that would result in `proof` being valid.
func (v *Verifier) Evaluate(entries []uint64, n uint64, nP *uint64, values [][]byte, proof [][]byte) ([][]byte, [][]byte, error) {
	// Input validation.
	if n == 0 || n > math.MaxTreeSize {
		return nil, nil, errors.New("invalid value for current tree size")
	} else if nP != nil && (*nP == 0 || *nP > n || *nP > math.MaxTreeSize) {
		return nil, nil, errors.New("invalid value for additional tree size")
	} else if len(entries) != len(values) {
		return nil, nil, errors.New("number of leaves indices must equal number of leaf values")
	}
	for _, x := range entries {
		if x >= n {
			return nil, nil, errors.New("leaf is beyond right edge of tree")
		}
	}
	copath := math.BatchCopath(entries, n, nP, v.prev)
	if len(proof) != len(copath) {
		return nil, nil, errors.New("malformed proof")
	}

	// Build a map from node index to value for all the nodes where we are
	// proving inclusion.
	nodes := make(map[uint64]*nodeData)
	for i, x := range entries {
		if err := v.addToMap(nodes, 2*x, values[i]); err != nil {
			return nil, nil, err
		}
	}
	for i, x := range v.subtrees {
		if err := v.addToMap(nodes, x, v.values[i]); err != nil {
			return nil, nil, err
		}
	}
	for i, x := range copath {
		if err := v.addToMap(nodes, x, proof[i]); err != nil {
			return nil, nil, err
		}
	}

	// Build a sorted list of node indices. This is used to ensure that we know
	// when we need to recurse further down and recompute a node value even
	// though we may already know it.
	sorted := make([]uint64, 0)
	for x := range nodes {
		sorted = append(sorted, x)
	}
	slices.Sort(sorted)

	// Evaluate the proof by computing all intermediate node values.
	if err := v.evaluate(math.Root(n), n, nodes, sorted); err != nil {
		return nil, nil, err
	}

	// Extract full subtree values and return.
	var fullSubtrees [][]byte
	for _, x := range math.FullSubtrees(math.Root(n), n) {
		fullSubtrees = append(fullSubtrees, nodes[x].value)
	}
	var additional [][]byte
	if nP != nil {
		for _, x := range math.FullSubtrees(math.Root(*nP), *nP) {
			additional = append(additional, nodes[x].value)
		}
	}
	return fullSubtrees, additional, nil
}

func (v *Verifier) addToMap(m map[uint64]*nodeData, x uint64, val []byte) error {
	if len(val) != v.cs.HashSize() {
		return errors.New("value is unexpected size")
	} else if expected, ok := m[x]; ok && !bytes.Equal(val, expected.value) {
		return errors.New("different values presented for same node index")
	} else if !ok {
		m[x] = &nodeData{leaf: math.IsLeaf(x), value: val}
	}
	return nil
}

func (v *Verifier) evaluate(x, n uint64, nodes map[uint64]*nodeData, sorted []uint64) error {
	if len(sorted) == 1 && sorted[0] == x {
		return nil
	}

	i, found := slices.BinarySearch(sorted, x)
	j := i
	if found {
		j++
	}
	left, right := math.Left(x), math.Right(x, n)

	if err := v.evaluate(left, n, nodes, sorted[:i]); err != nil {
		return err
	} else if err := v.evaluate(right, n, nodes, sorted[j:]); err != nil {
		return err
	}

	if math.IsFullSubtree(x, n) {
		intermediate := treeHash(v.cs, nodes[left], nodes[right])
		if err := v.addToMap(nodes, x, intermediate.value); err != nil {
			return err
		}
	}
	return nil
}
