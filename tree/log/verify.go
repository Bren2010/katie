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
	frontier [][]byte
}

func NewVerifier(cs suites.CipherSuite) *Verifier {
	return &Verifier{cs: cs}
}

// Previous returns the previously observed tree size.
func (v *Verifier) Previous() *uint64 { return v.prev }

// Frontier returns the retained frontier of the tree.
func (v *Verifier) Frontier() [][]byte { return v.frontier }

// Retain updates the verifier's retained state.
func (v *Verifier) Retain(prev uint64, frontier [][]byte) error {
	if prev == 0 || prev > math.MaxTreeSize {
		return errors.New("invalid value for previous tree size")
	}
	subtrees := math.FullSubtrees(math.Root(prev), prev)
	if len(frontier) != len(subtrees) {
		return errors.New("frontier has unexpected length")
	}
	for _, val := range frontier {
		if len(val) != v.cs.HashSize() {
			return errors.New("hash has wrong size")
		}
	}

	v.prev = &prev
	v.subtrees = subtrees
	v.frontier = frontier
	return nil
}

// Evaluate returns the root that would result in `proof` being valid.
func (v *Verifier) Evaluate(entries []uint64, n uint64, values [][]byte, proof [][]byte) ([][]byte, error) {
	// Input validation.
	if n == 0 || n > math.MaxTreeSize {
		return nil, errors.New("invalid value for current tree size")
	} else if len(entries) != len(values) {
		return nil, errors.New("number of leaves indices must equal number of leaf values")
	}
	for _, x := range entries {
		if x >= n {
			return nil, errors.New("leaf is beyond right edge of tree")
		}
	}
	copath := math.BatchCopath(entries, n, v.prev)
	if len(proof) != len(copath) {
		return nil, errors.New("malformed proof")
	}

	// Build a map from node index to value for all the nodes where we are
	// proving inclusion.
	valuesMap := make(map[uint64][]byte)
	for i, x := range entries {
		if err := v.addToMap(valuesMap, 2*x, values[i]); err != nil {
			return nil, err
		}
	}
	for i, x := range v.subtrees {
		if err := v.addToMap(valuesMap, x, v.frontier[i]); err != nil {
			return nil, err
		}
	}

	// Build sorted list of node indices.
	nodes := make([]uint64, 0, len(valuesMap))
	for x := range valuesMap {
		nodes = append(nodes, x)
	}
	slices.Sort(nodes)

	// Build a map from node index to value for all the nodes that were provided
	// as part of the proof.
	proofMap := make(map[uint64][]byte)
	for i, x := range copath {
		if err := v.addToMap(proofMap, x, proof[i]); err != nil {
			return nil, err
		}
	}

	// Compute the expected frontier.
	out := make([][]byte, 0)
	root := math.Root(n)
	offset := 0

	for {
		if math.IsFullSubtree(root, n) {
			elem, err := v.evaluate(root, n, nodes[offset:], valuesMap, proofMap)
			if err != nil {
				return nil, err
			}
			out = append(out, elem.value)
			return out, nil
		}
		i, _ := slices.BinarySearch(nodes, root)
		elem, err := v.evaluate(math.Left(root), n, nodes[offset:i], valuesMap, proofMap)
		if err != nil {
			return nil, err
		}
		out = append(out, elem.value)
		root = math.Right(root, n)
		offset = i
	}
}

func (v *Verifier) addToMap(m map[uint64][]byte, x uint64, val []byte) error {
	if len(val) != v.cs.HashSize() {
		return errors.New("value is unexpected size")
	} else if expected, ok := m[x]; ok && !bytes.Equal(val, expected) {
		return errors.New("different values presented for same node index")
	} else if !ok {
		m[x] = val
	}
	return nil
}

func (v *Verifier) evaluate(x, n uint64, nodes []uint64, values, proof map[uint64][]byte) (*nodeData, error) {
	if len(nodes) == 0 {
		if math.IsFullSubtree(x, n) {
			return &nodeData{leaf: math.IsLeaf(x), value: proof[x]}, nil
		}
		left := &nodeData{leaf: false, value: proof[math.Left(x)]}
		right, err := v.evaluate(math.Right(x, n), n, nil, nil, proof)
		if err != nil {
			return nil, err
		}
		return treeHash(v.cs, left, right), nil
	} else if len(nodes) == 1 && nodes[0] == x {
		return &nodeData{leaf: math.IsLeaf(x), value: values[x]}, nil
	}

	i, found := slices.BinarySearch(nodes, x)
	j := i
	if found {
		j++
	}
	left, err := v.evaluate(math.Left(x), n, nodes[:i], values, proof)
	if err != nil {
		return nil, err
	}
	right, err := v.evaluate(math.Right(x, n), n, nodes[j:], values, proof)
	if err != nil {
		return nil, err
	}
	intermediate := treeHash(v.cs, left, right)

	if found && !bytes.Equal(intermediate.value, values[x]) {
		return nil, errors.New("unexpected value computed for intermediate node")
	}
	return intermediate, nil
}
