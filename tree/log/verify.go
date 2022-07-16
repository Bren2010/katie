package log

import (
	"bytes"
	"errors"
)

// simpleRootCalculator is an alternative implementation of the root-calculation
// logic in the log tree which we use to double-check things are implemented
// correctly.
type simpleRootCalculator struct {
	chain   []*nodeData
	parents [][]byte
}

func newSimpleRootCalculator() *simpleRootCalculator {
	return &simpleRootCalculator{chain: make([]*nodeData, 0)}
}

func (c *simpleRootCalculator) CheckParents() error {
	nonEmpty := 0
	for _, elem := range c.chain {
		if elem != nil {
			nonEmpty++
		}
	}
	if len(c.parents) != nonEmpty-1 {
		return errors.New("wrong number of parents")
	}
	return nil
}

func (c *simpleRootCalculator) Add(leaf []byte, parents [][]byte) error {
	c.parents = c.Insert(0, leaf, parents)
	return c.CheckParents()
}

func (c *simpleRootCalculator) Insert(level int, value []byte, parents [][]byte) [][]byte {
	for len(c.chain) < level+1 {
		c.chain = append(c.chain, nil)
	}

	var acc *nodeData
	if level == 0 {
		acc = &nodeData{leaf: true, hash: nil, value: value}
	} else {
		acc = &nodeData{leaf: false, hash: value, value: parents[0]}
		parents = parents[1:]
	}

	i := level
	for i < len(c.chain) && c.chain[i] != nil {
		acc = &nodeData{
			leaf:  false,
			hash:  treeHash(c.chain[i], acc),
			value: parents[0],
		}
		c.chain[i] = nil
		parents = parents[1:]
		i++
	}
	if i == len(c.chain) {
		c.chain = append(c.chain, acc)
	} else {
		c.chain[i] = acc
	}

	return parents
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
	j := 0
	for i := rootPos + 1; i < len(c.chain); i++ {
		if c.chain[i] != nil {
			root = &nodeData{
				leaf:  false,
				hash:  treeHash(c.chain[i], root),
				value: c.parents[j],
			}
			j++
		}
	}

	if len(c.chain) == 1 {
		return root.value, nil
	}
	return root.hash, nil
}

// VerifyInclusionProof checks that `proof` is a valid inclusion proof for
// `value` at position `x` in a tree with the given root.
func VerifyInclusionProof(x, n int, value []byte, proof *InclusionProof, root []byte) error {
	for _, sl := range [][][]byte{proof.Hashes, proof.Values, proof.Intermediates} {
		for _, elem := range sl {
			if len(elem) != 32 {
				return errors.New("malformed proof")
			}
		}
	}

	x = 2 * x
	path := copath(x, n)

	pn := len(path)
	pnl := len(noLeaves(path))
	if len(proof.Hashes) != pnl || len(proof.Values) != pn {
		return errors.New("malformed proof")
	} else if pn == 0 && len(proof.Intermediates) != 0 {
		return errors.New("malformed proof")
	} else if pn != 0 && len(proof.Intermediates) != pn-1 {
		return errors.New("malformed proof")
	}

	proofNodes := make([]*nodeData, len(path))
	j := 0
	for i := 0; i < len(path); i++ {
		leaf := isLeaf(path[i])

		var h []byte
		if !leaf {
			h = proof.Hashes[j]
			j++
		}

		proofNodes[i] = &nodeData{leaf: leaf, hash: h, value: proof.Values[i]}
	}

	acc := &nodeData{leaf: true, hash: nil, value: value}
	for i, nd := range proofNodes {
		var val []byte
		if i != len(proofNodes)-1 {
			val = proof.Intermediates[i]
		}
		var hash []byte
		if x < path[i] {
			hash = treeHash(acc, nd)
		} else {
			hash = treeHash(nd, acc)
		}

		acc = &nodeData{leaf: false, hash: hash, value: val}
		x = path[i]
	}

	if acc.leaf && !bytes.Equal(acc.value, root) {
		return errors.New("root does not match proof")
	} else if !acc.leaf && !bytes.Equal(acc.hash, root) {
		return errors.New("root does not match proof")
	}
	return nil
}

// VerifyConsistencyProof checks that `proof` is a valid consistency proof
// between `mRoot` and `nRoot` where `m` < `n`.
func VerifyConsistencyProof(m, n int, proof *ConsistencyProof, mRoot, nRoot []byte) error {
	for _, sl := range [][][]byte{proof.Hashes, proof.Values, proof.Intermediates, proof.IntermediatesM} {
		for _, elem := range sl {
			if len(elem) != 32 {
				return errors.New("malformed proof")
			}
		}
	}

	ids := consistencyProof(m, n)
	calc := newSimpleRootCalculator()

	if len(proof.Hashes) != len(noLeaves(ids)) || len(proof.Values) != len(ids) {
		return errors.New("malformed proof")
	}

	// Step 1: Verify that the consistency proof aligns with mRoot.
	path := fullSubtrees(root(m), m)
	if len(path) == 1 {
		// m is a power of two so we don't need to verify anything.
		calc.Insert(level(root(m)), mRoot, [][]byte{proof.IntermediatesM[0]})
		if len(proof.IntermediatesM) != 1 {
			return errors.New("malformed proof")
		}
	} else {
		for i := 0; i < len(path); i++ {
			if ids[i] != path[i] {
				return errors.New("unexpected error")
			}
			if isLeaf(path[i]) {
				calc.Insert(level(path[i]), proof.Values[i], nil)
			} else {
				calc.Insert(level(path[i]), proof.Hashes[0], [][]byte{proof.Values[i]})
				proof.Hashes = proof.Hashes[1:]
			}
		}
		calc.parents = append(proof.IntermediatesM, nil)
		if err := calc.CheckParents(); err != nil {
			return err
		} else if root, err := calc.Root(); err != nil {
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
	proof.Intermediates = append(proof.Intermediates, nil)
	for ; i < len(ids); i++ {
		if isLeaf(ids[i]) {
			proof.Intermediates = calc.Insert(level(ids[i]), proof.Values[i], proof.Intermediates)
		} else {
			proof.Intermediates = calc.Insert(level(ids[i]), proof.Hashes[0], append([][]byte{proof.Values[i]}, proof.Intermediates...))
			proof.Hashes = proof.Hashes[1:]
		}
	}
	calc.parents = proof.Intermediates
	if err := calc.CheckParents(); err != nil {
		return err
	} else if root, err := calc.Root(); err != nil {
		return err
	} else if !bytes.Equal(nRoot, root) {
		return errors.New("second root does not match proof")
	}
	return nil
}
