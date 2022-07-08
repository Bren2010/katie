package log

import (
	"testing"

	"bytes"
	"crypto/rand"
	mrand "math/rand"

	"github.com/JumpPrivacy/katie/db"
)

func random() []byte {
	out := make([]byte, 32)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

func dup(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// SimpleRootCalculator is an alternative implementation of the root-calculation
// logic in the log tree which we use to double-check things are implemented
// correctly.
type SimpleRootCalculator struct {
	chain   []*nodeData
	parents [][]byte
}

func NewSimpleRootCalculator() *SimpleRootCalculator {
	return &SimpleRootCalculator{chain: make([]*nodeData, 0)}
}

func (c *SimpleRootCalculator) CheckParents() {
	nonEmpty := 0
	for _, elem := range c.chain {
		if elem != nil {
			nonEmpty++
		}
	}
	assert(len(c.parents) == nonEmpty-1)
}

func (c *SimpleRootCalculator) Add(leaf []byte, parents [][]byte) {
	c.parents = c.Insert(0, leaf, parents)
	c.CheckParents()
}

func (c *SimpleRootCalculator) Insert(level int, value []byte, parents [][]byte) [][]byte {
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

func (c *SimpleRootCalculator) Root() []byte {
	assert(len(c.chain) > 0)

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
	assert(root != nil)

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
		return root.value
	}
	return root.hash
}

// verifyInclusionProof checks that `proof` is a valid inclusion proof for
// `value` at position `x` in a tree with the given root.
func verifyInclusionProof(x, n int, value []byte, proof *InclusionProof, root []byte) {
	for _, elem := range proof.Hashes {
		assert(len(elem) == 32)
	}
	for _, elem := range proof.Values {
		assert(len(elem) == 32)
	}
	for _, elem := range proof.Intermediates {
		assert(len(elem) == 32)
	}

	x = 2 * x
	path := copath(x, n)

	pn := len(path)
	pnl := len(noLeaves(path))
	assert(len(proof.Hashes) == pnl)
	assert(len(proof.Values) == pn)
	assert(len(proof.Intermediates) == pn-1)

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

	assert(bytes.Equal(acc.hash, root))
}

func verifyConsistencyProof(m, n int, proof *ConsistencyProof, mRoot, nRoot []byte) {
	for _, elem := range proof.Hashes {
		assert(len(elem) == 32)
	}
	for _, elem := range proof.Values {
		assert(len(elem) == 32)
	}
	for _, elem := range proof.Intermediates {
		assert(len(elem) == 32)
	}
	for _, elem := range proof.IntermediatesM {
		assert(len(elem) == 32)
	}

	ids := consistencyProof(m, n)
	calc := NewSimpleRootCalculator()

	assert(len(proof.Hashes) == len(noLeaves(ids)))
	assert(len(proof.Values) == len(ids))

	// Step 1: Verify that the consistency proof aligns with mRoot.
	path := fullSubtrees(root(m), m)
	if len(path) == 1 {
		// m is a power of two so we don't need to verify anything.
		calc.Insert(level(root(m)), mRoot, [][]byte{proof.IntermediatesM[0]})
		assert(len(proof.IntermediatesM) == 1)
	} else {
		for i := 0; i < len(path); i++ {
			assert(ids[i] == path[i])
			if isLeaf(path[i]) {
				calc.Insert(level(path[i]), proof.Values[i], nil)
			} else {
				calc.Insert(level(path[i]), proof.Hashes[0], [][]byte{proof.Values[i]})
				proof.Hashes = proof.Hashes[1:]
			}
		}
		calc.parents = append(proof.IntermediatesM, nil)
		calc.CheckParents()
		assert(bytes.Equal(mRoot, calc.Root()))
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
	calc.CheckParents()
	assert(bytes.Equal(nRoot, calc.Root()))
}

func TestInclusionProof(t *testing.T) {
	tree := NewTree(db.NewMemoryTx())
	calc := NewSimpleRootCalculator()

	var (
		nodes [][]byte
		root  []byte
		err   error
	)
	for i := 0; i < 2000; i++ {
		path := directPath(2*i, i+1)

		// Generate new leaf and parent values.
		leaf := random()
		if len(nodes) == 0 {
			nodes = append(nodes, leaf)
		} else {
			nodes = append(nodes, nil, leaf)
		}
		parents := make([][]byte, len(path))
		for i, x := range path {
			intermediate := random()
			nodes[x] = dup(intermediate)
			parents[i] = intermediate
		}

		// Append to the tree.
		root, err = tree.Append(i, leaf, parents)
		if err != nil {
			t.Fatal(err)
		}
		n := i + 1

		calc.Add(leaf, parents)
		assert(bytes.Equal(root, calc.Root()))

		// Do inclusion proofs for a few random entries.
		if n < 5 {
			continue
		}
		for j := 0; j < 5; j++ {
			x := mrand.Intn(n)
			value, proof, err := tree.Get(x, n)
			if err != nil {
				t.Fatal(err)
			}

			// Check that correct value was given and inclusion proof works.
			assert(bytes.Equal(value, nodes[2*x]))
			verifyInclusionProof(x, n, value, proof, root)

			// Check that the copath/intermediate values match as well.
			for i, id := range copath(2*x, n) {
				assert(bytes.Equal(proof.Values[i], nodes[id]))
			}
			dpath := directPath(2*x, n)
			for i, id := range dpath[:len(dpath)-1] {
				assert(bytes.Equal(proof.Intermediates[i], nodes[id]))
			}
		}
	}
}

func TestConsistencyProof(t *testing.T) {
	tree := NewTree(db.NewMemoryTx())

	var roots [][]byte
	for i := 0; i < 2000; i++ {
		path := directPath(2*i, i+1)

		// Generate new leaf and parent values.
		leaf := random()
		parents := make([][]byte, len(path))
		for i, _ := range path {
			intermediate := random()
			parents[i] = intermediate
		}

		// Append to the tree.
		root, err := tree.Append(i, leaf, parents)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, dup(root))
		n := i + 1

		// Do consistency proofs for a few random revisions.
		if n < 5 {
			continue
		}
		for j := 0; j < 5; j++ {
			m := mrand.Intn(n-1) + 1
			proof, err := tree.GetConsistencyProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			verifyConsistencyProof(m, n, proof, roots[m-1], roots[n-1])

			if m > 1 {
				p := mrand.Intn(m-1) + 1
				proof, err := tree.GetConsistencyProof(p, m)
				if err != nil {
					t.Fatal(err)
				}
				verifyConsistencyProof(p, m, proof, roots[p-1], roots[m-1])
			}
		}
	}
}
