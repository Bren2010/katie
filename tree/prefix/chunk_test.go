package prefix

import (
	"testing"

	"bytes"
)

func TestPrefixChunk(t *testing.T) {
	zeroes := make([]byte, 32)
	ones := make([]byte, 32)
	for i := 0; i < 32; i++ {
		ones[i] = 1
	}

	chunk := newEmptyChunk(false, make([]byte, 0))
	chunk.elems[0] = &treeNode{typ: leafNode, inner: ones}
	root := chunk.hash()

	shortProof := chunk.proof(10)
	assert(len(shortProof) == 1)
	assert(bytes.Equal(root, parentHash(shortProof[0], zeroes)))

	longProof := chunk.proof(0)
	assert(len(longProof) == 4)
	for i := 0; i < 4; i++ {
		assert(bytes.Equal(longProof[i], zeroes))
	}
}
