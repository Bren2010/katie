package prefix

import (
	"bytes"
	"crypto/sha256"
)

func treeHash(leaf bool, left, right []byte) [32]byte {
	input := make([]byte, 1+len(left)+len(right))
	if leaf {
		input[0] = 0
	} else {
		input[0] = 1
	}
	copy(input[1:1+len(left)], left)
	copy(input[1+len(left):], right)

	return sha256.Sum256(input)
}

func leafHash(nd *leafNode) [32]byte {
	buf := new(bytes.Buffer)
	if err := nd.Marshal(buf); err != nil {
		panic(err)
	}
	return treeHash(true, buf.Bytes(), nil)
}

func parentHash(left, right [32]byte) [32]byte {
	return treeHash(false, left[:], right[:])
}

func getBit(data [32]byte, bit int) bool {
	return (data[bit/8]>>(7-(bit%8)))&1 == 1
}
