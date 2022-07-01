package prefix

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// buildKey returns a slice starting and ending with other slices, `prefix` and
// `suffix`, separated by byte `b`.
func buildKey(prefix []byte, b byte, suffix []byte) []byte {
	return append(prefix, append([]byte{b}, suffix...)...)
}

// parsePrefix returns the slice prefix from `id`, which is the string primary
// key used in the database.
func parsePrefix(id string) []byte {
	if id == "root" {
		return make([]byte, 0)
	}
	raw, err := hex.DecodeString(id)
	if err != nil {
		panic(fmt.Errorf("failed to parse key: %v: %v", id, err))
	}
	return raw
}

func treeHash(leaf bool, left, right []byte) []byte {
	input := make([]byte, 1+len(left)+len(right))
	if leaf {
		input[0] = byte(leafNode)
	} else {
		input[0] = byte(parentNode)
	}
	copy(input[1:1+len(left)], left)
	copy(input[1+len(left):], right)

	output := sha256.Sum256(input)
	return output[:]
}

func leafHash(suffix []byte) []byte {
	return treeHash(true, suffix, nil)
}

func parentHash(left, right []byte) []byte {
	return treeHash(false, left, right)
}
