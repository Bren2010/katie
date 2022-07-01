package prefix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// buildKey returns a slice starting and ending with other slices, `prefix` and
// `suffix`, separated by a nibble `b`.
func buildKey(prefix []byte, b byte, suffix []byte, half bool) []byte {
	out := make([]byte, len(prefix)+len(suffix))
	copy(out[:len(prefix)], prefix)
	copy(out[len(prefix):], suffix)

	if half {
		out[len(prefix)-1] ^= b
	} else {
		out[len(prefix)] ^= b << 4
	}

	return out
}

func buildPrefix(prefix []byte, b byte, half bool) ([]byte, string) {
	if half {
		out := make([]byte, len(prefix))
		copy(out, prefix)
		out[len(out)-1] ^= b
		return out, hex.EncodeToString(out)
	}

	out := make([]byte, len(prefix)+1)
	copy(out, prefix)
	out[len(out)-1] ^= b << 4

	id := hex.EncodeToString(out)
	return out, id[:len(id)-1]
}

func buildSuffix(key []byte, fullBytes int, half bool) []byte {
	if half {
		out := make([]byte, len(key)-fullBytes+1)
		copy(out, key[fullBytes-1:])
		out[0] &= 0xf
		return out
	}

	out := make([]byte, len(key)-fullBytes)
	copy(out, key[fullBytes:])
	return out
}

// parsePrefix returns the slice prefix from `id`, which is the string primary
// key used in the database.
func parsePrefix(id string) ([]byte, error) {
	if id == "root" {
		return make([]byte, 0)
	}
	paddedId := id
	if len(paddedId)%2 == 1 {
		paddedId += "0"
	}
	raw, err := hex.DecodeString(paddedId)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %v: %v", id, err)
	}
	return raw, nil
}

// getNextNibble returns the next nibble from `key` that the search path should
// follow, if the current path is `fullBytes` long.
func getNextNibble(key []byte, fullBytes int, half bool) byte {
	if half {
		return key[fullBytes-1] & 0xf
	}
	return key[fullBytes] >> 4
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
