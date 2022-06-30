package tree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// TODO: Look into more efficient storage format for prefix tree nodes.

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

func prefixTreeHash(leaf bool, left, right []byte) []byte {
	input := make([]byte, 1+len(left)+len(right))
	if leaf {
		input[0] = 1
	}
	copy(input[1:1+len(left)], left)
	copy(input[1+len(left):], right)

	output := sha256.Sum256(input)
	return output[:]
}

func prefixLeafHash(suffix, value []byte) []byte {
	return prefixTreeHash(true, suffix, value)
}

func prefixParentHash(left, right []byte) []byte {
	return prefixTreeHash(false, left, right)
}

type prefixNode interface {
	isPrefixNode()
}

type prefixLeafNode struct {
	suffix, value []byte
}

func (n prefixLeafNode) isPrefixNode() {}

type prefixParentNode struct {
	hash []byte
}

func (n prefixParentNode) isPrefixNode() {}

// prefixChunk is a helper struct that handles parsing the data in a chunk.
type prefixChunk struct {
	prefix []byte
	cache  [16][]byte
	elems  map[byte]prefixNode
}

func newPrefixChunk(prefix, data []byte) (*prefixChunk, error) {
	if len(data) < 16*32 {
		return nil, fmt.Errorf("prefix tree chunk is too short")
	}
	cache := [16][]byte{}
	for i := 0; i < 16; i++ {
		cache[i] = data[i*32 : (i+1)*32]
	}
	data = data[16*32:]

	elems := make(map[byte]prefixNode)
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("invalid data in slice")
		}
		b := data[0]
		if _, ok := elems[b]; ok {
			return nil, fmt.Errorf("duplicate entries")
		}

		if data[1] == 0 {
			// Leaf node: Suffix and then value.
			suffixLen := 32 - len(prefix) - 1
			if len(data) < 2+suffixLen+32 {
				return nil, fmt.Errorf("not enough data in slice")
			}
			suffix := data[2 : 2+suffixLen]
			value := data[2+suffixLen : 2+suffixLen+32]
			data = data[2+suffixLen+32:]

			elems[b] = prefixLeafNode{suffix: suffix, value: value}
		} else if data[1] == 1 {
			// Parent node: Just hash.
			if len(data) < 2+32 {
				return nil, fmt.Errorf("not enough data in slice")
			}
			hash := data[2 : 2+32]
			data = data[2+32:]

			elems[b] = prefixParentNode{hash: hash}
		} else {
			return nil, fmt.Errorf("unexpected value in slice")
		}
	}

	return &prefixChunk{
		prefix: prefix,
		cache:  cache,
		elems:  elems,
	}, nil
}

func newEmptyPrefixChunk(prefix []byte) *prefixChunk {
	value := make([]byte, 32)
	for i := 0; i < 4; i++ {
		value = prefixParentHash(value, value)
	}
	buf := make([]byte, 32*16)
	for i := 0; i < 16; i++ {
		copy(buf[i*32:], value)
	}
	chunk, err := newPrefixChunk(prefix, buf)
	if err != nil {
		panic(err)
	}
	return chunk
}

// updateCache updates the cache of hashes given that only element `b` has
// changed.
func (pc *prefixChunk) updateCache(b byte) {
	b = b >> 4
	bits := fmt.Sprintf("%04b", b)
	pc.cache[b] = prefixParentHash(
		pc._hash(bits+"0"),
		pc._hash(bits+"1"),
	)
}

// hash returns the root hash of the chunk.
func (pc *prefixChunk) hash() []byte {
	return pc._hash("")
}

// proof returns the proof of (non-)inclusion for element b.
func (pc *prefixChunk) proof(b byte) [][]byte {
	out := make([][]byte, 0)
	bits := ""

	for i := 0; i < 8; i++ {
		if (b & (1 << (7 - i))) == 0 {
			out = append(out, pc._hash(bits+"1"))
			bits = bits + "0"
		} else {
			out = append(out, pc._hash(bits+"0"))
			bits = bits + "1"
		}
	}

	return out
}

func (pc *prefixChunk) _hash(b string) []byte {
	if len(b) == 4 {
		n, err := strconv.ParseInt(b, 2, 4)
		if err != nil {
			panic(err)
		}
		return pc.cache[n]
	} else if len(b) == 8 {
		n, err := strconv.ParseInt(b, 2, 8)
		if err != nil {
			panic(err)
		}
		elem, ok := pc.elems[byte(n)]
		if ok {
			return make([]byte, 32)
		}
		switch elem := elem.(type) {
		case prefixLeafNode:
			return prefixLeafHash(elem.suffix, elem.value)
		case prefixParentNode:
			return elem.hash
		default:
			panic("unreachable")
		}
	}

	return prefixParentHash(pc._hash(b+"0"), pc._hash(b+"1"))
}

// marshal returns the serialize chunk.
func (pc *prefixChunk) marshal() []byte {
	out := make([]byte, 0)

	// Prepend the cached hashes.
	for i := 0; i < len(pc.cache); i++ {
		out = append(out, pc.cache[i]...)
	}

	// Serialize each element individually.
	for i := 0; i < 256; i++ {
		elem, ok := pc.elems[byte(i)]
		if !ok {
			continue
		}

		switch elem := elem.(type) {
		case prefixLeafNode:
			piece := make([]byte, 2+len(elem.suffix)+32)
			piece[0] = byte(i)
			piece[1] = 0
			copy(piece[2:2+len(suffix)], elem.suffix)
			copy(piece[2+len(suffix):], elem.value)

			out = append(out, piece)
		case prefixParentNode:
			piece := make([]byte, 34)
			piece[0] = byte(i)
			piece[1] = 1
			copy(piece[2:34], elem.hash)

			out = append(out, piece)
		default:
			panic("unreachable")
		}
	}

	return out
}

// PrefixTree represents the roof of a Merkle prefix tree that can provide
// inclusion and non-inclusion proofs.
type PrefixTree struct{}

func NewPrefixTree() {}
