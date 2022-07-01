package prefix

import (
	"fmt"
	"strconv"
)

type treeNode interface {
	// sum returns the tree hash of the node.
	sum() []byte
	// marshal returns the serialized node contents for storage in the database.
	marshal(b byte) []byte
}

type leafNode struct {
	suffix, value []byte
}

func (n leafNode) sum() []byte {
	return leafHash(n.suffix, n.value)
}

func (n leafNode) marshal(b byte) []byte {
	out := make([]byte, 2+len(n.suffix)+32)
	out[0] = b
	out[1] = 0
	copy(out[2:2+len(n.suffix)], n.suffix)
	copy(out[2+len(n.suffix):], n.value)

	return out
}

type parentNode struct {
	hash []byte
}

func (n parentNode) sum() []byte {
	return n.hash
}

func (n parentNode) marshal(b byte) []byte {
	out := make([]byte, 34)
	out[0] = b
	out[1] = 1
	copy(out[2:34], n.hash)

	return out
}

// prefixChunk is a helper struct that handles parsing the data in a chunk.
type prefixChunk struct {
	prefix []byte
	cache  [16][]byte
	elems  map[byte]treeNode
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

	elems := make(map[byte]treeNode)
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

			elems[b] = leafNode{suffix: suffix, value: value}
		} else if data[1] == 1 {
			// Parent node: Just hash.
			if len(data) < 2+32 {
				return nil, fmt.Errorf("not enough data in slice")
			}
			hash := data[2 : 2+32]
			data = data[2+32:]

			elems[b] = parentNode{hash: hash}
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

func newEmptyChunk(prefix []byte) *prefixChunk {
	value := make([]byte, 32)
	for i := 0; i < 4; i++ {
		value = parentHash(value, value)
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
	pc.cache[b] = parentHash(
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
		if !ok {
			return make([]byte, 32)
		}
		return elem.sum()
	}

	return parentHash(pc._hash(b+"0"), pc._hash(b+"1"))
}

// marshal returns the serialized chunk.
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
		out = append(out, elem.marshal(byte(i))...)
	}

	return out
}
