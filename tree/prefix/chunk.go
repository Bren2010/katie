package prefix

import (
	"fmt"
)

var nibbleTable = map[string]byte{
	"0000": 0,
	"0001": 1,
	"0010": 2,
	"0011": 3,
	"0100": 4,
	"0101": 5,
	"0110": 6,
	"0111": 7,
	"1000": 8,
	"1001": 9,
	"1010": 10,
	"1011": 11,
	"1100": 12,
	"1101": 13,
	"1110": 14,
	"1111": 15,
}

type treeNodeType byte

const (
	leafNode   treeNodeType = 0
	parentNode              = 1
)

type treeNode struct {
	typ   treeNodeType
	inner []byte
}

func (n *treeNode) sum() []byte {
	switch n.typ {
	case leafNode:
		return leafHash(n.inner)
	case parentNode:
		return n.inner
	default:
		panic("unreachable")
	}
}

// marshal returns the serialized node contents for storage in the database.
func (n *treeNode) marshal(b byte) []byte {
	out := make([]byte, 2+len(n.inner))
	out[0] = b
	out[1] = byte(n.typ)
	copy(out[2:], n.inner)

	return out
}

// prefixChunk is a helper struct that handles parsing the data in a chunk.
type prefixChunk struct {
	half   bool
	prefix []byte
	elems  map[byte]*treeNode
}

func newPrefixChunk(half bool, prefix, data []byte) (*prefixChunk, error) {
	elems := make(map[byte]*treeNode)

	for len(data) > 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("invalid data in slice")
		}
		b := data[0]
		if _, ok := elems[b]; ok {
			return nil, fmt.Errorf("duplicate entries")
		} else if (b >> 4) != 0 {
			return nil, fmt.Errorf("invalid data in slice")
		}
		t := treeNodeType(data[1])

		var innerLen int
		if t == leafNode {
			innerLen = 32 - len(prefix)
		} else if t == parentNode {
			innerLen = 32
		} else {
			return nil, fmt.Errorf("unexpected value in slice")
		}

		if len(data) < 2+innerLen {
			return nil, fmt.Errorf("not enough data in slice")
		}
		inner := data[2 : 2+innerLen]
		data = data[2+innerLen:]

		elems[b] = &treeNode{typ: t, inner: inner}
	}

	return &prefixChunk{
		half:   half,
		prefix: prefix,
		elems:  elems,
	}, nil
}

func newEmptyChunk(half bool, prefix []byte) *prefixChunk {
	chunk, err := newPrefixChunk(half, prefix, make([]byte, 0))
	if err != nil {
		panic(err)
	}
	return chunk
}

// hash returns the root hash of the chunk.
func (pc *prefixChunk) hash() []byte {
	return pc._hash("")
}

// proof returns the proof of (non-)inclusion for element b.
func (pc *prefixChunk) proof(b byte) [][]byte {
	if b >= 16 {
		panic("cannot give proof for requested path")
	}

	out := make([][]byte, 0)
	bits := ""

	for i := 0; i < 4; i++ {
		if pc._isEmpty(bits) {
			break
		}
		if (b & (1 << (3 - i))) == 0 {
			out = append(out, pc._hash(bits+"1"))
			bits = bits + "0"
		} else {
			out = append(out, pc._hash(bits+"0"))
			bits = bits + "1"
		}
	}

	return out
}

func (pc *prefixChunk) _isEmpty(b string) bool {
	if len(b) == 4 {
		n, ok := nibbleTable[b]
		if !ok {
			panic("could not find nibble")
		}
		_, ok = pc.elems[n]
		return !ok
	}

	return pc._isEmpty(b+"0") && pc._isEmpty(b+"1")
}

func (pc *prefixChunk) _hash(b string) []byte {
	if pc._isEmpty(b) {
		return make([]byte, 32)
	} else if len(b) == 4 {
		n, ok := nibbleTable[b]
		if !ok {
			panic("could not find nibble")
		}
		return pc.elems[n].sum()
	}

	return parentHash(pc._hash(b+"0"), pc._hash(b+"1"))
}

// marshal returns the serialized chunk.
func (pc *prefixChunk) marshal() []byte {
	out := make([]byte, 0)

	for i := 0; i < 16; i++ {
		elem, ok := pc.elems[byte(i)]
		if !ok {
			continue
		}
		out = append(out, elem.marshal(byte(i))...)
	}

	return out
}
