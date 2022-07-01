// Package prefix implements a Merkle prefix tree.
package prefix

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/JumpPrivacy/katie/db"
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
		input[0] = 1
	}
	copy(input[1:1+len(left)], left)
	copy(input[1+len(left):], right)

	output := sha256.Sum256(input)
	return output[:]
}

func leafHash(suffix, value []byte) []byte {
	return treeHash(true, suffix, value)
}

func parentHash(left, right []byte) []byte {
	return treeHash(false, left, right)
}

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

// chunkSet is a helper struct for directing operations that span multiple
// prefixChunks, like search and insertion.
type chunkSet struct {
	chunks   map[string]*prefixChunk
	modified map[string]struct{}
}

func newChunkSet(chunks map[string][]byte) (*chunkSet, error) {
	out := &chunkSet{
		chunks:   make(map[string]*prefixChunk),
		modified: make(map[string]struct{}),
	}

	for id, data := range chunks {
		prefix, err := hex.DecodeString(id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse id: %v", id)
		}
		chunk, err := newPrefixChunk(prefix, data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chunk: %v: %v", id, err)
		}
		out.chunks[id] = chunk
	}

	return out, nil
}

// search executes a search for `key` through the tree, assuming all necessary
// chunks are already loaded into the ChunkSet.
func (s *chunkSet) search(key []byte) (SearchResult, error) {
	// Walk down the path looking for the right leaf node and building our
	// inclusion/non-inclusion proof.
	id := "root"
	proof := make([][]byte, 0)

	for i := 0; i < len(key); i++ {
		chunk, ok := s.chunks[id]
		if !ok {
			if i == 0 { // The root doesn't exist yet which is fine.
				return nil, nil
			}
			// An intermediate doesn't exist.
			return nil, fmt.Errorf("expected chunk was not found")
		}

		b := key[len(chunk.prefix)]
		proof = append(proof, chunk.proof(b)...)

		elem, ok := chunk.elems[b]
		if !ok {
			return nonInclusionParent{proof: proof}, nil
		}
		switch elem := elem.(type) {
		case leafNode:
			cand := buildKey(chunk.prefix, b, elem.suffix)

			if bytes.Equal(key, cand) {
				return inclusionProof{
					proof: proof,
					value: elem.value,
				}, nil
			}
			return nonInclusionLeaf{
				proof:  proof,
				suffix: elem.suffix,
				value:  elem.value,
			}, nil

		case parentNode:
			id = hex.EncodeToString(key[0 : i+1])

		default:
			panic("unreachable")
		}
	}

	panic("unexpected error condition")
}

// insert executes a search for `key` in the tree and adds it if it doesn't
// exist or replaces the existing value if it does.
func (s *chunkSet) insert(key, value []byte) {
	if _, ok := s.chunks["root"]; !ok {
		s.chunks["root"] = newEmptyChunk(make([]byte, 0))
	}
	return s._insert("root", key, value)
}

func (s *chunkSet) _insert(id string, key, value []byte) ([]byte, error) {
	chunk := s.chunks[id]
	if !bytes.Equal(chunk.prefix, key[:len(chunk.prefix)]) {
		return nil, fmt.Errorf("key does not belong in this chunk")
	}

	b := key[len(chunk.prefix)]
	elem, ok := chunk.elems[b]
	if !ok {
		// This byte isn't already in the chunk so we can just add it.
		chunk.elems[b] = leafNode{
			suffix: key[len(chunk.prefix)+1:],
			value:  value,
		}
	} else {
		switch elem := elem.(type) {
		case leafNode:
			// Reconstruct the key/value pair that's here already.
			oldKey := buildKey(chunk.prefix, b, elem.suffix)
			oldValue := elem.value

			// Compare the key/value pair that's already here with what we want
			// to insert to determine how to continue.
			if bytes.Equal(key, oldKey) {
				// The keys are the same so we just need to replace the value.
				chunk.elems[b] = leafNode{
					suffix: elem.suffix,
					value:  value,
				}
			} else {
				// The keys are different so we need to merge them into a new
				// parent.
				newPrefix := append(chunk.prefix, b)
				newId := hex.EncodeToString(newPrefix)
				if _, ok := s.chunks[newId]; ok {
					return nil, fmt.Errorf("chunk should not exist yet")
				}
				s.chunks[newId] = newEmptyChunk(newPrefix)

				// Add the old key/value pair to the chunk.
				if _, err := s._insert(newId, oldKey, oldValue); err != nil {
					return nil, err
				}
				// Add the new key/value pair.
				if _, err := s._insert(newId, key, value); err != nil {
					return nil, err
				}

				chunk.elems[b] = parentNode{hash: h}
			}

		case parentNode:
			newId := hex.EncodeToString(append(chunk.prefix, b))
			h, err := s._insert(newId, key, value)
			if err != nil {
				return nil, err
			}
			chunk.elems[b] = parentNode{hash: h}

		default:
			panic("unreachable")
		}
	}
	chunk.updateCache(b)

	s.modified[id] = struct{}{}
	return chunk.hash(), nil
}

// marshal returns a map of serialized chunks, for any chunks which have been
// changed.
func (s *chunkSet) marshal() map[string][]byte {
	out := make(map[string][]byte)

	for id, _ := range s.modified {
		out[id] = s.chunks[id].marshal()
	}

	return out
}

type SearchResult interface{}

// nonInclusionParent is a proof of non-inclusion based on showing a null link
// in a parent node where the search path would normally proceed.
type nonInclusionParent struct {
	proof [][]byte
}

// nonInclusionLeaf is a proof of non-inclusion based on showing a leaf node for
// a different key where the search path would normally proceed.
type nonInclusionLeaf struct {
	proof  [][]byte
	suffix []byte
	value  []byte
}

// inclusionLeaf is a proof of inclusion containing the leaf value.
type inclusionLeaf struct {
	proof [][]byte
	value []byte
}
