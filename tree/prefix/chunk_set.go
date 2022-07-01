package prefix

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

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
		prefix, err := parsePrefix(id)
		if err != nil {
			return nil, err
		}
		chunk, err := newPrefixChunk(len(id)%2 == 1, prefix, data)
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
	fullKey := hex.EncodeToString(key)
	proof := make([][]byte, 0)

	for i := 0; i < len(fullKey); i++ {
		chunk, ok := s.chunks[id]
		if !ok {
			if i == 0 { // The root doesn't exist yet which is fine.
				return nil, nil
			} // An intermediate doesn't exist.
			return nil, fmt.Errorf("expected chunk was not found")
		}

		b := getNextNibble(key, len(chunk.prefix), chunk.half)
		proof = append(proof, chunk.proof(b)...)

		elem, ok := chunk.elems[b]
		if !ok {
			return nonInclusionParent{proof: proof}, nil
		} else if elem.typ == leafNode {
			cand := buildKey(chunk.prefix, b, elem.inner, chunk.half)

			if bytes.Equal(key, cand) {
				return inclusionProof{proof: proof}, nil
			}
			return nonInclusionLeaf{
				proof:  proof,
				suffix: elem.inner,
			}, nil
		} else if elem.typ == parentNode {
			id = fullKey[0 : i+1]
		} else {
			panic("unreachable")
		}
	}

	panic("unexpected error condition")
}

// insert executes a search for `key` in the tree and adds it if it doesn't
// already exist.
func (s *chunkSet) insert(key []byte) ([]byte, error) {
	if _, ok := s.chunks["root"]; !ok {
		s.chunks["root"] = newEmptyChunk(make([]byte, 0))
	}
	return s._insert("root", key)
}

func (s *chunkSet) _insert(id string, key []byte) ([]byte, error) {
	chunk := s.chunks[id]
	b := getNextNibble(key, len(chunk.prefix), chunk.half)
	elem, ok := chunk.elems[b]
	if !ok {
		// This nibble isn't already in the chunk so we can just add it.
		chunk.elems[b] = &treeNode{
			typ:   leafNode,
			inner: buildSuffix(key, len(chunk.prefix), chunk.half),
		}
	} else if elem.typ == leafNode {
		// Reconstruct the key that's here already.
		oldKey := buildKey(chunk.prefix, b, elem.inner, chunk.half)

		// Check that the new key is different from what's already here to
		// avoid inserting a duplicate.
		if !bytes.Equal(key, oldKey) {
			newPrefix, newId := buildPrefix(chunk.prefix, b, chunk.half)
			if _, ok := s.chunks[newId]; ok {
				return nil, fmt.Errorf("chunk should not exist yet")
			}
			s.chunks[newId] = newEmptyChunk(newPrefix)

			// Add the old key to the chunk.
			if _, err := s._insert(newId, oldKey); err != nil {
				return nil, err
			}
			// Add the new key.
			h, err := s._insert(newId, key)
			if err != nil {
				return nil, err
			}

			chunk.elems[b] = &treeNode{typ: parentNode, inner: h}
		}
	} else if elem.typ == parentNode {
		_, newId := buildPrefix(chunk.prefix, b, chunk.half)
		h, err := s._insert(newId, key)
		if err != nil {
			return nil, err
		}
		chunk.elems[b] = &treeNode{typ: parentNode, inner: h}
	} else {
		panic("unreachable")
	}

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
