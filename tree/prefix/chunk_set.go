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
				return inclusionLeaf{
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
func (s *chunkSet) insert(key, value []byte) ([]byte, error) {
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
				h, err := s._insert(newId, key, value)
				if err != nil {
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
