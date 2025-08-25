package prefix

import (
	"bytes"
	"errors"
	"slices"
	"sort"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
)

func getBit(data []byte, bit int) bool {
	return (data[bit/8]>>(7-(bit%8)))&1 == 1
}

// nextStep represents the next step of a search.
type nextStep struct {
	id  tileId // The tile id that needs to be loaded to continue search.
	ptr *node  // Pointer to the node where the search terminated.
}

// cursor represents an in-progress search for a single VRF output.
type cursor struct {
	vrfOutput []byte // The VRF output being searched for.
	depth     int    // The current depth of the search.
}

// step executes the next step in a search.
func (c *cursor) step(n *node) *nextStep {
	for {
		switch m := (*n).(type) {
		case emptyNode, leafNode:
			return nil

		case *parentNode:
			if getBit(c.vrfOutput, c.depth) {
				n = &m.right
			} else {
				n = &m.left
			}
			c.depth++

		case externalNode:
			return &nextStep{id: m.id, ptr: n}

		default:
			panic("unexpected node type found")
		}
	}
}

// batch implements a batch search algorithm. It does not directly produce
// proofs, it only ensures that all necessary information is in-memory.
type batch struct {
	cs    suites.CipherSuite
	tx    db.PrefixStore
	cache map[string]tile
}

func newBatch(cs suites.CipherSuite, tx db.PrefixStore) *batch {
	return &batch{cs: cs, tx: tx, cache: make(map[string]tile)}
}

// initialize creates the initial state object to call search with, and creates
// a slice of tiles where the results will be stored.
func (b *batch) initialize(searches map[uint64][][]byte) ([]tile, map[*node][]cursor) {
	vers := make([]uint64, 0, len(searches))
	for ver := range searches {
		vers = append(vers, ver)
	}
	slices.Sort(vers)

	tiles := make([]tile, 0, len(searches))
	state := make(map[*node][]cursor, len(searches))
	for _, ver := range vers {
		id := tileId{ver: ver, ctr: 0}
		tiles = append(tiles, tile{id: id, depth: 0, root: externalNode{nil, id}})

		vrfOutputs := searches[ver]
		slices.SortFunc(vrfOutputs, bytes.Compare)

		cursors := make([]cursor, 0, len(vrfOutputs))
		for _, vrfOutput := range vrfOutputs {
			cursors = append(cursors, cursor{vrfOutput: vrfOutput, depth: 0})
		}
		state[&tiles[len(tiles)-1].root] = cursors
	}

	return tiles, state
}

// get looks up the tiles that will be needed to execute the provided next
// search steps. It returns a map from serialized tile id to parsed tile.
func (b *batch) get(nextSteps map[*cursor]nextStep) (map[string]tile, error) {
	out := make(map[string]tile)

	dedup := make(map[string]tileId)
	for _, step := range nextSteps {
		dedup[step.id.String()] = step.id
	}
	keys := make([]string, 0, len(dedup))
	for key := range dedup {
		if t, ok := b.cache[key]; ok {
			out[key] = t
		} else {
			keys = append(keys, key)
		}
	}
	if len(out) > 0 {
		// If we find anything in cache at all, return this right away. We only
		// want to do database requests when required for all active searches.
		return out, nil
	}
	sort.Strings(keys)

	data, err := b.tx.BatchGet(keys)
	if err != nil {
		return nil, err
	}

	for key, id := range dedup {
		val, ok := data[key]
		if !ok {
			return nil, errors.New("not all expected data was found")
		}
		t, err := unmarshalTile(b.cs, id, val)
		if err != nil {
			return nil, err
		}
		out[key], b.cache[key] = t, t
	}
	return out, nil
}

// search takes a mapping from some nodes, to a list of searches that are
// currently active on those nodes. It moves each search as far as possible
// within each node, identifies which tiles will be need next, and initiates
// looking them up for the next search iteration.
func (b *batch) search(state map[*node][]cursor) error {
	nextSteps := make(map[*cursor]nextStep)
	for nd, cursors := range state {
		for _, cursor := range cursors {
			if res := cursor.step(nd); res != nil {
				nextSteps[&cursor] = *res
			}
		}
	}
	if len(nextSteps) == 0 {
		return nil
	}

	tiles, err := b.get(nextSteps)
	if err != nil {
		return err
	} else if len(tiles) == 0 {
		return errors.New("no tiles were successfully fetched")
	}

	nextState := make(map[*node][]cursor)
	for cursor, step := range nextSteps {
		t, ok := tiles[step.id.String()]
		if !ok {
			nextState[step.ptr] = append(nextState[step.ptr], *cursor)
			continue
		}

		// Recurse down within the tile until we reach the desired depth.
		n := &t.root
		for i := range cursor.depth - t.depth {
			switch m := (*n).(type) {
			case *parentNode:
				if getBit(cursor.vrfOutput, t.depth+i) {
					n = &m.right
				} else {
					n = &m.left
				}
			default:
				return errors.New("unexpected node found in search path")
			}
		}

		// Replace the node where the search terminated with the new subtree
		// that was just looked up. Setup cursor for next iteration.
		*step.ptr = *n
		nextState[n] = append(nextState[n], *cursor)
	}

	return b.search(nextState)
}
