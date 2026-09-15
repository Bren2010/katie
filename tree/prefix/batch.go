package prefix

import (
	"errors"

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
	cache map[tileId]*tile
}

func newBatch(cs suites.CipherSuite, tx db.PrefixStore) *batch {
	return &batch{cs, tx, make(map[tileId]*tile)}
}

// initialize creates the initial state object to call search with, and creates
// a map from each searched version of the Prefix Tree to a tile where the
// result for that version will be stored.
func (b *batch) initialize(searches map[uint64][][]byte) (map[uint64]*tile, map[*node][]cursor) {
	tiles := make(map[uint64]*tile, len(searches))
	state := make(map[*node][]cursor, len(searches))

	for ver, vrfOutputs := range searches {
		id := tileId{ver: ver, ctr: 0}
		out := &tile{id: id, depth: 0, root: externalNode{nil, id}}
		if ver == 0 {
			// Version 0 of the tree is empty and isn't stored in the database,
			// so searches of it terminate immediately.
			out.root = emptyNode{}
		}
		tiles[ver] = out

		cursors := make([]cursor, len(vrfOutputs))
		for i, vrfOutput := range vrfOutputs {
			cursors[i] = cursor{vrfOutput: vrfOutput, depth: 0}
		}
		state[&out.root] = cursors
	}

	return tiles, state
}

// get looks up the tiles that will be needed to execute the provided next
// search steps. It returns a map from tile id to parsed tile.
func (b *batch) get(nextSteps map[*cursor]nextStep) (map[tileId]*tile, error) {
	out := make(map[tileId]*tile)

	dedup := make(map[tileId]struct{})
	for _, step := range nextSteps {
		dedup[step.id] = struct{}{}
	}
	ids := make([]tileId, 0, len(dedup))
	for id := range dedup {
		if t, ok := b.cache[id]; ok {
			out[id] = t
		} else {
			ids = append(ids, id)
		}
	}
	if len(out) > 0 {
		// If we find anything in cache at all, return this right away. We only
		// want to do database requests when required for all active searches.
		return out, nil
	}

	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = id.String()
	}
	data, err := b.tx.BatchGet(keys)
	if err != nil {
		return nil, err
	}

	for i, id := range ids {
		if data[i] == nil {
			return nil, errors.New("not all expected data was found")
		}
		t, err := unmarshalTile(b.cs, id, data[i])
		if err != nil {
			return nil, err
		}
		out[id], b.cache[id] = &t, &t
	}
	return out, nil
}

// search takes a mapping from some nodes, to a list of searches that are
// currently active on those nodes. It moves each search as far as possible
// within each node, identifies which tiles will be needed next, and initiates
// looking them up for the next search iteration.
func (b *batch) search(state map[*node][]cursor) error {
	nextSteps := make(map[*cursor]nextStep)
	for nd, cursors := range state {
		for i := range cursors {
			if res := cursors[i].step(nd); res != nil {
				nextSteps[&cursors[i]] = *res
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
		t, ok := tiles[step.id]
		if !ok {
			nextState[step.ptr] = append(nextState[step.ptr], *cursor)
			continue
		}

		// Recurse down within the tile until we reach the desired depth.
		if t.depth > cursor.depth {
			return errors.New("tile does not fit into search as expected")
		}
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
		nextState[step.ptr] = append(nextState[step.ptr], *cursor)
	}

	return b.search(nextState)
}
