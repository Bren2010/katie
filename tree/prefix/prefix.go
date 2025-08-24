// Package prefix implements a Prefix Tree that supports versioning and batch
// searches and insertions.
package prefix

import (
	"errors"
	"sort"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
)

func getBit(data []byte, bit int) bool {
	return (data[bit/8]>>(7-(bit%8)))&1 == 1
}

type nextStep struct {
	id  tileId
	ptr *node
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

		case parentNode:
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

type batch struct {
	cs suites.CipherSuite
	tx db.PrefixStore
}

func (b *batch) get(nextSteps map[int]nextStep) (map[string]tile, error) {
	dedup := make(map[string]tileId)
	for _, step := range nextSteps {
		dedup[step.id.String()] = step.id
	}

	keys := make([]string, 0, len(dedup))
	for key := range dedup {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	data, err := b.tx.BatchGet(keys) // TODO: In-fill from cache.
	if err != nil {
		return nil, err
	}

	out := make(map[string]tile)
	for key, id := range dedup {
		val, ok := data[key]
		if !ok {
			return nil, errors.New("not all expected data was found")
		}
		out[key], err = unmarshalTile(b.cs, id, val)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (b *batch) search(nd *node, cursors []cursor) error {
	nextSteps := make(map[int]nextStep)
	for i, cursor := range cursors {
		if res := cursor.step(nd); res != nil {
			nextSteps[i] = *res
		}
	}

	tiles, err := b.get(nextSteps)
	if err != nil {
		return err
	}

	recursions := make(map[*node][]cursor)
	for i, step := range nextSteps {
		cursor := cursors[i]
		t := tiles[step.id.String()]

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

		recursions[n] = append(recursions[n], cursor)
	}

	for nd, cursors := range recursions {
		if err := b.search(nd, cursors); err != nil {
			return err
		}
	}

	return nil
}
