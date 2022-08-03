package transparency

import (
	"errors"
	"sort"
)

type idCtrPair struct {
	id  uint64
	ctr uint32
}

type idCtrSlice []idCtrPair

func (s idCtrSlice) Len() int           { return len(s) }
func (s idCtrSlice) Less(i, j int) bool { return s[i].id < s[j].id }
func (s idCtrSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type proofGuide struct {
	ids    []uint64
	sorted idCtrSlice
}

func newProofGuide(n uint64) *proofGuide {
	// Build the initial set of ids to check.
	ids := []uint64{n - 1}
	for {
		id := ids[len(ids)-1]
		id -= id & (^(id - 1)) // Clear lowest bit.
		if id == 0 {
			break
		} else {
			ids = append(ids, id)
		}
	}
	// Reverse the slice so its sorted.
	for i := 0; i < len(ids)/2; i++ {
		ids[i], ids[len(ids)-i-1] = ids[len(ids)-i-1], ids[i]
	}

	return &proofGuide{ids: ids}
}

// done returns true if the search proof is finished.
func (pg *proofGuide) done() (bool, error) {
	if len(pg.ids) > len(pg.sorted) {
		return false, nil
	}
	sort.Sort(pg.sorted)

	// Check that the list of counters is monotonic.
	last := uint32(0)
	for i := 0; i < len(pg.sorted); i++ {
		if pg.sorted[i].ctr < last {
			return false, errors.New("set of counters given is not monotonic")
		}
		last = pg.sorted[i].ctr
	}

	// Find the smallest id for which the counter is the max.
	smallest := len(pg.sorted) - 1
	for smallest > 0 && pg.sorted[smallest-1].ctr == pg.sorted[smallest].ctr {
		smallest--
	}

	// Determine the next id to check.
	if smallest == 0 {
		if pg.sorted[0].id == 0 {
			return true, nil
		}
		pg.ids = append(pg.ids, pg.sorted[0].id/2)
	} else if pg.sorted[smallest-1].id+1 == pg.sorted[smallest].id {
		return true, nil
	} else {
		id := (pg.sorted[smallest-1].id + pg.sorted[smallest].id) / 2
		pg.ids = append(pg.ids, id)
	}
	return false, nil
}

// next returns the next id to fetch from the database.
func (pg *proofGuide) next() uint64 { return pg.ids[len(pg.sorted)] }

// insert adds an id-counter pair to the guide.
func (pg *proofGuide) insert(id uint64, ctr uint32) {
	pg.sorted = append(pg.sorted, idCtrPair{id, ctr})
}

// final returns the id that represents the final search result.
func (pg *proofGuide) final() uint64 {
	smallest := len(pg.sorted) - 1
	for smallest > 0 && pg.sorted[smallest-1].ctr == pg.sorted[smallest].ctr {
		smallest--
	}
	return pg.sorted[smallest].id
}
