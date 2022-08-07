package transparency

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"

	"github.com/JumpPrivacy/katie/crypto/commitments"
	"github.com/JumpPrivacy/katie/crypto/vrf"
	"github.com/JumpPrivacy/katie/crypto/vrf/p256"
	"github.com/JumpPrivacy/katie/tree/log"
	"github.com/JumpPrivacy/katie/tree/prefix"
)

type idCtrPair struct {
	id  uint64
	ctr int
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
	last := -1
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
	if pg.sorted[smallest].ctr == -1 {
		return true, nil
	} else if smallest == 0 {
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
func (pg *proofGuide) insert(id uint64, ctr int) {
	pg.sorted = append(pg.sorted, idCtrPair{id, ctr})
}

// final returns the index that represents the final search result.
func (pg *proofGuide) final() int {
	smallest := len(pg.sorted) - 1
	for smallest > 0 && pg.sorted[smallest-1].ctr == pg.sorted[smallest].ctr {
		smallest--
	}
	if pg.sorted[smallest].ctr == -1 {
		return -1
	}
	for i := 0; i < len(pg.ids); i++ {
		if pg.ids[i] == pg.sorted[smallest].id {
			return i
		}
	}
	panic("unexpected error")
}

// LogConfig wraps the information that a client needs to know about a log.
type LogConfig struct {
	SigKey *ecdsa.PublicKey
	VrfKey vrf.PublicKey
}

type leafData struct {
	id    uint64
	value []byte
}

type leafSlice []leafData

func (ls leafSlice) Len() int           { return len(ls) }
func (ls leafSlice) Less(i, j int) bool { return ls[i].id < ls[j].id }
func (ls leafSlice) Swap(i, j int)      { ls[i], ls[j] = ls[j], ls[i] }

// Verify checks that the contents of SearchResult is valid.
func Verify(config *LogConfig, key string, sr *SearchResult) error {
	if int(sr.Root.TreeSize) <= 0 {
		return errors.New("invalid search result")
	}

	// Validate the VRF output.
	index, err := config.VrfKey.ProofToHash([]byte(key), sr.Vrf.Proof)
	if err != nil {
		return err
	} else if !bytes.Equal(index[:], sr.Vrf.Index) {
		return errors.New("vrf output is different than expected")
	}

	// Follow the search path in prefix trees.
	guide := newProofGuide(sr.Root.TreeSize)
	i := 0
	var leaves leafSlice
	for {
		if i > len(sr.Search) {
			return errors.New("not enough steps provided in search path")
		}
		done, err := guide.done()
		if err != nil {
			return err
		} else if done {
			break
		}
		id := guide.next()

		proot, err := prefix.Evaluate(index[:], sr.Search[i].Prefix)
		if err != nil {
			return err
		}
		leaf := new(bytes.Buffer)
		leaf.Write(proot)
		leaf.Write(sr.Search[i].Commitment)
		leaves = append(leaves, leafData{id, leafHash(leaf.Bytes())})

		guide.insert(id, sr.Search[i].Prefix.Counter())

		i++
	}
	if i < len(sr.Search) {
		return errors.New("search path is longer than expected")
	}

	// Compute the expected log root.
	sort.Sort(leaves)
	ids, values := make([]int, 0), make([][]byte, 0)
	for _, leaf := range leaves {
		ids = append(ids, int(leaf.id))
		values = append(values, leaf.value)
	}
	root, err := log.EvaluateBatchProof(ids, int(sr.Root.TreeSize), values, sr.Log)
	if err != nil {
		return err
	}

	// Validate the root signature.
	sigPub := config.SigKey
	vrfPub := config.VrfKey.(*p256.PublicKey).PublicKey

	tbs, err := json.Marshal(rootTbs{
		SignatureKey: elliptic.Marshal(sigPub.Curve, sigPub.X, sigPub.Y),
		VrfKey:       elliptic.Marshal(vrfPub.Curve, vrfPub.X, vrfPub.Y),
		TreeSize:     sr.Root.TreeSize,
		Timestamp:    sr.Root.Timestamp,
		Root:         root,
	})
	if err != nil {
		return err
	}
	tbsHash := sha256.Sum256(tbs)

	if ok := ecdsa.VerifyASN1(sigPub, tbsHash[:], sr.Root.Signature); !ok {
		return errors.New("signature on root failed to verify")
	}

	// Validate the commit opening.
	if i := guide.final(); i == -1 {
		if sr.Value != nil {
			return errors.New("expected no value")
		}
	} else {
		err := commitments.Verify(key, sr.Search[i].Commitment, sr.Value.Value, sr.Value.Opening)
		if err != nil {
			return err
		}
	}

	return nil
}

// TODO: Check timestamp in root.
// TODO: Monitoring code.
