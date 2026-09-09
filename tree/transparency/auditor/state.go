package auditor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// insertedVrfOutput pairs a VRF output that was recently inserted into the
// audited transparency log's prefix tree with the position in the log where it
// was inserted.
type insertedVrfOutput struct {
	pos       uint64
	vrfOutput []byte
}

// auditorState is the state of an Auditor that's persisted to a database.
type auditorState struct {
	treeHead     structs.AuditorTreeHead // Last tree head issued by auditor.
	fullSubtrees [][]byte                // Full subtrees of the log tree.
	timestamps   []uint64                // Timestamps of the log entries along the frontier.
	prefixTree   []byte                  // Prefix tree root hash of the rightmost log entry.

	inserted []insertedVrfOutput // List of recently-inserted VRF outputs.
}

func newAuditorState(cs suites.CipherSuite, buf *bytes.Buffer) (*auditorState, error) {
	treeHead, err := structs.NewAuditorTreeHead(buf)
	if err != nil {
		return nil, err
	}

	fullSubtrees := make([][]byte, bits.OnesCount64(treeHead.TreeSize))
	for i := range fullSubtrees {
		fullSubtree := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, fullSubtree); err != nil {
			return nil, err
		}
		fullSubtrees[i] = fullSubtree
	}

	timestamps := make([]uint64, len(math.Frontier(treeHead.TreeSize)))
	for i := range timestamps {
		var timestamp uint64
		if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
			return nil, err
		}
		timestamps[i] = timestamp
	}

	prefixTree := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, prefixTree); err != nil {
		return nil, err
	}

	var size uint32
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	inserted := make([]insertedVrfOutput, size)
	for i := range size {
		var pos uint64
		if err := binary.Read(buf, binary.BigEndian, &pos); err != nil {
			return nil, err
		}
		vrfOutput := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, vrfOutput); err != nil {
			return nil, err
		}
		inserted[i] = insertedVrfOutput{pos, vrfOutput}
	}

	return &auditorState{
		treeHead:     *treeHead,
		fullSubtrees: fullSubtrees,
		timestamps:   timestamps,
		prefixTree:   prefixTree,

		inserted: inserted,
	}, nil
}

func (as *auditorState) Marshal() ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := as.treeHead.Marshal(buf); err != nil {
		return nil, err
	}
	for _, subtree := range as.fullSubtrees {
		buf.Write(subtree)
	}
	for _, timestamp := range as.timestamps {
		binary.Write(buf, binary.BigEndian, timestamp)
	}
	buf.Write(as.prefixTree)

	if int64(len(as.inserted)) >= int64(1)<<32 {
		return nil, errors.New("inserted vrf outputs slice is too long to marshal")
	}
	binary.Write(buf, binary.BigEndian, uint32(len(as.inserted)))
	for _, inserted := range as.inserted {
		binary.Write(buf, binary.BigEndian, inserted.pos)
		buf.Write(inserted.vrfOutput)
	}

	return buf.Bytes(), nil
}

// addedSince returns true if `vrfOutput` was added to the prefix tree after the
// log entry `x` was published.
func (as *auditorState) addedSince(x uint64, vrfOutput []byte) bool {
	if as == nil {
		return true // TODO: Is this right?
	}
	target := insertedVrfOutput{vrfOutput: vrfOutput}
	i, found := slices.BinarySearchFunc(as.inserted, target, compareInserted)
	if !found {
		return false
	}
	return as.inserted[i].pos > x
}

func compareEntry(a, b prefix.Entry) int {
	return bytes.Compare(a.VrfOutput, b.VrfOutput)
}

func compareInserted(a, b insertedVrfOutput) int {
	return bytes.Compare(a.vrfOutput, b.vrfOutput)
}

// mergeInserted returns the new set of recently-inserted VRF outputs to retain:
// those already retained + the VRF outputs added in the most recent log entry,
// filtering out any that have been published in a distinguished log entry.
func mergeInserted(existing, added []insertedVrfOutput, rightmost *uint64) []insertedVrfOutput {
	out := make([]insertedVrfOutput, 0, len(existing)+len(added))

	i, j := 0, 0
	for i < len(existing) && j < len(added) {
		// Filter out elements from either slice that are too old.
		if rightmost != nil {
			if existing[i].pos <= *rightmost {
				i++
				continue
			} else if added[j].pos <= *rightmost {
				j++
				continue
			}
		}
		// Append the lesser VRF output to our output slice.
		switch compareInserted(existing[i], added[j]) {
		case -1:
			out = append(out, existing[i])
			i++
		case 0:
			out = append(out, added[j])
			i++
			j++
		case 1:
			out = append(out, added[j])
			j++
		}
	}
	for ; i < len(existing); i++ {
		if rightmost == nil || existing[i].pos > *rightmost {
			out = append(out, existing[i])
		}
	}
	for ; j < len(added); j++ {
		if rightmost == nil || added[j].pos > *rightmost {
			out = append(out, added[j])
		}
	}

	return out
}
