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

// InsertedVrfOutput pairs a VRF output that was recently inserted into the
// audited transparency log's prefix tree with the position in the log where it
// was inserted.
type InsertedVrfOutput struct {
	Pos       uint64
	VrfOutput []byte
}

// AuditorState is the state of an Auditor that's persisted to a database.
type AuditorState struct {
	TreeHead     structs.AuditorTreeHead
	FullSubtrees [][]byte
	Timestamps   []uint64
	PrefixTree   []byte

	Inserted []InsertedVrfOutput
}

func NewAuditorState(cs suites.CipherSuite, buf *bytes.Buffer) (*AuditorState, error) {
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

	var size uint16
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	inserted := make([]InsertedVrfOutput, size)
	for i := range size {
		var pos uint64
		if err := binary.Read(buf, binary.BigEndian, &pos); err != nil {
			return nil, err
		}
		vrfOutput := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, vrfOutput); err != nil {
			return nil, err
		}
		inserted[i] = InsertedVrfOutput{Pos: pos, VrfOutput: vrfOutput}
	}

	return &AuditorState{
		TreeHead:     *treeHead,
		FullSubtrees: fullSubtrees,
		Timestamps:   timestamps,
		PrefixTree:   prefixTree,

		Inserted: inserted,
	}, nil
}

func (as *AuditorState) Marshal() ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := as.TreeHead.Marshal(buf); err != nil {
		return nil, err
	}
	for _, subtree := range as.FullSubtrees {
		buf.Write(subtree)
	}
	for _, timestamp := range as.Timestamps {
		binary.Write(buf, binary.BigEndian, timestamp)
	}
	buf.Write(as.PrefixTree)

	if len(as.Inserted) >= (1 << 16) {
		return nil, errors.New("inserted vrf outputs is too long to marshal")
	}
	binary.Write(buf, binary.BigEndian, uint16(len(as.Inserted)))
	for _, inserted := range as.Inserted {
		binary.Write(buf, binary.BigEndian, inserted.Pos)
		buf.Write(inserted.VrfOutput)
	}

	return buf.Bytes(), nil
}

// AddedSince returns true if `vrfOutput` was added to the prefix tree after the
// log entry `x` was published.
func (as *AuditorState) addedSince(x uint64, vrfOutput []byte) bool {
	if as == nil {
		return true
	}
	target := InsertedVrfOutput{VrfOutput: vrfOutput}
	i, found := slices.BinarySearchFunc(as.Inserted, target, compareInserted)
	if !found {
		return false
	}
	return as.Inserted[i].Pos > x
}

func compareEntry(a, b prefix.Entry) int {
	return bytes.Compare(a.VrfOutput, b.VrfOutput)
}

func compareInserted(a, b InsertedVrfOutput) int {
	return bytes.Compare(a.VrfOutput, b.VrfOutput)
}

// mergeInserted returns the new set of recently-inserted VRF outputs to retain:
// those already retained + the VRF outputs added in the most recent log entry,
// filtering out any that have been published in a distinguished log entry.
func mergeInserted(existing, added []InsertedVrfOutput, rightmost *uint64) []InsertedVrfOutput {
	out := make([]InsertedVrfOutput, 0, len(existing)+len(added))

	i, j := 0, 0
	for i < len(existing) && j < len(added) {
		// Filter out elements from either slice that are too old.
		if rightmost != nil {
			if existing[i].Pos <= *rightmost {
				i++
				continue
			} else if added[j].Pos <= *rightmost {
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
		if rightmost == nil || existing[i].Pos > *rightmost {
			out = append(out, existing[i])
		}
	}
	for ; j < len(added); j++ {
		if rightmost == nil || added[j].Pos > *rightmost {
			out = append(out, added[j])
		}
	}

	return out
}
