package transparency

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func logEntryHash(cs suites.CipherSuite, entry structs.LogEntry) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := entry.Marshal(buf); err != nil {
		return nil, err
	}

	hasher := cs.Hash()
	hasher.Write(buf.Bytes())
	return hasher.Sum(nil), nil
}

// getLabelIndex returns the index (the list of log entries where each new
// version was added) of a given label.
//
// The index is stored as an encoded series of uvarints. For compression, only
// the difference between each subsequent entry is stored.
func (t *Tree) getLabelIndex(label []byte) ([]uint64, error) {
	raw, err := t.tx.GetLabelIndex(label)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(raw)

	index := make([]uint64, 0)
	for {
		pos, err := binary.ReadUvarint(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		index = append(index, pos)
	}

	for i := 1; i < len(index); i++ {
		index[i] += index[i-1]
	}
	return index, nil
}

// setLabelIndex updates the stored index of the label.
func (t *Tree) setLabelIndex(label []byte, index []uint64) error {
	for i := len(index) - 1; i > 0; i-- {
		if index[i] < index[i-1] {
			return errors.New("list of label-version positions is not monotonic")
		}
		index[i] -= index[i-1]
	}

	buf := &bytes.Buffer{}
	for _, pos := range index {
		temp := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(temp, pos)
		buf.Write(temp[:n])
	}

	return t.tx.SetLabelIndex(label, buf.Bytes())
}

// getLabelValue returns the commitment opening and the value of the requested
// label-version pair.
func (t *Tree) getLabelValue(label []byte, ver uint32) (*structs.LabelValue, error) {
	raw, err := t.tx.GetLabelValue(label, ver)
	if err != nil {
		return nil, err
	} else if raw == nil {
		// Returning a zero value for the commitment opening ensures that the
		// SearchResponse doesn't end up getting serialized wrong when a search
		// produces a non-inclusion proof.
		size := t.config.Suite.CommitmentOpeningSize()
		return &structs.LabelValue{Opening: make([]byte, size)}, nil
	}
	return structs.NewLabelValue(t.config.Public(), bytes.NewBuffer(raw))
}

// setLabelValue generates a new commitment opening and sets the given
// label-version pair to the given value. It returns the new commitment.
func (t *Tree) setLabelValue(label []byte, ver uint32, value structs.UpdateValue) ([]byte, error) {
	opening := commitments.GenerateOpening(t.config.Suite)

	// Serialize opening and UpdateValue structure. Write to database.
	labelValue := structs.LabelValue{Opening: opening, Value: value}
	buf := &bytes.Buffer{}
	if err := labelValue.Marshal(buf); err != nil {
		return nil, err
	} else if err := t.tx.SetLabelValue(label, ver, buf.Bytes()); err != nil {
		return nil, err
	}

	// Serialize the data that will be committed to and compute the commitment.
	commitmentValue := structs.CommitmentValue{Label: label, Update: value}
	buf.Reset()
	if err := commitmentValue.Marshal(buf); err != nil {
		return nil, err
	}
	return commitments.Commit(t.config.Suite, opening, buf.Bytes()), nil
}

// computeVrfOutput returns the VRF output for the requested label-version pair
// and the proof that the output is correct.
func (t *Tree) computeVrfOutput(label []byte, ver uint32) (vrfOutput, proof []byte, err error) {
	input := structs.VrfInput{Label: label, Version: ver}
	buf := &bytes.Buffer{}
	if err := input.Marshal(buf); err != nil {
		return nil, nil, err
	}
	vrfOutput, proof = t.config.VrfKey.Prove(buf.Bytes())
	return
}

type posAndVersions struct {
	pos  uint64
	vers []uint32
}

type versionTracker struct {
	inclusion, nonInclusion []posAndVersions
}

func (vt *versionTracker) AddResults(x uint64, omit bool, ladder []uint32, results []prefix.PrefixSearchResult) {
	if !omit {
		return
	}

	var inclusion, nonInclusion []uint32
	for i, res := range results {
		if res.Inclusion() {
			inclusion = append(inclusion, ladder[i])
		} else {
			nonInclusion = append(nonInclusion, ladder[i])
		}
	}
	vt.inclusion = append(vt.inclusion, posAndVersions{pos: x, vers: inclusion})
	vt.nonInclusion = append(vt.nonInclusion, posAndVersions{pos: x, vers: nonInclusion})
}

func (vt *versionTracker) AddLadder(x uint64, omit bool, greatest int, ladder []uint32) {
	if !omit {
		return
	}

	var inclusion, nonInclusion []uint32
	for _, version := range ladder {
		if int(version) <= greatest {
			inclusion = append(inclusion, version)
		} else {
			nonInclusion = append(nonInclusion, version)
		}
	}
	vt.inclusion = append(vt.inclusion, posAndVersions{pos: x, vers: inclusion})
	vt.nonInclusion = append(vt.nonInclusion, posAndVersions{pos: x, vers: nonInclusion})
}

func (vt *versionTracker) SearchMaps(x uint64, omit bool) (leftInclusion, rightNonInclusion map[uint32]struct{}) {
	if !omit {
		return
	}

	leftInclusion = make(map[uint32]struct{})
	for _, entry := range vt.inclusion {
		if entry.pos < x {
			for _, ver := range entry.vers {
				leftInclusion[ver] = struct{}{}
			}
		}
	}
	rightNonInclusion = make(map[uint32]struct{})
	for _, entry := range vt.nonInclusion {
		if entry.pos > x {
			for _, ver := range entry.vers {
				rightNonInclusion[ver] = struct{}{}
			}
		}
	}
	return
}

func (vt *versionTracker) MonitoringMap(x uint64) (leftInclusion map[uint32]struct{}) {
	parents := make(map[uint64]struct{})
	for _, parent := range math.LeftDirectPath(x) {
		parents[parent] = struct{}{}
	}

	leftInclusion = make(map[uint32]struct{})
	for _, entry := range vt.inclusion {
		if _, ok := parents[entry.pos]; ok {
			for _, ver := range entry.vers {
				leftInclusion[ver] = struct{}{}
			}
		}
	}
	return
}
