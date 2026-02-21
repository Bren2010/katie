package transparency

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// batchGetIndex returns the index (the list of log entries where each new
// version was added) of each of the given labels.
//
// The index is stored as an encoded series of uvarints. For compression, only
// the difference between each subsequent entry is stored.
func (t *Tree) batchGetIndex(labels [][]byte) ([][]uint64, error) {
	rawIndices, err := t.tx.BatchGetIndex(labels)
	if err != nil {
		return nil, err
	}

	out := make([][]uint64, len(rawIndices))
	for i, raw := range rawIndices {
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

		out[i] = index
	}

	return out, nil
}

// putIndex updates the stored index of the label.
func (t *Tree) putIndex(label []byte, index []uint64) error {
	compressed := make([]uint64, len(index))
	copy(compressed, index)
	for i := len(compressed) - 1; i > 0; i-- {
		if compressed[i] < compressed[i-1] {
			return errors.New("list of label-version positions is not monotonic")
		}
		compressed[i] -= compressed[i-1]
	}

	buf := &bytes.Buffer{}
	for _, pos := range compressed {
		temp := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(temp, pos)
		buf.Write(temp[:n])
	}

	return t.tx.PutIndex(label, buf.Bytes())
}

// getVersion returns the commitment opening and the value of the requested
// label-version pair.
func (t *Tree) getVersion(label []byte, ver uint32) (*structs.LabelValue, error) {
	raw, err := t.tx.GetVersion(label, ver)
	if err != nil {
		return nil, err
	} else if raw == nil {
		// Returning a zero value for the commitment opening ensures that the
		// SearchResponse doesn't end up getting serialized wrong when a search
		// produces a non-inclusion proof.
		size := t.config.Suite.CommitmentOpeningSize()
		return &structs.LabelValue{Opening: make([]byte, size)}, nil
	}
	buf := bytes.NewBuffer(raw)
	labelValue, err := structs.NewLabelValue(t.config.Public(), buf)
	if err != nil {
		return nil, err
	} else if buf.Len() != 0 {
		return nil, errors.New("unexpected data appended to label value")
	}
	return labelValue, nil
}

// putVersion generates a new commitment opening and sets the given
// label-version pair to the given value. It returns the new commitment.
func (t *Tree) putVersion(label []byte, ver uint32, value structs.UpdateValue) ([]byte, error) {
	opening := commitments.GenerateOpening(t.config.Suite)

	// Serialize opening and UpdateValue structure. Write to database.
	labelValue, err := structs.Marshal(&structs.LabelValue{Opening: opening, Value: value})
	if err != nil {
		return nil, err
	} else if err := t.tx.PutVersion(label, ver, labelValue); err != nil {
		return nil, err
	}

	// Serialize the data that will be committed to and compute the commitment.
	commitmentValue, err := structs.Marshal(&structs.CommitmentValue{
		Label:   label,
		Version: ver,
		Update:  value,
	})
	if err != nil {
		return nil, err
	}
	return commitments.Commit(t.config.Suite, opening, commitmentValue), nil
}

// computeVrfOutput returns the VRF output for the requested label-version pair
// and the proof that the output is correct.
func (t *Tree) computeVrfOutput(label []byte, ver uint32) (vrfOutput, proof []byte, err error) {
	input, err := structs.Marshal(&structs.VrfInput{Label: label, Version: ver})
	if err != nil {
		return nil, nil, err
	}
	vrfOutput, proof = t.config.VrfKey.Prove(input)
	return
}
