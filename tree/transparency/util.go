package transparency

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
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
		index := make([]uint64, 0)

		buf := bytes.NewBuffer(raw)
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

// getIndex is the single-lookup version of batchGetIndex.
func (t *Tree) getIndex(label []byte) ([]uint64, error) {
	indices, err := t.batchGetIndex([][]byte{label})
	if err != nil {
		return nil, err
	}
	return indices[0], nil
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

	t.tx.PutIndex(label, buf.Bytes())
	return nil
}

// batchGetVersion returns the commitment opening and value of the requested
// versions of the label.
func (t *Tree) batchGetVersion(label []byte, vers []uint32) ([]structs.OpeningAndValue, error) {
	results, err := t.tx.BatchGetVersion(label, vers)
	if err != nil {
		return nil, err
	}

	out := make([]structs.OpeningAndValue, len(results))
	for i, raw := range results {
		if raw == nil {
			return nil, algorithms.ErrLabelNotFound
		}
		parsed, err := structs.UnmarshalWith(raw, structs.NewOpeningAndValue, t.config.Public())
		if err != nil {
			return nil, err
		}
		out[i] = *parsed
	}

	return out, nil
}

// getVersion is the single-lookup version of batchGetVersion.
func (t *Tree) getVersion(label []byte, ver uint32) (*structs.OpeningAndValue, error) {
	res, err := t.batchGetVersion(label, []uint32{ver})
	if err != nil {
		return nil, err
	}
	return &res[0], nil
}

// putVersion generates a new commitment opening and sets the given
// label-version pair to the given value. It returns the new commitment.
func (t *Tree) putVersion(label []byte, ver uint32, value structs.UpdateValue) ([]byte, error) {
	opening := commitments.GenerateOpening(t.config.Suite)

	// Serialize opening and UpdateValue structure. Write to database.
	labelValue, err := structs.Marshal(&structs.OpeningAndValue{Opening: opening, Value: value})
	if err != nil {
		return nil, err
	}
	t.tx.PutVersion(label, ver, labelValue)

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
func (t *Tree) computeVrfOutput(label []byte, ver uint32) ([]byte, []byte, error) {
	input, err := structs.Marshal(&structs.VrfInput{Label: label, Version: ver})
	if err != nil {
		return nil, nil, err
	}
	vrfOutput, proof := t.config.VrfKey.Prove(input)
	return vrfOutput, proof, nil
}

// getBinaryLadder returns the binary ladder steps corresponding to the
// requested versions and the VRF output for each version. `label` is the label
// that the binary ladder is for, and `greatest` is the greatest version of
// `label` that exists as of log entry `x` (or -1 if none).
//
// The commitment for each version up to `greatest` is looked up in the prefix
// tree of log entry `x`.
func (t *Tree) getBinaryLadder(
	label []byte,
	versions []uint32,
	greatest int64,
	x uint64,
) ([]structs.BinaryLadderStep, [][]byte, error) {
	var (
		// Contains the VRF output for each version.
		vrfOutputs = make([][]byte, len(versions))

		// Contains the index in `versions` of each version that exists, and
		// the VRF output for each. Used to lookup the commitment to the
		// label's value at those versions.
		existing        []int
		existingOutputs [][]byte

		// Contains the list of BinaryLadderStep structures to output.
		out = make([]structs.BinaryLadderStep, len(versions))
	)
	for i, ver := range versions {
		vrfOutput, proof, err := t.computeVrfOutput(label, ver)
		if err != nil {
			return nil, nil, err
		}
		if int64(ver) <= greatest { // Only look up existing versions.
			existing = append(existing, i)
			existingOutputs = append(existingOutputs, vrfOutput)
		}
		vrfOutputs[i] = vrfOutput
		out[i].Proof = proof
	}

	// Search the prefix tree to learn the value commitment for versions that we
	// expect to exist.
	if len(existing) == 0 {
		return out, vrfOutputs, nil
	}
	prefixTree := prefix.NewTree(t.config.Suite, t.tx.PrefixStore())
	results, err := prefixTree.Search([]prefix.PrefixSearch{{
		Version:    x + 1,
		VrfOutputs: existingOutputs,
	}})
	if err != nil {
		return nil, nil, err
	}
	for i, commitment := range results[0].Commitments {
		if commitment == nil {
			return nil, nil, errors.New("expected version of label not found in prefix tree")
		}
		out[existing[i]].Commitment = commitment
	}

	return out, vrfOutputs, nil
}

// verifyServiceSignature verifies a leaf signature from the Service Operator.
// This method is only used in Third-Party Management mode.
func (t *Tree) verifyServiceSignature(label []byte, signedVer uint32, val structs.UpdateValue) error {
	tbs, err := structs.Marshal(&structs.UpdateTBS{
		Config:  t.config.Public(),
		Label:   label,
		Version: signedVer,
		Value:   val.Value,
	})
	if err != nil {
		return err
	}
	ok := t.config.LeafPublicKey.Verify(tbs, val.Signature)
	if !ok {
		return errors.New("leaf signature verification failed")
	}
	return nil
}
