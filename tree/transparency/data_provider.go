package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

type innerDataProvider interface {
	ConsumeTimestamp() (uint64, error)
	ConsumePrefixProof() (*prefix.PrefixProof, error)
}

func addTimestamp(collection map[uint64]uint64, pos1, ts1 uint64) error {
	for pos2, ts2 := range collection {
		if pos1 == pos2 {
			return errors.New("can not insert same timestamp multiple times")
		} else if pos1 < pos2 && ts1 > ts2 || pos1 > pos2 && ts1 < ts2 {
			return errors.New("timestamps are not monotonic")
		}
	}
	collection[pos1] = ts1
	return nil
}

func addPrefixTree(collection map[uint64][]byte, pos uint64, root []byte) error {
	existing, ok := collection[pos]
	if ok && !bytes.Equal(root, existing) {
		return errors.New("conflicting values for prefix tree root hash found")
	} else if !ok {
		collection[pos] = root
	}
	return nil
}

type dataProvider struct {
	cs    suites.CipherSuite
	inner innerDataProvider

	vrfOutputs  map[uint32][]byte // Map from label version to VRF output.
	commitments map[uint32][]byte // Map from label version to commitment.
	timestamps  map[uint64]uint64 // Map from log entry to timestamp.
	prefixTrees map[uint64][]byte // Map from log entry to prefix tree root value.
}

func newDataProvider(cs suites.CipherSuite, inner innerDataProvider) *dataProvider {
	return &dataProvider{
		cs:    cs,
		inner: inner,

		vrfOutputs:  make(map[uint32][]byte),
		commitments: make(map[uint32][]byte),
		timestamps:  make(map[uint64]uint64),
		prefixTrees: make(map[uint64][]byte),
	}
}

func (dp *dataProvider) AddVRFOutput(ver uint32, vrfOutput []byte) error {
	if len(vrfOutput) != dp.cs.HashSize() {
		return errors.New("malformed vrf output")
	} else if _, ok := dp.vrfOutputs[ver]; ok {
		return errors.New("can not add the same vrf output twice")
	}
	dp.vrfOutputs[ver] = vrfOutput
	return nil
}

func (dp *dataProvider) AddCommitment(ver uint32, commitment []byte) error {
	if len(commitment) != dp.cs.HashSize() {
		return errors.New("malformed commitment")
	} else if _, ok := dp.commitments[ver]; ok {
		return errors.New("can not add the same commitment twice")
	}
	dp.commitments[ver] = commitment
	return nil
}

func (dp *dataProvider) AddRetained(retained map[uint64]structs.LogLeaf) error {
	for pos, leaf := range retained {
		if err := addTimestamp(dp.timestamps, pos, leaf.Timestamp); err != nil {
			return err
		}
		dp.prefixTrees[pos] = leaf.PrefixTree
	}
	return nil
}

// GetTimestamp takes as input the position of a log entry and returns the
// timestamp of the log entry. This function verifies that the timestamp is
// monotonic with others provided or retained.
func (dp *dataProvider) GetTimestamp(x uint64) (uint64, error) {
	if ts, ok := dp.timestamps[x]; ok {
		return ts, nil
	}
	ts, err := dp.inner.ConsumeTimestamp()
	if err != nil {
		return 0, err
	} else if err := addTimestamp(dp.timestamps, x, ts); err != nil {
		return 0, err
	}
	return ts, nil
}

// GetSearchBinaryLadder takes as input the position of a log entry, the target
// version for a search binary ladder, and whether or not to omit redundant
// lookups. It returns -1, 0, or 1 to indicate whether the greatest version of
// the label proven to exist is less than, equal to, or greater than the target
// version, respectively.
func (dp *dataProvider) GetSearchBinaryLadder(x uint64, ver uint32, omit bool) (int, error) {

}

// GetMonitoringBinaryLadder takes as input the position of a log entry and
// the target version for a monitoring binary ladder.
func (dp *dataProvider) GetMonitoringBinaryLadder(x uint64, ver uint32) error {
	ladder :=
}

// GetInclusionProof takes as input the position of a log entry and the
// target version to get an inclusion proof for.
func (dp *dataProvider) GetInclusionProof(x uint64, ver uint32) error {
	vrfOutput, ok := dp.vrfOutputs[ver]
	if !ok {
		return errors.New("vrf output for version not known")
	}
	commitment, ok := dp.commitments[ver]
	if !ok {
		return errors.New("commitment for version not known")
	}

	proof, err := dp.inner.ConsumePrefixProof()
	if err != nil {
		return err
	}
	entries := []prefix.Entry{{VrfOutput: vrfOutput, Commitment: commitment}}
	candidate, err := prefix.Evaluate(dp.cs, entries, proof)
	if err != nil {
		return err
	}

	return addPrefixTree(dp.prefixTrees, x, candidate)
}
