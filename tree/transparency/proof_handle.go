package transparency

type proofHandle interface {
	// GetTimestamp takes as input the position of a log entry and returns the
	// timestamp of the log entry.
	GetTimestamp(x uint64) (uint64, error)

	// GetSearchBinaryLadder takes as input the position of a log entry, the
	// target version for a search binary ladder, and whether or not to omit
	// redundant lookups. It returns the prefix tree root value and -1, 0, or 1
	// to indicate whether the greatest version of the label proven to exist is
	// less than, equal to, or greater than the target version, respectively.
	GetSearchBinaryLadder(x uint64, ver uint32, omit bool) ([]byte, int, error)

	// GetMonitoringBinaryLadder takes as input the position of a log entry and
	// the target version for a monitoring binary ladder. It returns the prefix
	// tree root value.
	GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error)

	// GetInclusionProof takes as input the position of a log entry and the
	// target version to get an inclusion proof for. It returns the prefix tree
	// root value.
	GetInclusionProof(x uint64, ver uint32) ([]byte, error)

	// GetPrefixTrees returns the
	GetPrefixTrees(xs []uint64) ([][]byte, error)

	// Finish verifies that the proof is done being consumed and returns and
	// inclusion proof in the log tree for the inspected leaves.
	Finish() ([][]byte, error)
}

// func (dp *dataProvider) AddVRFOutput(ver uint32, vrfOutput []byte) error {
// 	if len(vrfOutput) != dp.cs.HashSize() {
// 		return errors.New("malformed vrf output")
// 	} else if _, ok := dp.vrfOutputs[ver]; ok {
// 		return errors.New("can not add the same vrf output twice")
// 	}
// 	dp.vrfOutputs[ver] = vrfOutput
// 	return nil
// }

// func (dp *dataProvider) AddCommitment(ver uint32, commitment []byte) error {
// 	if len(commitment) != dp.cs.HashSize() {
// 		return errors.New("malformed commitment")
// 	} else if _, ok := dp.commitments[ver]; ok {
// 		return errors.New("can not add the same commitment twice")
// 	}
// 	dp.commitments[ver] = commitment
// 	return nil
// }
