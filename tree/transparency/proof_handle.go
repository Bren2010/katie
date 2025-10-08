package transparency

import (
	"errors"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

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

// receivedProofHandler implements the proofHandle interface over a
// CombinedTreeProof that was received and is being evaluated.
type receivedProofHandler struct {
	cs    suites.CipherSuite
	inner structs.CombinedTreeProof

	vrfOutputs  map[uint32][]byte
	commitments map[uint32][]byte
}

func newReceivedProofHandler(cs suites.CipherSuite, inner structs.CombinedTreeProof) *receivedProofHandler {
	return &receivedProofHandler{cs: cs, inner: inner}
}

func (rph *receivedProofHandler) AddVersion(ver uint32, vrfOutput, commitment []byte) error {
	if len(vrfOutput) != rph.cs.HashSize() {
		return errors.New("malformed vrf output")
	} else if _, ok := rph.vrfOutputs[ver]; ok {
		return errors.New("can not add the same vrf output twice")
	} else if len(commitment) != rph.cs.HashSize() {
		return errors.New("malformed commitment")
	} else if _, ok := rph.commitments[ver]; ok {
		return errors.New("can not add the same commitment twice")
	}
	rph.vrfOutputs[ver] = vrfOutput
	rph.commitments[ver] = commitment
	return nil
}

func (rph *receivedProofHandler) GetTimestamp(x uint64) (uint64, error) {
	if len(rph.inner.Timestamps) == 0 {
		return 0, errors.New("unexpected number of timestamps consumed")
	}
	ts := rph.inner.Timestamps[0]
	rph.inner.Timestamps = rph.inner.Timestamps[1:]
	return ts, nil
}

func (rph *receivedProofHandler) GetSearchBinaryLadder(x uint64, ver uint32, omit bool) ([]byte, int, error) {

}

func (rph *receivedProofHandler) GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error) {

}

func (rph *receivedProofHandler) GetInclusionProof(x uint64, ver uint32) ([]byte, error) {
	if len(rph.inner.PrefixProofs) == 0 {
		return nil, errors.New("unexpected number of prefix proofs consumed")
	}
	proof := rph.inner.PrefixProofs[0]
	rph.inner.PrefixProofs = rph.inner.PrefixProofs[1:]

	if len(proof.Results) != 1 {
		return nil, errors.New("unexpected number of results present in prefix proof")
	} else if !proof.Results[0].Inclusion() {
		return nil, errors.New("unexpected non-inclusion proof provided")
	}
	vrfOutput, ok1 := rph.vrfOutputs[ver]
	commitment, ok2 := rph.commitments[ver]
	if !ok1 || !ok2 {
		return nil, errors.New("inclusion proof requested for unknown version")
	}
	entries := []prefix.Entry{{VrfOutput: vrfOutput, Commitment: commitment}}

	return prefix.Evaluate(rph.cs, entries, &proof)
}

func (rph *receivedProofHandler) GetPrefixTrees(xs []uint64) ([][]byte, error) {
	if len(xs) != len(rph.inner.PrefixRoots) {
		return nil, errors.New("unexpected number of prefix tree roots requested")
	}
	roots := rph.inner.PrefixRoots
	rph.inner.PrefixRoots = nil
	return roots, nil
}

func (rph *receivedProofHandler) Finish() ([][]byte, error) {
	if len(rph.inner.Timestamps) != 0 {
		return nil, errors.New("unexpected additional timestamps found")
	} else if len(rph.inner.PrefixProofs) != 0 {
		return nil, errors.New("unexpected additional prefix proofs found")
	} else if len(rph.inner.PrefixRoots) != 0 {
		return nil, errors.New("unexpected additional prefix roots found")
	}
	return rph.inner.Inclusion.Elements, nil
}
