package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func addVersion(
	cs suites.CipherSuite,
	ver uint32,
	vrfOutput, commitment []byte,
	vrfOutputs, commitments map[uint32][]byte,
) error {
	if len(vrfOutput) != cs.HashSize() {
		return errors.New("malformed vrf output")
	} else if _, ok := vrfOutputs[ver]; ok {
		return errors.New("can not add the same vrf output twice")
	} else if commitment != nil && len(commitment) != cs.HashSize() {
		return errors.New("malformed commitment")
	} else if _, ok := commitments[ver]; ok {
		return errors.New("can not add the same commitment twice")
	}
	vrfOutputs[ver] = vrfOutput
	commitments[ver] = commitment
	return nil
}

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

	vrfOutputs        map[uint32][]byte
	commitments       map[uint32][]byte
	leftInclusion     map[uint32]uint64
	rightNonInclusion map[uint32]uint64
}

func newReceivedProofHandler(cs suites.CipherSuite, inner structs.CombinedTreeProof) *receivedProofHandler {
	return &receivedProofHandler{
		cs:    cs,
		inner: inner,

		vrfOutputs:        make(map[uint32][]byte),
		commitments:       make(map[uint32][]byte),
		leftInclusion:     make(map[uint32]uint64),
		rightNonInclusion: make(map[uint32]uint64),
	}
}

func (rph *receivedProofHandler) AddVersion(ver uint32, vrfOutput, commitment []byte) error {
	return addVersion(rph.cs, ver, vrfOutput, commitment, rph.vrfOutputs, rph.commitments)
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
	// Pop next PrefixProof to consume off of queue.
	if len(rph.inner.PrefixProofs) == 0 {
		return nil, 0, errors.New("unexpected number of prefix proofs consumed")
	}
	proof := rph.inner.PrefixProofs[0]
	rph.inner.PrefixProofs = rph.inner.PrefixProofs[1:]

	// Interpret the binary ladder provided in `proof` to determine which
	// direction our search should go after processing it.
	var versions []uint32
	if omit {
		versions = math.SearchBinaryLadder(ver, ver, nil, nil)
	} else {
		versions = math.SearchBinaryLadder(ver, ver, rph.leftInclusion, rph.rightNonInclusion)
	}
	res, err := math.InterpretSearchLadder(versions, ver, &proof)
	if err != nil {
		return nil, 0, err
	}

	// Populate the leftInclusion / rightNonInclusion maps, and also put
	// together the prefix.Entry structures we'll need for proof evaluation.
	entries := make([]prefix.Entry, 0)
	for i, result := range proof.Results {
		if res == -1 && result.Inclusion() {
			rph.leftInclusion[versions[i]] = x
		} else if (res == 0 || res == 1) && !result.Inclusion() {
			rph.rightNonInclusion[versions[i]] = x
		}
		vrfOutput, ok := rph.vrfOutputs[versions[i]]
		if !ok {
			return nil, 0, errors.New("vrf output not known for required version")
		}
		var commitment []byte
		if result.Inclusion() {
			commitment, ok = rph.commitments[versions[i]]
			if !ok {
				return nil, 0, errors.New("commitment not known for required version")
			}
		}
		entries = append(entries, prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment})
	}

	// Evaluate prefix proof and return.
	root, err := prefix.Evaluate(rph.cs, entries, &proof)
	if err != nil {
		return nil, 0, err
	}
	return root, res, nil
}

func (rph *receivedProofHandler) GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error) {
	// Pop next PrefixProof to consume off of queue.
	if len(rph.inner.PrefixProofs) == 0 {
		return nil, errors.New("unexpected number of prefix proofs consumed")
	}
	proof := rph.inner.PrefixProofs[0]
	rph.inner.PrefixProofs = rph.inner.PrefixProofs[1:]

	// Compute the leftInclusion map. This is the rph.leftInclusion map,
	// excluding entries that aren't in the current log entry's direct path and
	// to its left.
	parents := make(map[uint64]struct{})
	for _, parent := range math.LeftDirectPath(x) {
		parents[parent] = struct{}{}
	}
	leftInclusion := make(map[uint32]uint64)
	for ver, pos := range rph.leftInclusion {
		if _, ok := parents[pos]; ok {
			leftInclusion[ver] = pos
		}
	}

	// Verify that proof matches what we'd expect of a proper monitoring binary
	// ladder (correct number of entries, all showing inclusion).
	versions := math.MonitoringBinaryLadder(ver, leftInclusion)
	if len(proof.Results) != len(versions) {
		return nil, errors.New("unexpected number of results present in prefix proof")
	}
	for _, res := range proof.Results {
		if !res.Inclusion() {
			return nil, errors.New("unexpected non-inclusion proof provided")
		}
	}

	// Evaluate the prefix proof and return.
	entries := make([]prefix.Entry, len(versions))
	for i, version := range versions {
		vrfOutput, ok1 := rph.vrfOutputs[version]
		commitment, ok2 := rph.commitments[version]
		if !ok1 || !ok2 {
			return nil, errors.New("vrf output or commitment not known for required version")
		}
		entries[i] = prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment}
	}

	return prefix.Evaluate(rph.cs, entries, &proof)
}

func (rph *receivedProofHandler) GetInclusionProof(x uint64, ver uint32) ([]byte, error) {
	// Pop next PrefixProof to consume off of queue.
	if len(rph.inner.PrefixProofs) == 0 {
		return nil, errors.New("unexpected number of prefix proofs consumed")
	}
	proof := rph.inner.PrefixProofs[0]
	rph.inner.PrefixProofs = rph.inner.PrefixProofs[1:]

	// Verify that proof shows inclusion for a single version.
	if len(proof.Results) != 1 {
		return nil, errors.New("unexpected number of results present in prefix proof")
	} else if !proof.Results[0].Inclusion() {
		return nil, errors.New("unexpected non-inclusion proof provided")
	}

	// Evaluate the prefix proof and return.
	vrfOutput, ok1 := rph.vrfOutputs[ver]
	commitment, ok2 := rph.commitments[ver]
	if !ok1 || !ok2 {
		return nil, errors.New("vrf output or commitment not known for required version")
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

// producedProofHandler implements the proofHandle interface such that it can
// output output the corresponding CombinedTreeProof.
type producedProofHandler struct {
	cs        suites.CipherSuite
	tx        db.TransparencyStore
	n         uint64
	nP, m     *uint64
	labelInfo []uint64

	vrfOutputs  map[uint32][]byte
	commitments map[uint32][]byte

	prefixTrees       map[uint64][]byte
	leftInclusion     map[uint32]uint64
	rightNonInclusion map[uint32]uint64
	inner             structs.CombinedTreeProof
}

func newProducedProofHandler(
	cs suites.CipherSuite,
	tx db.TransparencyStore,
	n uint64,
	nP, m *uint64,
	labelInfo []uint64,
) *producedProofHandler {
	return &producedProofHandler{
		cs:        cs,
		tx:        tx,
		n:         n,
		nP:        nP,
		m:         m,
		labelInfo: labelInfo,

		vrfOutputs:  make(map[uint32][]byte),
		commitments: make(map[uint32][]byte),

		prefixTrees:       make(map[uint64][]byte),
		leftInclusion:     make(map[uint32]uint64),
		rightNonInclusion: make(map[uint32]uint64),
	}
}

func (pph *producedProofHandler) AddVersion(ver uint32, vrfOutput, commitment []byte) error {
	return addVersion(pph.cs, ver, vrfOutput, commitment, pph.vrfOutputs, pph.commitments)
}

func (pph *producedProofHandler) GetTimestamp(x uint64) (uint64, error) {
	raw, err := pph.tx.Get(x)
	if err != nil {
		return 0, err
	}
	entry, err := structs.NewLogEntry(pph.cs, bytes.NewBuffer(raw))
	if err != nil {
		return 0, err
	}

	pph.inner.Timestamps = append(pph.inner.Timestamps, entry.Timestamp)
	pph.prefixTrees[x] = entry.PrefixTree

	return entry.Timestamp, nil
}

func (pph *producedProofHandler) GetSearchBinaryLadder(x uint64, ver uint32, omit bool) ([]byte, int, error) {

}

func (pph *producedProofHandler) GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error) {

}

func (pph *producedProofHandler) GetInclusionProof(x uint64, ver uint32) ([]byte, error) {

}

func (pph *producedProofHandler) GetPrefixTrees(xs []uint64) ([][]byte, error) {
	out := make([][]byte, 0)
	for _, x := range xs {
		prefixTree, ok := pph.prefixTrees[x]
		if !ok {
			return nil, errors.New("unexpected prefix tree requested")
		}
		out = append(out, prefixTree)
	}
	return out, nil
}

func (pph *producedProofHandler) Finish() ([][]byte, error) {
	leaves := make([]uint64, 0, len(pph.prefixTrees))
	for x, _ := range pph.prefixTrees {
		leaves = append(leaves, x)
	}
	return log.NewTree(pph.cs, pph.tx.LogStore()).GetBatch(leaves, pph.n, pph.nP, pph.m)
}
