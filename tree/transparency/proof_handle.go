package transparency

import (
	"bytes"
	"errors"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/math"
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

	// GetPrefixTrees returns the prefix tree root values for the log entries at
	// the given positions. This corresponds to either consuming or producing
	// the `prefix_roots` field of a CombinedTreeProof.
	GetPrefixTrees(xs []uint64) ([][]byte, error)

	// Finish verifies that the proof is done being consumed and returns and
	// inclusion proof in the log tree for the inspected leaves.
	Finish(n uint64, nP, m *uint64) ([][]byte, error)
}

// receivedProofHandler implements the proofHandle interface over a
// CombinedTreeProof that was received and is being evaluated.
type receivedProofHandler struct {
	cs    suites.CipherSuite
	inner structs.CombinedTreeProof

	versions map[uint32]prefix.Entry
	tracker  versionTracker
}

func newReceivedProofHandler(cs suites.CipherSuite, inner structs.CombinedTreeProof) *receivedProofHandler {
	return &receivedProofHandler{
		cs:    cs,
		inner: inner,

		versions: make(map[uint32]prefix.Entry),
	}
}

func (rph *receivedProofHandler) AddVersion(ver uint32, vrfOutput, commitment []byte) error {
	if len(vrfOutput) != rph.cs.HashSize() {
		return errors.New("malformed vrf output")
	} else if commitment != nil && len(commitment) != rph.cs.HashSize() {
		return errors.New("malformed commitment")
	} else if _, ok := rph.versions[ver]; ok {
		return errors.New("can not add the same version twice")
	}
	rph.versions[ver] = prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment}
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
	// Pop next PrefixProof to consume off of queue.
	if len(rph.inner.PrefixProofs) == 0 {
		return nil, 0, errors.New("unexpected number of prefix proofs consumed")
	}
	proof := rph.inner.PrefixProofs[0]
	rph.inner.PrefixProofs = rph.inner.PrefixProofs[1:]

	// Interpret the binary ladder provided in `proof` to determine which
	// direction our search should go after processing it.
	leftInclusion, rightNonInclusion := rph.tracker.SearchMaps(x, omit)
	ladder := math.SearchBinaryLadder(ver, ver, leftInclusion, rightNonInclusion)
	res, err := math.InterpretSearchLadder(ladder, ver, &proof)
	if err != nil {
		return nil, 0, err
	}
	rph.tracker.AddResults(x, omit, ladder, proof.Results)

	// Put together the prefix.Entry structures we'll need for proof evaluation.
	entries := make([]prefix.Entry, len(proof.Results))
	for i, result := range proof.Results {
		entry, ok := rph.versions[ladder[i]]
		if !ok {
			return nil, 0, errors.New("required version not known")
		} else if result.Inclusion() && entry.Commitment == nil {
			return nil, 0, errors.New("commitment not known for required version")
		}
		entries[i] = entry
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

	// Verify that proof matches what we'd expect of a proper monitoring binary
	// ladder (correct number of entries, all showing inclusion).
	ladder := math.MonitoringBinaryLadder(ver, rph.tracker.MonitoringMap(x))
	if len(proof.Results) != len(ladder) {
		return nil, errors.New("unexpected number of results present in prefix proof")
	}
	for _, res := range proof.Results {
		if !res.Inclusion() {
			return nil, errors.New("unexpected non-inclusion proof provided")
		}
	}

	// Evaluate the prefix proof and return.
	entries := make([]prefix.Entry, len(ladder))
	for i, version := range ladder {
		entry, ok := rph.versions[version]
		if !ok {
			return nil, errors.New("required version not known")
		} else if entry.Commitment == nil {
			return nil, errors.New("commitment not known for required version")
		}
		entries[i] = entry
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
	entry, ok := rph.versions[ver]
	if !ok {
		return nil, errors.New("required version not known")
	} else if entry.Commitment == nil {
		return nil, errors.New("commitment not known for required version")
	}
	entries := []prefix.Entry{entry}

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

func (rph *receivedProofHandler) Finish(n uint64, nP, m *uint64) ([][]byte, error) {
	if len(rph.inner.Timestamps) != 0 {
		return nil, errors.New("unexpected additional timestamps found")
	} else if len(rph.inner.PrefixProofs) != 0 {
		return nil, errors.New("unexpected additional prefix proofs found")
	} else if len(rph.inner.PrefixRoots) != 0 {
		return nil, errors.New("unexpected additional prefix roots found")
	}
	return rph.inner.Inclusion.Elements, nil
}

type requiredProof struct {
	pos  uint64
	vers []uint32
}

// producedProofHandler implements the proofHandle interface such that it can
// output the corresponding CombinedTreeProof.
type producedProofHandler struct {
	cs        suites.CipherSuite
	tx        db.TransparencyStore
	labelInfo []uint64

	timestamps  []uint64
	prefixTrees map[uint64][]byte
	proofs      []requiredProof
	roots       [][]byte
	inclusion   [][]byte

	tracker versionTracker
}

func newProducedProofHandler(
	cs suites.CipherSuite,
	tx db.TransparencyStore,
	labelInfo []uint64,
) *producedProofHandler {
	return &producedProofHandler{
		cs:        cs,
		tx:        tx,
		labelInfo: labelInfo,

		prefixTrees: make(map[uint64][]byte),
	}
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

	pph.timestamps = append(pph.timestamps, entry.Timestamp)
	pph.prefixTrees[x] = entry.PrefixTree

	return entry.Timestamp, nil
}

func (pph *producedProofHandler) GetSearchBinaryLadder(x uint64, ver uint32, omit bool) ([]byte, int, error) {
	// Determine the greatest version of the label that exists at this point.
	greatest, found := slices.BinarySearch(pph.labelInfo, x)
	if !found {
		greatest--
	}

	// Compute the binary ladder steps to lookup.
	var ladder []uint32
	if greatest < 0 {
		ladder = []uint32{0}
	} else {
		leftInclusion, rightNonInclusion := pph.tracker.SearchMaps(x, omit)
		ladder = math.SearchBinaryLadder(ver, uint32(greatest), leftInclusion, rightNonInclusion)
	}
	pph.tracker.AddLadder(x, omit, greatest, ladder)
	pph.proofs = append(pph.proofs, requiredProof{pos: x, vers: ladder})

	// Return prefix tree root and the result of the search.
	prefixTree, ok := pph.prefixTrees[x]
	if !ok {
		return nil, 0, errors.New("prefix tree root not known for required version")
	}
	var res int
	if greatest < int(ver) {
		res = -1
	} else if greatest > int(ver) {
		res = 1
	}
	return prefixTree, res, nil
}

func (pph *producedProofHandler) GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error) {
	ladder := math.MonitoringBinaryLadder(ver, pph.tracker.MonitoringMap(x))
	pph.proofs = append(pph.proofs, requiredProof{pos: x, vers: ladder})

	prefixTree, ok := pph.prefixTrees[x]
	if !ok {
		return nil, errors.New("prefix tree root not known for required version")
	}
	return prefixTree, nil
}

func (pph *producedProofHandler) GetInclusionProof(x uint64, ver uint32) ([]byte, error) {
	pph.proofs = append(pph.proofs, requiredProof{pos: x, vers: []uint32{ver}})

	prefixTree, ok := pph.prefixTrees[x]
	if !ok {
		return nil, errors.New("prefix tree root not known for required version")
	}
	return prefixTree, nil
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
	pph.roots = out
	return out, nil
}

func (pph *producedProofHandler) Finish(n uint64, nP, m *uint64) ([][]byte, error) {
	leaves := make([]uint64, 0, len(pph.prefixTrees))
	for x, _ := range pph.prefixTrees {
		leaves = append(leaves, x)
	}
	inclusion, err := log.NewTree(pph.cs, pph.tx.LogStore()).GetBatch(leaves, n, nP, m)
	if err != nil {
		return nil, err
	}
	pph.inclusion = inclusion
	return inclusion, nil
}
