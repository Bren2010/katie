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

func addVersion(
	cs suites.CipherSuite,
	versions map[uint32]prefix.Entry,
	ver uint32, vrfOutput, commitment []byte,
) error {
	if len(vrfOutput) != cs.HashSize() {
		return errors.New("malformed vrf output")
	} else if commitment != nil && len(commitment) != cs.HashSize() {
		return errors.New("malformed commitment")
	} else if _, ok := versions[ver]; ok {
		return errors.New("can not add the same version twice")
	}
	versions[ver] = prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment}
	return nil
}

type proofHandle interface {
	// AddVersion adds the VRF output and commitment corresponding to a version
	// of a label to the proofHandle.
	AddVersion(ver uint32, vrfOutput, commitment []byte) error

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

	// Finish verifies that the proof is done being consumed and returns an
	// inclusion proof in the log tree for the inspected leaves.
	Finish() ([][]byte, error)

	// Output returns the produced CombinedTreeProof. It takes as input the set
	// of inspected log leaves `leaves` and the tree size parameters `n`, `nP`,
	// and `m`.
	Output(leaves []uint64, n uint64, nP, m *uint64) (*structs.CombinedTreeProof, error)
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
	return addVersion(rph.cs, rph.versions, ver, vrfOutput, commitment)
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
	// Pop next PrefixProof off of queue.
	if len(rph.inner.PrefixProofs) == 0 {
		return nil, 0, errors.New("unexpected number of prefix proofs consumed")
	}
	proof := rph.inner.PrefixProofs[0]

	// Interpret the binary ladder provided in `proof` to determine which
	// direction our search should go after processing it.
	leftInclusion, rightNonInclusion := rph.tracker.SearchMaps(x, omit)
	ladder := math.SearchBinaryLadder(ver, ver, leftInclusion, rightNonInclusion)
	res, err := math.InterpretSearchLadder(ladder, ver, &proof)
	if err != nil {
		return nil, 0, err
	}

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

	rph.inner.PrefixProofs = rph.inner.PrefixProofs[1:]
	rph.tracker.AddResults(x, omit, ladder, proof.Results)
	return root, res, nil
}

func (rph *receivedProofHandler) GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error) {
	// Pop next PrefixProof off of queue.
	if len(rph.inner.PrefixProofs) == 0 {
		return nil, errors.New("unexpected number of prefix proofs consumed")
	}
	proof := rph.inner.PrefixProofs[0]

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
	root, err := prefix.Evaluate(rph.cs, entries, &proof)
	if err != nil {
		return nil, err
	}

	rph.inner.PrefixProofs = rph.inner.PrefixProofs[1:]
	return root, nil
}

func (rph *receivedProofHandler) GetInclusionProof(x uint64, ver uint32) ([]byte, error) {
	// Pop next PrefixProof off of queue.
	if len(rph.inner.PrefixProofs) == 0 {
		return nil, errors.New("unexpected number of prefix proofs consumed")
	}
	proof := rph.inner.PrefixProofs[0]

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
	root, err := prefix.Evaluate(rph.cs, []prefix.Entry{entry}, &proof)
	if err != nil {
		return nil, err
	}

	rph.inner.PrefixProofs = rph.inner.PrefixProofs[1:]
	return root, nil
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

func (rph *receivedProofHandler) Output(leaves []uint64, n uint64, nP, m *uint64) (*structs.CombinedTreeProof, error) {
	panic("unreachable")
}

type requiredProof struct {
	pos  uint64
	vers []uint32
}

// producedProofHandler implements the proofHandle interface such that it can
// output the corresponding CombinedTreeProof.
type producedProofHandler struct {
	cs    suites.CipherSuite
	tx    db.TransparencyStore
	index []uint64

	timestamps  []uint64
	prefixTrees map[uint64][]byte
	proofs      []requiredProof
	roots       [][]byte

	versions map[uint32]prefix.Entry
	tracker  versionTracker
}

func newProducedProofHandler(
	cs suites.CipherSuite,
	tx db.TransparencyStore,
	index []uint64,
) *producedProofHandler {
	return &producedProofHandler{
		cs:    cs,
		tx:    tx,
		index: index,

		prefixTrees: make(map[uint64][]byte),

		versions: make(map[uint32]prefix.Entry),
	}
}

func (pph *producedProofHandler) AddVersion(ver uint32, vrfOutput, commitment []byte) error {
	return addVersion(pph.cs, pph.versions, ver, vrfOutput, commitment)
}

func (pph *producedProofHandler) GetTimestamp(x uint64) (uint64, error) {
	res, err := pph.tx.BatchGet([]uint64{x})
	if err != nil {
		return 0, err
	}
	raw, ok := res[x]
	if !ok {
		return 0, errors.New("requested log entry not found")
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
	greatest, found := slices.BinarySearch(pph.index, x) // TODO: What if there are duplicate values?
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

	// Determine the prefix tree root and the result of the search.
	prefixTree, ok := pph.prefixTrees[x]
	if !ok {
		return nil, 0, errors.New("prefix tree root not known for required version")
	}
	res := 0
	if greatest < int(ver) {
		res = -1
	} else if greatest > int(ver) {
		res = 1
	}

	pph.proofs = append(pph.proofs, requiredProof{pos: x, vers: ladder})
	pph.tracker.AddLadder(x, omit, greatest, ladder)
	return prefixTree, res, nil
}

func (pph *producedProofHandler) GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error) {
	prefixTree, ok := pph.prefixTrees[x]
	if !ok {
		return nil, errors.New("prefix tree root not known for required version")
	}
	ladder := math.MonitoringBinaryLadder(ver, pph.tracker.MonitoringMap(x))
	pph.proofs = append(pph.proofs, requiredProof{pos: x, vers: ladder})
	return prefixTree, nil
}

func (pph *producedProofHandler) GetInclusionProof(x uint64, ver uint32) ([]byte, error) {
	prefixTree, ok := pph.prefixTrees[x]
	if !ok {
		return nil, errors.New("prefix tree root not known for required version")
	}
	pph.proofs = append(pph.proofs, requiredProof{pos: x, vers: []uint32{ver}})
	return prefixTree, nil
}

func (pph *producedProofHandler) GetPrefixTrees(xs []uint64) ([][]byte, error) {
	roots := make([][]byte, len(xs))
	for i, x := range xs {
		prefixTree, ok := pph.prefixTrees[x]
		if !ok {
			return nil, errors.New("unexpected prefix tree requested")
		}
		roots[i] = prefixTree
	}
	pph.roots = roots
	return roots, nil
}

func (pph *producedProofHandler) Finish() ([][]byte, error) {
	panic("unreachable")
}

func (pph *producedProofHandler) Output(leaves []uint64, n uint64, nP, m *uint64) (*structs.CombinedTreeProof, error) {
	// Construct the list of prefix tree searches to execute.
	searches := make([]prefix.PrefixSearch, len(pph.proofs))
	for i, proof := range pph.proofs {
		vrfOutputs := make([][]byte, len(proof.vers))
		for j, ver := range proof.vers {
			entry, ok := pph.versions[ver]
			if !ok {
				return nil, errors.New("required version not known")
			}
			vrfOutputs[j] = entry.VrfOutput
		}
		searches[i] = prefix.PrefixSearch{Version: proof.pos + 1, VrfOutputs: vrfOutputs}
	}

	// Execute prefix tree searches.
	res, err := prefix.NewTree(pph.cs, pph.tx.PrefixStore()).Search(searches)
	if err != nil {
		return nil, err
	}

	// Pull out individual proofs. Pull out commitment values / check for
	// consistency if there is duplication.
	proofs := make([]prefix.PrefixProof, len(res))
	for i, result := range res {
		proofs[i] = result.Proof

		for j, commitment := range result.Commitments {
			if commitment == nil {
				continue
			}
			ver := pph.proofs[i].vers[j]
			entry := pph.versions[ver]
			if entry.Commitment == nil {
				pph.versions[ver] = prefix.Entry{VrfOutput: entry.VrfOutput, Commitment: commitment}
			} else if !bytes.Equal(commitment, entry.Commitment) {
				return nil, errors.New("different values for same commitment found")
			}
		}
	}

	// Fetch inclusion proof and return final CombinedTreeProof.
	inclusion, err := log.NewTree(pph.cs, pph.tx.LogStore()).GetBatch(leaves, n, nP, m)
	if err != nil {
		return nil, err
	}
	return &structs.CombinedTreeProof{
		Timestamps:   pph.timestamps,
		PrefixProofs: proofs,
		PrefixRoots:  pph.roots,

		Inclusion: structs.InclusionProof{Elements: inclusion},
	}, nil
}
