package transparency

import (
	"errors"
	"slices"

	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// verifyEntries verifies that the monitoring map entries presented in a request
// are valid. It returns the contact monitoring state.
func verifyEntries(entries []structs.MonitorMapEntry, index []uint64, n uint64) (map[uint64]uint32, error) {
	// Verify in ascending order by `position` and `version`, and that no
	// `position` or `version` is duplicate.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Position >= entries[i].Position {
			return nil, errors.New("monitoring map is not sorted by position")
		} else if entries[i-1].Version >= entries[i].Version {
			return nil, errors.New("monitoring map is not sorted by version")
		}
	}

	// Verify that each `position` is on the direct path of the first log entry
	// to contain the associated `version` of the label.
	ptrs := make(map[uint64]uint32)
	for _, entry := range entries {
		if int(entry.Version) >= len(index) {
			return nil, errors.New("unexpected version found in monitoring map")
		}
		first := index[entry.Version]

		path := math.RightDirectPath(first, n)
		if entry.Position != first && !slices.Contains(path, entry.Position) {
			return nil, errors.New("unexpected position found in monitoring map")
		}

		ptrs[entry.Position] = entry.Version
	}

	return ptrs, nil
}

// allLadderVersions returns the sorted list of all versions that would appear
// in a search binary ladder for any version in `versions`.
func allLadderVersions(versions []uint32) []uint32 {
	accumulated := make(map[uint32]struct{})
	accumulated[0] = struct{}{}
	for _, ver := range versions {
		for _, ladder := range math.SearchBinaryLadder(ver, ver, nil, nil) {
			accumulated[ladder] = struct{}{}
		}
	}

	sorted := make([]uint32, 0, len(accumulated))
	for ver := range accumulated {
		sorted = append(sorted, ver)
	}
	slices.Sort(sorted)

	return sorted
}

// getBinaryLadder returns the binary ladder steps corresponding to the
// requested versions. `label` is the label that the binary ladder is for,
// `greatest` is the greatest version of `label` that exists, and `n` is the
// size of the tree.
func (t *Tree) getBinaryLadder(label []byte, versions []uint32, greatest int, n uint64) ([]structs.BinaryLadderStep, error) {
	var (
		// Contains the VRF output for each version. Used to lookup the
		// commitment to the label's value at that version.
		vrfOutputs = make([][]byte, 0, len(versions))

		// Contains the list of BinaryLadderStep structures to output.
		out = make([]structs.BinaryLadderStep, len(versions))
	)
	for i, ver := range versions {
		vrfOutput, proof, err := t.computeVrfOutput(label, ver)
		if err != nil {
			return nil, err
		}
		if int(ver) <= greatest { // Only look up existing versions.
			vrfOutputs = append(vrfOutputs, vrfOutput)
		}
		out[i].Proof = proof
	}

	// Search the prefix tree to learn the value commitment for versions that we
	// expect to exist.
	prefixTree := prefix.NewTree(t.config.Suite, t.tx.PrefixStore())
	results, err := prefixTree.Search([]prefix.PrefixSearch{{
		Version:    n,
		VrfOutputs: vrfOutputs,
	}})
	if err != nil {
		return nil, err
	}
	for i, commitment := range results[0].Commitments {
		out[i].Commitment = commitment
	}

	return out, nil
}

type monitorOp struct {
	n       uint64
	index   []uint64
	monitor *algorithms.Monitor
	finish  func() (*structs.FullTreeHead, *structs.CombinedTreeProof, error)
}

func (t *Tree) startMonitor(last *uint64, label []byte) (*monitorOp, error) {
	fth, n, nP, m, err := t.fullTreeHead(last)
	if err != nil {
		return nil, err
	}
	indices, err := t.batchGetIndex([][]byte{label})
	if err != nil {
		return nil, err
	}
	index := indices[0]

	handle := algorithms.NewProducedProofHandle(t.config.Suite, t.tx, index)
	provider := algorithms.NewDataProvider(t.config.Suite, handle)

	if err := t.updateView(last, provider); err != nil {
		return nil, err
	}
	monitor, err := algorithms.NewMonitor(t.config.Public(), n, provider)
	if err != nil {
		return nil, err
	}

	return &monitorOp{
		n:       n,
		index:   index,
		monitor: monitor,
		finish: func() (*structs.FullTreeHead, *structs.CombinedTreeProof, error) {
			proof, err := provider.Output(n, nP, m)
			if err != nil {
				return nil, nil, err
			}
			return fth, proof, nil
		},
	}, nil
}

func (t *Tree) ContactMonitor(req *structs.ContactMonitorRequest) (*structs.ContactMonitorResponse, error) {
	op, err := t.startMonitor(req.Last, req.Label)
	if err != nil {
		return nil, err
	}

	ptrs, err := verifyEntries(req.Entries, op.index, op.n)
	if err != nil {
		return nil, err
	}
	op.monitor.Contact = &algorithms.ContactState{Ptrs: ptrs}
	if err := op.monitor.ContactMonitor(); err != nil {
		return nil, err
	}

	fth, combinedProof, err := op.finish()
	if err != nil {
		return nil, err
	}
	return &structs.ContactMonitorResponse{
		FullTreeHead: *fth,
		Monitor:      *combinedProof,
	}, nil
}

func (t *Tree) OwnerInit(req *structs.OwnerInitRequest) (*structs.OwnerInitResponse, error) {
	op, err := t.startMonitor(req.Last, req.Label)
	if err != nil {
		return nil, err
	}
	entries, err := op.monitor.InitEntries(req.Start)
	if err != nil {
		return nil, err
	}

	// Compute the greatest version of the label that exists at each log entry
	// in `entries`.
	state := &algorithms.OwnerState{Starting: 0, VerAtStarting: -1, UpcomingVers: op.index}
	versions := make([]uint32, 0, len(entries))
	for _, entry := range entries {
		ver := state.GreatestVersionAt(entry)
		if ver == -1 {
			break
		}
		versions = append(versions, uint32(ver))
	}
	// Fetch the VRF proof and value commitment for all versions that may appear
	// in a binary ladder for any version in `versions`.
	binaryLadder, err := t.getBinaryLadder(req.Label, allLadderVersions(versions), len(op.index)-1, op.n)
	if err != nil {
		return nil, err
	}

	// Finish owner initialization and output the completed proof.
	if _, err := op.monitor.OwnerInit(req.Start, versions); err != nil {
		return nil, err
	}

	fth, combinedProof, err := op.finish()
	if err != nil {
		return nil, err
	}
	return &structs.OwnerInitResponse{
		FullTreeHead: *fth,

		GreatestVersions: versions,
		BinaryLadder:     binaryLadder,
		Init:             *combinedProof,
	}, nil
}

func (t *Tree) OwnerMonitor(req *structs.OwnerMonitorRequest) (*structs.OwnerMonitorResponse, error) {
	op, err := t.startMonitor(req.Last, req.Label)
	if err != nil {
		return nil, err
	}

	// Verify `Entries` is acceptable.
	ptrs, err := verifyEntries(req.Entries, op.index, op.n)
	if err != nil {
		return nil, err
	}
	// Verify that `GreatestVersion` is less than or equal to the greatest known
	// version.
	if int(req.GreatestVersion) >= len(op.index) {
		return nil, errors.New("version advertised is greater than known greatest version")
	}

	op.monitor.Contact = &algorithms.ContactState{Ptrs: ptrs}
	op.monitor.Owner = &algorithms.OwnerState{
		VerAtStarting: -1,
		UpcomingVers:  op.index[:req.GreatestVersion+1],
	}
	op.monitor.Owner.SetStarting(req.Start)

	// Verify that `GreatestVersion` is greater than or equal to the greatest
	// version of the label that existed at `start`.
	if int(req.GreatestVersion) < op.monitor.Owner.VerAtStarting {
		return nil, errors.New("version advertised is less than version at starting position")
	}

	if err := op.monitor.ContactMonitor(); err != nil {
		return nil, err
	} else if err := op.monitor.OwnerMonitor(); err != nil {
		return nil, err
	}

	fth, combinedProof, err := op.finish()
	if err != nil {
		return nil, err
	}
	return &structs.OwnerMonitorResponse{
		FullTreeHead: *fth,
		Monitor:      *combinedProof,
	}, nil
	// TODO: Do we verify that `Start` is an unexpired distinguished log entry?
}
