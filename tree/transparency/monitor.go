package transparency

import (
	"context"
	"errors"
	"slices"

	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// verifyEntries verifies that the monitoring map entries presented in a request
// are valid.
func verifyEntries(entries []structs.MonitorMapEntry, index []uint64, n uint64) error { // TODO: Is this replaced by NewContactState?
	// Verify that `entries` is in ascending order by both `position` and
	// `version`, and that no `position` or `version` is duplicate.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Position >= entries[i].Position {
			return errors.New("monitoring map is not sorted by position")
		} else if entries[i-1].Version >= entries[i].Version {
			return errors.New("monitoring map is not sorted by version")
		}
	}

	// Verify that each `position` is on the (right) direct path of the first
	// log entry to contain the associated `version` of the label.
	for _, entry := range entries {
		if int(entry.Version) >= len(index) {
			return errors.New("unexpected version found in monitoring map")
		}
		first := index[entry.Version]

		path := math.RightDirectPath(first, n)
		if entry.Position != first && !slices.Contains(path, entry.Position) {
			return errors.New("unexpected position found in monitoring map")
		}
	}

	return nil
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
// requested versions, along with the VRF output for each version. `label` is
// the label that the binary ladder is for, `greatest` is the greatest version
// of `label` that exists as of log entry `x` (or -1 if none), and the
// commitment for each version up to `greatest` is looked up in the prefix tree
// of log entry `x`.
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
		existing       []int
		existingOutput [][]byte

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
			existingOutput = append(existingOutput, vrfOutput)
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
		VrfOutputs: existingOutput,
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
	handle.SetMaxProofs(t.config.MonitoringProofLimit())
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
			for ver := range handle.RequiredVersions() {
				vrfOutput, _, err := t.computeVrfOutput(label, ver)
				if err != nil {
					return nil, nil, err
				} else if err := handle.AddVersion(ver, vrfOutput); err != nil {
					return nil, nil, err
				}
			}

			proof, err := provider.Output(n, nP, m)
			if err != nil {
				return nil, nil, err
			}
			return fth, proof, nil
		},
	}, nil
}

func (t *Tree) ContactMonitor(
	ctx context.Context,
	req *structs.ContactMonitorRequest,
) (*structs.ContactMonitorResponse, error) {
	op, err := t.startMonitor(req.Last, req.Label)
	if err != nil {
		return nil, err
	}

	if err := verifyEntries(req.Entries, op.index, op.n); err != nil {
		return nil, err
	} else if err := op.monitor.SetContactState(req.Entries); err != nil {
		return nil, err
	}
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

func (t *Tree) OwnerInit(
	ctx context.Context,
	req *structs.OwnerInitRequest,
) (*structs.OwnerInitResponse, error) {
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
	state := &algorithms.OwnerState{UpcomingVers: op.index}
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
	greatestAtStart, start := int64(-1), uint64(0)
	if req.Start != nil {
		greatestAtStart, start = state.GreatestVersionAt(*req.Start), *req.Start
	}
	binaryLadder, _, err := t.getBinaryLadder(
		req.Label,
		allLadderVersions(versions),
		greatestAtStart,
		start,
	)
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

func (t *Tree) OwnerMonitor(
	ctx context.Context,
	req *structs.OwnerMonitorRequest,
) (*structs.OwnerMonitorResponse, error) {
	op, err := t.startMonitor(req.Last, req.Label)
	if err != nil {
		return nil, err
	}

	// Verify `Entries` is acceptable.
	if err := verifyEntries(req.Entries, op.index, op.n); err != nil {
		return nil, err
	}
	// Verify that `Start` is either absent or less than the size of the tree.
	if req.Start != nil && *req.Start >= op.n {
		return nil, errors.New("advertised starting position is greater than tree size")
	}
	// Verify that `GreatestVersion` is either absent, or less than or equal to
	// the greatest version of the label.
	if req.GreatestVersion != nil && int(*req.GreatestVersion) >= len(op.index) {
		return nil, errors.New("version advertised is greater than known greatest version")
	}

	if err := op.monitor.SetContactState(req.Entries); err != nil {
		return nil, err
	}

	// Reconstruct the owner's state from the label's index. The owner's state
	// starts out knowing every version of the label, and is then advanced to
	// the starting position advertised by the user.
	owner := &algorithms.OwnerState{UpcomingVers: op.index}
	if req.Start != nil {
		owner.SetStarting(*req.Start)
	}
	op.monitor.Owner = owner

	// Verify that, if some version of the label existed at `start`, that
	// `GreatestVersion` is present and greater than or equal to that version.
	verAtStarting := owner.VerAtStarting()
	if verAtStarting > -1 {
		if req.GreatestVersion == nil || int64(*req.GreatestVersion) < verAtStarting {
			return nil, errors.New("version advertised is less than version at starting position")
		}
	}

	// Remove any versions that aren't known to the user from `UpcomingVers`.
	// This ensures that the stopping condition is followed.
	end := int64(0)
	if req.GreatestVersion != nil {
		end = int64(*req.GreatestVersion) - verAtStarting
	}
	owner.UpcomingVers = owner.UpcomingVers[:end]

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
}
