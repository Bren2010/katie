package transparency

import (
	"context"
	"errors"
	"slices"

	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// verifyEntries verifies that the monitoring map entries presented in a request
// are valid.
func verifyEntries(entries []structs.MonitorMapEntry, index []uint64, n uint64) error {
	// Verify that `entries` is in ascending order by both `position` and
	// `version`, and that no `position` or `version` is duplicate.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Position >= entries[i].Position {
			return errors.New("monitoring map is not sorted by position")
		} else if entries[i-1].Version >= entries[i].Version {
			return errors.New("monitoring map is not sorted by version")
		}
	}

	// Verify that each `position` is on the right direct path of the first log
	// entry to contain the associated `version` of the label.
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

type monitorOp struct {
	index   []uint64
	monitor *algorithms.Monitor
	finish  func(map[uint32][]byte) (*structs.FullTreeHead, *structs.CombinedTreeProof, error)
}

func (t *Tree) startMonitor(last *uint64, label []byte) (*monitorOp, error) {
	fth, err := t.fullTreeHead(last)
	if err != nil {
		return nil, err
	}
	index, err := t.getIndex(label)
	if err != nil {
		return nil, err
	}

	handle := algorithms.NewProducedProofHandle(t.config.Suite, t.tx, index)
	handle.SetMaxProofs(t.config.MonitoringProofLimit())
	provider := algorithms.NewDataProvider(t.config.Suite, handle)

	if err := t.updateView(last, provider); err != nil {
		return nil, err
	}
	monitor, err := algorithms.NewMonitor(t.config.Public(), t.n(), provider)
	if err != nil {
		return nil, err
	}

	return &monitorOp{
		index:   index,
		monitor: monitor,
		finish: func(vrfOutputs map[uint32][]byte) (*structs.FullTreeHead, *structs.CombinedTreeProof, error) {
			if err := t.addRequiredVersions(handle, label, vrfOutputs); err != nil {
				return nil, nil, err
			}
			proof, err := provider.Output(t.n(), nP(fth), last)
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

	if err := verifyEntries(req.Entries, op.index, t.n()); err != nil {
		return nil, err
	} else if err := op.monitor.SetContactState(req.Entries); err != nil {
		return nil, err
	} else if err := op.monitor.ContactMonitor(); err != nil {
		return nil, err
	}

	fth, combinedProof, err := op.finish(nil)
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
	//
	// If `req.Start` is nil, or no version of the label exists at `req.Start`,
	// then `versions` is empty and `greatestAtStart` is -1. This results in a
	// binary ladder for only version 0 with no commitment. The prefix tree is
	// not searched in this case, so the value of `start` is unused.
	greatestAtStart, start := int64(-1), uint64(0)
	if req.Start != nil {
		greatestAtStart, start = state.GreatestVersionAt(*req.Start), *req.Start
	}
	binaryLadder, vrfOutputs, err := t.getBinaryLadder(
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

	fth, combinedProof, err := op.finish(vrfOutputs)
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
	if err := verifyEntries(req.Entries, op.index, t.n()); err != nil {
		return nil, err
	}
	// Verify that `Start` is either absent or less than the size of the tree.
	if req.Start != nil && *req.Start >= t.n() {
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

	fth, combinedProof, err := op.finish(nil)
	if err != nil {
		return nil, err
	}
	return &structs.OwnerMonitorResponse{
		FullTreeHead: *fth,
		Monitor:      *combinedProof,
	}, nil
}
