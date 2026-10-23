package transparency

import (
	"context"
	"errors"
	"slices"

	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/wire"
)

// updateLadderVersions returns the set of versions that a VRF proof needs to be
// provided for in an UpdateResponse, where the first version created in the
// UpdateResponse is `startVer` and the final version created is `endVer`.
//
// Specifically: the versions in a search binary ladder for `endVer`, plus
// versions in the range [startVer, endVer), excluding versions that exist in
// the search binary ladder for `startVer-1`.
func updateLadderVersions(startVer, endVer uint32) []uint32 {
	dedup := make(map[uint32]struct{})

	for _, ver := range math.SearchBinaryLadder(endVer, endVer, nil, nil) {
		dedup[ver] = struct{}{}
	}
	for ver := startVer; ver < endVer; ver++ {
		dedup[ver] = struct{}{}
	}
	if startVer == 0 {
		delete(dedup, 0)
	} else {
		for _, ver := range math.SearchBinaryLadder(startVer-1, startVer-1, nil, nil) {
			delete(dedup, ver)
		}
	}

	// Convert `dedup` into a sorted slice of versions.
	versions := make([]uint32, 0, len(dedup))
	for ver := range dedup {
		versions = append(versions, ver)
	}
	slices.Sort(versions)

	return versions
}

func (t *Tree) Update(
	ctx context.Context,
	req *structs.UpdateRequest,
) (<-chan wire.UpdateResponse, error) {
	if t.config.Mode == structs.ThirdPartyManagement {
		return nil, errors.New("update may not be called directly on third party manager")
	}
	up := newUpdater(t, ctx)
	if err := up.setRequest(req); err != nil {
		return nil, err
	}
	go up.process()

	return up.ch, nil
}

func (t *Tree) ManagerUpdate(
	ctx context.Context,
	req *structs.ManagerUpdateRequest,
) (<-chan wire.UpdateResponse, error) {
	if t.config.Mode != structs.ThirdPartyManagement {
		return nil, errors.New("manager update may not be called when not using third party management")
	}
	up := newUpdater(t, ctx)
	if err := up.setManagerRequest(req); err != nil {
		return nil, err
	}
	go up.process()

	return up.ch, nil
}

type updater struct {
	tree *Tree
	ctx  context.Context
	ch   chan wire.UpdateResponse

	last      *uint64
	label     []byte
	values    []structs.UpdateValue
	signedVer *uint32

	index []uint64 // index is the label's index (= position of each version).
	ver   int64    // ver is the next version the user needs to be informed about.
}

func newUpdater(t *Tree, ctx context.Context) *updater {
	return &updater{
		tree: t,
		ctx:  ctx,
		ch:   make(chan wire.UpdateResponse),
	}
}

func (u *updater) setRequest(req *structs.UpdateRequest) error {
	// Load index and validate the request against it.
	index, err := u.tree.getIndex(req.Label)
	if err != nil {
		return err
	} else if req.GreatestVersion != nil {
		if *req.GreatestVersion >= uint32(len(index)) {
			return errors.New("advertised greatest version of label is greater than actual greatest version")
		}
	}

	// Populate updater state.
	u.last = req.Last
	u.label = req.Label
	u.values = make([]structs.UpdateValue, len(req.Values))
	for i, val := range req.Values {
		u.values[i] = structs.UpdateValue{Value: val.Value}
	}

	u.index = index
	u.ver = 0
	if req.GreatestVersion != nil {
		u.ver = int64(*req.GreatestVersion) + 1
	}

	return nil
}

func (u *updater) setManagerRequest(req *structs.ManagerUpdateRequest) error {
	if len(req.Values) == 0 && req.SignedVersion != 0 {
		return errors.New("signed version must be zero if no values are provided")
	}

	// Verify service operator signatures.
	for i, val := range req.Values {
		signedVer := int64(req.SignedVersion) + int64(i)
		if signedVer >= 1<<32 {
			return errors.New("signed version overflows")
		}
		err := u.tree.verifyServiceSignature(req.Label, uint32(signedVer), val)
		if err != nil {
			return err
		}
	}

	// Load index and validate the request against it.
	index, err := u.tree.getIndex(req.Label)
	if err != nil {
		return err
	} else if req.SignedVersion < uint32(len(index)) {
		return errors.New("signed version is less than next version of label")
	} else if req.GreatestVersion != nil {
		if *req.GreatestVersion >= uint32(len(index)) {
			return errors.New("advertised greatest version of label is greater than actual greatest version")
		}
	}

	// Populate updater state.
	u.last = req.Last
	u.label = req.Label
	u.values = req.Values
	u.signedVer = &req.SignedVersion

	u.index = index
	u.ver = 0
	if req.GreatestVersion != nil {
		u.ver = int64(*req.GreatestVersion) + 1
	}

	return nil
}

func (u *updater) send(res wire.UpdateResponse) bool {
	select {
	case <-u.ctx.Done():
		return false
	case u.ch <- res:
		return true
	}
}

func (u *updater) process() {
	defer close(u.ch)

	// First, push out UpdateResponses for versions of the label the user
	// doesn't know about, if any.
	if ok := u.sync(nil); !ok {
		return
	}

	// Submit new versions to be sequenced and reload the tree once they are.
	if len(u.values) == 0 {
		return
	} else if u.tree.updater == nil {
		err := errors.New("transparency tree does not support user-submitted label updates")
		u.send(wire.UpdateResponse{Err: err})
		return
	}
	ch := make(chan UpdateResponse, 1)
	req := UpdateRequest{
		Label:           u.label,
		StartingVersion: u.signedVer,
		Values:          u.values,

		Response: ch,
	}
	select {
	case u.tree.updater <- req:
	case <-u.ctx.Done():
		return
	}

	var res UpdateResponse
	select {
	case res = <-ch:
	case <-u.ctx.Done():
		return
	}
	if res.Err != nil {
		u.send(wire.UpdateResponse{Err: res.Err})
		return
	} else if err := u.reloadTree(res.Pos); err != nil {
		u.send(wire.UpdateResponse{Err: err})
		return
	}

	// Push out remaining UpdateResponses.
	u.sync(&res.Pos)
}

// sync pushes all outstanding UpdateResponses to the user.
func (u *updater) sync(pos *uint64) bool {
	for u.ver < int64(len(u.index)) {
		out, err := u.next(pos != nil && *pos != u.index[u.ver])
		if ok := u.send(wire.UpdateResponse{Out: out, Err: err}); !ok {
			return false
		} else if err != nil {
			return false
		}

		last := u.tree.n()
		u.last = &last
		u.ver += int64(len(out.Values))
	}

	return true
}

func (u *updater) next(withValues bool) (*structs.UpdateResponse, error) {
	t, pos := u.tree, u.index[u.ver]

	fth, err := t.fullTreeHead(u.last)
	if err != nil {
		return nil, err
	}

	startVer := u.ver
	values, info, err := u.infos(pos, withValues)
	if err != nil {
		return nil, err
	}
	ladder, err := u.ladder(startVer, startVer+int64(len(info))-1, pos)
	if err != nil {
		return nil, err
	}

	// Execute the algorithm to update the user's view of the tree, followed by
	// the update algorithm.
	handle := algorithms.NewProducedProofHandle(t.config.Suite, t.tx, u.index)
	provider := algorithms.NewDataProvider(t.config.Suite, handle)
	if err := t.updateView(u.last, provider); err != nil {
		return nil, err
	}
	monitor, err := algorithms.NewMonitor(t.config.Public(), t.n(), provider)
	if err != nil {
		return nil, err
	}
	monitor.Owner = &algorithms.OwnerState{UpcomingVers: u.index[:startVer]}
	if err := monitor.Update(pos, len(info)); err != nil {
		return nil, err
	}

	// Produce final CombinedTreeProof.
	for ver := range handle.RequiredVersions() {
		vrfOutput, _, err := t.computeVrfOutput(u.label, ver)
		if err != nil {
			return nil, err
		} else if err := handle.AddVersion(ver, vrfOutput); err != nil {
			return nil, err
		}
	}
	proof, err := provider.Output(t.n(), t.nP(), u.last)
	if err != nil {
		return nil, err
	}
	return &structs.UpdateResponse{
		FullTreeHead: *fth,

		Position: pos,
		Values:   values,
		Info:     info,

		BinaryLadder: ladder,
		Update:       *proof,
	}, nil
}

// infos returns the UpdateInfo structures for all of the versions inserted in
// the log entry at `pos`. If `withValues` is true, it also returns the value
// for each version.
func (u *updater) infos(pos uint64, withValues bool) ([]structs.LabelValue, []structs.UpdateInfo, error) {
	var vers []uint32
	for i := u.ver; i < int64(len(u.index)) && u.index[i] == pos; i++ {
		if i >= 1<<32 {
			return nil, nil, errors.New("version counter overflow")
		}
		vers = append(vers, uint32(i))
	}
	results, err := u.tree.batchGetVersion(u.label, vers)
	if err != nil {
		return nil, nil, err
	}

	var (
		values []structs.LabelValue
		info   []structs.UpdateInfo
	)
	for _, res := range results {
		if withValues {
			values = append(values, structs.LabelValue{Value: res.Value.Value})
		}
		info = append(info, structs.UpdateInfo{
			Opening:      res.Opening,
			UpdateSuffix: res.Value.UpdateSuffix,
		})
	}
	return values, info, nil
}

// ladder returns the binary ladder steps for an Update operation where
// `startVer` was the first new version inserted and `endVer` was the last new
// version inserted, in log entry `pos`. `startVer` and `endVer` are the same if
// only one version was inserted.
func (u *updater) ladder(startVer, endVer int64, pos uint64) ([]structs.BinaryLadderStep, error) {
	if startVer > endVer || endVer >= 1<<32 {
		return nil, errors.New("version counter overflow")
	}
	versions := updateLadderVersions(uint32(startVer), uint32(endVer))
	steps, _, err := u.tree.getBinaryLadder(u.label, versions, startVer-1, pos)
	return steps, err
}

// reloadTree refreshes the `tree` and `index` fields of `u` to cover new
// versions created in the log entry `pos`.
func (u *updater) reloadTree(pos uint64) error {
	tree, err := NewTree(u.tree.config, u.tree.tx, u.tree.updater)
	if err != nil {
		return err
	} else if tree.n() <= pos {
		return errors.New("reloaded tree does not contain new versions of label")
	}
	tree.now = u.tree.now

	index, err := u.tree.getIndex(u.label)
	if err != nil {
		return err
	} else if len(index) == 0 || index[len(index)-1] < pos {
		return errors.New("reloaded index does not contain new versions of label")
	}

	u.tree = tree
	u.index = index
	return nil
}
