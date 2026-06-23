package transparency

import (
	"context"
	"errors"
	"slices"

	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/auditor/wire"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

func (t *Tree) Update(
	ctx context.Context,
	req *structs.UpdateRequest,
) (<-chan wire.UpdateResponse, error) {
	ch := make(chan wire.UpdateResponse)

	up := newUpdater(t, ctx, ch)
	if err := up.setRequest(req); err != nil {
		return nil, err
	}
	go up.process()

	return ch, nil
}

func (t *Tree) ManagerUpdate(
	ctx context.Context,
	req *structs.ManagerUpdateRequest,
) (<-chan wire.UpdateResponse, error) {
	ch := make(chan wire.UpdateResponse)

	up := newUpdater(t, ctx, ch)
	if err := up.setManagerRequest(req); err != nil {
		return nil, err
	}
	go up.process()

	return ch, nil
}

type updater struct {
	tree *Tree
	ctx  context.Context
	ch   chan wire.UpdateResponse

	last   *uint64
	label  []byte
	values []structs.UpdateValue

	index []uint64 // index is the label's index.
	ver   int      // ver is the next version the user needs to be informed about.
}

func newUpdater(t *Tree, ctx context.Context, ch chan wire.UpdateResponse) *updater {
	return &updater{tree: t, ctx: ctx, ch: ch}
}

func (u *updater) setRequest(req *structs.UpdateRequest) error {
	values := make([]structs.UpdateValue, len(req.Values))
	for i, val := range req.Values {
		values[i] = structs.UpdateValue{Value: val.Value}
	}
	indices, err := u.tree.batchGetIndex([][]byte{req.Label})
	if err != nil {
		return err
	}

	u.last = req.Last
	u.label = req.Label
	u.values = values
	u.index = indices[0]
	u.ver = 0
	if req.GreatestVersion != nil {
		u.ver = int(*req.GreatestVersion) + 1
	}
	return nil
}

func (u *updater) setManagerRequest(req *structs.ManagerUpdateRequest) error {
	indices, err := u.tree.batchGetIndex([][]byte{req.Label})
	if err != nil {
		return err
	}

	u.last = req.Last
	u.label = req.Label
	u.values = req.Values
	u.index = indices[0]
	u.ver = 0
	if req.GreatestVersion != nil {
		u.ver = int(*req.GreatestVersion) + 1
	}
	return nil
}

func (u *updater) send(res wire.UpdateResponse) bool {
	select {
	case u.ch <- res:
		return true
	case <-u.ctx.Done():
		return false
	}
}

func (u *updater) process() {
	defer close(u.ch)

	// If the greatest version that was advertised by the user is less than the
	// actual greatest version, first push out UpdateResponses for the
	// unknown versions.
	for u.ver < len(u.index) {
		out, err := u.next(true)
		if ok := u.send(wire.UpdateResponse{Out: out, Err: err}); !ok {
			return
		} else if err != nil {
			return
		}

		last := u.tree.treeHead.TreeSize
		u.last = &last
	}

	// Submit new versions to be sequenced and reload the tree once they are.
	if len(u.values) == 0 {
		return
	} else if u.tree.updater == nil {
		u.send(wire.UpdateResponse{
			Err: errors.New("transparency tree does not support user-submitted label updates"),
		})
		return
	}
	res := make(chan uint64, 1)
	req := UpdateRequest{Label: u.label, Values: u.values, Response: res}
	select {
	case u.tree.updater <- req:
	case <-u.ctx.Done():
		return
	}

	var (
		pos uint64
		ok  bool
	)
	select {
	case pos, ok = <-res:
		if !ok {
			u.send(wire.UpdateResponse{
				Err: errors.New("failed to sequence requested new versions of label"),
			})
			return
		}
	case <-u.ctx.Done():
		return
	}
	if err := u.reloadTree(pos); err != nil {
		u.send(wire.UpdateResponse{Err: err})
		return
	}

	// Push out the UpdateResponse for our new version of the label, and any
	// others that were created concurrently.
	for u.ver < len(u.index) {
		out, err := u.next(u.index[u.ver] != pos)
		if ok := u.send(wire.UpdateResponse{Out: out, Err: err}); !ok {
			return
		} else if err != nil {
			return
		}

		last := u.tree.treeHead.TreeSize
		u.last = &last
	}
}

func (u *updater) next(withValues bool) (*structs.UpdateResponse, error) {
	t, pos := u.tree, u.index[u.ver]

	values, info, err := u.infos(pos, withValues)
	if err != nil {
		return nil, err
	}
	ladder, err := u.ladder(u.ver-len(info), u.ver-1)
	if err != nil {
		return nil, err
	}

	fth, n, nP, m, err := t.fullTreeHead(u.last)
	if err != nil {
		return nil, err
	}

	handle := algorithms.NewProducedProofHandle(t.config.Suite, t.tx, u.index)
	provider := algorithms.NewDataProvider(t.config.Suite, handle)

	if err := t.updateView(u.last, provider); err != nil {
		return nil, err
	}
	monitor, err := algorithms.NewMonitor(t.config.Public(), n, provider)
	if err != nil {
		return nil, err
	} else if err := monitor.Update(pos, len(info)); err != nil {
		return nil, err
	}
	proof, err := provider.Output(n, nP, m)
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
	var (
		values []structs.LabelValue
		info   []structs.UpdateInfo
	)

	for ; u.ver < len(u.index) && u.index[u.ver] == pos; u.ver++ {
		res, err := u.tree.getVersion(u.label, uint32(u.ver))
		if err != nil {
			return nil, nil, err
		}
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
// version inserted. `startVer` and `endVer` are the same if only one version
// was inserted.
func (u *updater) ladder(startVer, endVer int) ([]structs.BinaryLadderStep, error) {
	// Compute the set of versions that we need to compute VRF outputs for:
	// versions in a search binary ladder for `endVer`, plus versions in the
	// range [startVer, endVer), excluding versions that exist in the search
	// binary ladder for `startVer-1`.
	dedup := make(map[uint32]struct{})

	for _, ver := range math.SearchBinaryLadder(uint32(endVer), uint32(endVer), nil, nil) {
		dedup[ver] = struct{}{}
	}
	for ver := startVer; ver < endVer; ver++ {
		dedup[uint32(ver)] = struct{}{}
	}
	if startVer == 0 {
		delete(dedup, 0)
	} else {
		for _, ver := range math.SearchBinaryLadder(uint32(startVer-1), uint32(startVer-1), nil, nil) {
			delete(dedup, ver)
		}
	}

	// Convert `dedup` into a sorted slice of versions.
	versions := make([]uint32, 0, len(dedup))
	for ver := range dedup {
		versions = append(versions, ver)
	}
	slices.Sort(versions)

	// Compute VRF outputs and load commitments for (maybe) existing lesser
	// versions.
	return u.tree.getBinaryLadder(u.label, versions, startVer-1, u.tree.treeHead.TreeSize)
}

// reloadTree refreshes the `tree` and `index` fields of `u` to cover new
// versions created in the log entry `pos`.
func (u *updater) reloadTree(pos uint64) error {
	tree, err := NewTree(u.tree.config, u.tree.tx, u.tree.updater)
	if err != nil {
		return err
	} else if tree.treeHead.TreeSize <= pos {
		return errors.New("reloaded tree does not contain new versions of label")
	}

	indices, err := u.tree.batchGetIndex([][]byte{u.label})
	if err != nil {
		return err
	}
	index := indices[0]
	if len(index) == 0 || index[len(index)-1] < pos {
		return errors.New("reloaded index does not contain new versions of label")
	}

	u.tree = tree
	u.index = index
	return nil
}
