package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// Tree is an implementation of a Transparency Tree that handles all state
// management, the evaluation of a VRF, and generating/opening commitments.
type Tree struct {
	config      structs.PrivateConfig
	tx          db.TransparencyStore
	treeHead    *structs.TreeHead
	auditorHead *structs.AuditorTreeHead
}

func NewTree(config structs.PrivateConfig, tx db.TransparencyStore) (*Tree, error) {
	rawTreeHead, rawAuditor, err := tx.GetTreeHead()
	if err != nil {
		return nil, err
	}

	var (
		treeHead    *structs.TreeHead
		auditorHead *structs.AuditorTreeHead
	)
	if rawTreeHead != nil {
		treeHead, err = structs.NewTreeHead(bytes.NewBuffer(rawTreeHead))
		if err != nil {
			return nil, err
		}
	}
	if config.Mode == structs.ThirdPartyAuditing && rawAuditor != nil {
		auditorHead, err = structs.NewAuditorTreeHead(bytes.NewBuffer(rawAuditor))
		if err != nil {
			return nil, err
		}
	}

	return &Tree{
		config:      config,
		tx:          tx,
		treeHead:    treeHead,
		auditorHead: auditorHead,
	}, nil
}

func (t *Tree) fullTreeHead(last *uint64) (fth *structs.FullTreeHead, n uint64, nP, m *uint64, err error) {
	if t.treeHead == nil {
		return nil, 0, nil, nil, errors.New("can not operate on an empty tree")
	} else if last != nil {
		if *last == t.treeHead.TreeSize {
			return &structs.FullTreeHead{}, t.treeHead.TreeSize, nil, nil, nil
		} else if *last > t.treeHead.TreeSize {
			return nil, 0, nil, nil, errors.New("tree size advertised by user is greater than current tree size")
		}
	}

	fth = &structs.FullTreeHead{TreeHead: t.treeHead, AuditorTreeHead: t.auditorHead}
	n = t.treeHead.TreeSize
	if t.auditorHead != nil {
		nP = &t.auditorHead.TreeSize
	}
	if last != nil {
		m = last
	}
	return
}

func (t *Tree) Search(req *structs.SearchRequest) (*structs.SearchResponse, error) {
	fth, n, nP, m, err := t.fullTreeHead(req.Last)
	if err != nil {
		return nil, err
	}
	info, err := getLabelInfo(t.tx, req.Label)
	if err != nil {
		return nil, err
	}
	handle := newProducedProofHandler(t.config.Suite, t.tx, n, nP, m, info)

	// Determine which versions we will need VRF outputs for and compute them.
	var ladder []uint32
	if req.Version == nil {
		greatestVer := uint32(len(info))
		ladder = math.SearchBinaryLadder(greatestVer, greatestVer, nil, nil)
	} else {
		ladder = math.SearchBinaryLadder(*req.Version, *req.Version, nil, nil)
	}
	steps := make([]structs.BinaryLadderStep, 0, len(ladder))
	for _, ver := range ladder {
		vrfOutput, proof := computeVrfOutput(t.config, req.Label, ver)
		handle.AddVersion(ver, vrfOutput, nil)
		steps = append(steps, structs.BinaryLadderStep{Proof: proof})
	}

	// // Build the list of log entries to fetch. These are the log entries
	// // required to update the user's view of the log, followed by whichever log
	// // entries (may) be needed for a fixed-version or greatest-version search.
	// var m uint64
	// if req.Last != nil {
	// 	m = *req.Last
	// }
	// dedup := make(map[uint64]struct{})
	// for _, pos := range math.UpdateView(m, t.treeHead.TreeSize) {
	// 	dedup[pos] = struct{}{}
	// }
	// if req.Version == nil {
	// 	for _, pos := range math.Frontier(t.treeHead.TreeSize) {
	// 		dedup[pos] = struct{}{}
	// 	}
	// } else {
	// 	var pos uint64
	// 	if int(*req.Version) < len(info) {
	// 		pos = info[*req.Version]
	// 	} else if int(*req.Version) > len(info) {
	// 		pos = t.treeHead.TreeSize - 1
	// 	}
	// 	for _, pos := range math.SearchPath(pos, t.treeHead.TreeSize) {
	// 		dedup[pos] = struct{}{}
	// 	}
	// }

	// fth, err := t.fullTreeHead(req.Last)
	// if err != nil {
	// 	return nil, err
	// }
}
