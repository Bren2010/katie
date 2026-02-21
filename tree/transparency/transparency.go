package transparency

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

type LabelValue struct {
	Label []byte
	Value structs.UpdateValue
}

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
		buf := bytes.NewBuffer(rawTreeHead)
		treeHead, err = structs.NewTreeHead(buf)
		if err != nil {
			return nil, err
		} else if buf.Len() != 0 {
			return nil, errors.New("unexpected data appended to tree head")
		}
	}
	if config.Mode == structs.ThirdPartyAuditing && rawAuditor != nil {
		buf := bytes.NewBuffer(rawAuditor)
		auditorHead, err = structs.NewAuditorTreeHead(buf)
		if err != nil {
			return nil, err
		} else if buf.Len() != 0 {
			return nil, errors.New("unexpected data appended to auditor tree head")
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

func (t *Tree) updateView(last *uint64, provider *algorithms.DataProvider) error {
	if last != nil { // Load frontier log entries.
		frontier := math.Frontier(*last)

		results, err := t.tx.BatchGet(frontier)
		if err != nil {
			return err
		}

		logEntries := make(map[uint64]structs.LogEntry)
		for _, pos := range frontier {
			raw, ok := results[pos]
			if !ok {
				return errors.New("expected frontier log entry not found")
			}
			buf := bytes.NewBuffer(raw)
			entry, err := structs.NewLogEntry(t.config.Suite, buf)
			if err != nil {
				return err
			} else if buf.Len() != 0 {
				return errors.New("unexpected data appended to log entry")
			}
			logEntries[pos] = *entry
		}

		provider.AddRetained(nil, logEntries)
	}

	return algorithms.UpdateView(t.config.Public(), t.treeHead.TreeSize, last, provider)
}

func (t *Tree) Search(req *structs.SearchRequest) (*structs.SearchResponse, error) {
	fth, n, nP, m, err := t.fullTreeHead(req.Last)
	if err != nil {
		return nil, err
	}

	// Load label index and determine greatest version that exists, if any.
	indices, err := t.batchGetIndex([][]byte{req.Label})
	if err != nil {
		return nil, err
	}
	greatest := len(indices[0]) - 1

	handle := algorithms.NewProducedProofHandle(t.config.Suite, t.tx, indices[0])

	// Determine which versions we will need VRF outputs for, and also load the
	// target version of the label.
	var (
		ladder     []uint32
		labelValue *structs.LabelValue
	)
	if req.Version == nil {
		if greatest < 0 {
			ladder = []uint32{0}
			labelValue, err = t.getVersion(req.Label, 0)
		} else {
			ladder = math.SearchBinaryLadder(uint32(greatest), uint32(greatest), nil, nil)
			labelValue, err = t.getVersion(req.Label, uint32(greatest))
		}
	} else {
		ladder = math.SearchBinaryLadder(*req.Version, *req.Version, nil, nil)
		labelValue, err = t.getVersion(req.Label, *req.Version)
	}
	if err != nil {
		return nil, err
	}

	// Compute VRF outputs and proofs for ladder.
	steps := make([]structs.BinaryLadderStep, len(ladder))
	for i, ver := range ladder {
		vrfOutput, proof, err := t.computeVrfOutput(req.Label, ver)
		if err != nil {
			return nil, err
		}
		handle.AddVersion(ver, vrfOutput, nil)
		steps[i] = structs.BinaryLadderStep{Proof: proof}
	}

	// Execute the algorithm to update the user's view of the tree, and then
	// either a greatest-version or fixed-version search.
	provider := algorithms.NewDataProvider(t.config.Suite, handle)
	if err := t.updateView(req.Last, provider); err != nil {
		return nil, err
	}
	if req.Version == nil {
		if greatest < 0 {
			_, err = algorithms.GreatestVersionSearch(t.config.Public(), 0, t.treeHead.TreeSize, provider)
		} else {
			_, err = algorithms.GreatestVersionSearch(t.config.Public(), uint32(greatest), t.treeHead.TreeSize, provider)
		}
	} else {
		_, err = algorithms.FixedVersionSearch(t.config.Public(), *req.Version, t.treeHead.TreeSize, provider)
	}
	if err != nil && err != algorithms.ErrLabelNotFound {
		return nil, err
	}
	combinedProof, err := provider.Output(n, nP, m)
	if err != nil {
		return nil, err
	}

	// Populate commitment field of appropriate BinaryLadderStep structures.
	for i, ver := range ladder {
		if req.Version == nil && int(ver) != greatest {
			steps[i].Commitment = handle.GetCommitment(ver)
		} else if req.Version != nil && ver != *req.Version {
			steps[i].Commitment = handle.GetCommitment(ver)
		}
	}

	// Put together final SearchResponse structure.
	var outputVer *uint32
	if req.Version == nil {
		ver := uint32(0)
		if greatest > 0 {
			ver = uint32(greatest)
		}
		outputVer = &ver
	}
	return &structs.SearchResponse{
		FullTreeHead: *fth,

		Version: outputVer,
		Opening: labelValue.Opening,
		Value:   labelValue.Value,

		BinaryLadder: steps,
		Search:       *combinedProof,
	}, nil
}
