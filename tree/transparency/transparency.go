package transparency

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

type LabelValue struct {
	Label []byte
	Value structs.UpdateValue
}

type LabelVersion struct {
	Label   []byte
	Version uint32
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

// Mutate takes a set of new label-value pairs to insert. Version counters are
// automatically assigned. The same label may be present multiple times, in
// which case each subsequent instance is assigned to the subsequent version.
//
// It returns the AuditorUpdate structure for the Third-Party Auditor, if any.
func (t *Tree) Mutate(add []LabelValue, remove []LabelVersion) (*structs.AuditorUpdate, error) {
	n := uint64(0)
	if t.treeHead != nil {
		n = t.treeHead.TreeSize
	}

	// Organize the requested mutations into groups of the same label.
	allLabels := make(map[string][]byte)

	groupedAdds := make(map[string][]LabelValue)
	for _, pair := range add {
		labelStr := fmt.Sprintf("%x", pair.Label)
		allLabels[labelStr] = pair.Label
		groupedAdds[labelStr] = append(groupedAdds[labelStr], pair)
	}

	groupedRemoves := make(map[string][]LabelVersion)
	for _, pair := range remove {
		labelStr := fmt.Sprintf("%x", pair.Label)
		allLabels[labelStr] = pair.Label
		groupedRemoves[labelStr] = append(groupedRemoves[labelStr], pair)
	}

	// Batch look up each label's index.
	labelStrs := make([]string, 0, len(allLabels))
	labels := make([][]byte, 0, len(allLabels))
	for labelStr, label := range allLabels {
		labelStrs = append(labelStrs, labelStr)
		labels = append(labels, label)
	}

	indices, err := t.getLabelIndices(labels)
	if err != nil {
		return nil, err
	}

	// Process the mutation for each label individually and collect the set of
	// additions and removals that we want to do to the prefix tree.
	var (
		prefixAdd    []prefix.Entry
		prefixRemove [][]byte
	)
	for i, labelStr := range labelStrs {
		pa, pr, err := t.mutateLabel(indices[i], groupedAdds[labelStr], groupedRemoves[labelStr])
		if err != nil {
			return nil, err
		}
		prefixAdd = append(prefixAdd, pa...)
		prefixRemove = append(prefixRemove, pr...)
	}

	// Sort the new additions and removals by VRF output to avoid
	// unintentionally leaking information to the Third-Party Auditor, if there
	// is one.
	slices.SortFunc(prefixAdd, func(a, b prefix.Entry) int {
		return bytes.Compare(a.VrfOutput, b.VrfOutput)
	})
	slices.SortFunc(prefixRemove, bytes.Compare)

	// Make the required modifications to the prefix tree.
	prefixTree := prefix.NewTree(t.config.Suite, t.tx.PrefixStore())
	prefixRoot, prefixProof, err := prefixTree.Mutate(n, prefixAdd, prefixRemove)
	if err != nil {
		return nil, err
	}

	// Compute the new log entry leaf hash and append it to the log tree.
	logEntry := structs.LogEntry{
		Timestamp:  uint64(time.Now().UnixMilli()), // TODO: Check monotonic?
		PrefixTree: prefixRoot,
	}
	leaf, err := logEntryHash(t.config.Suite, logEntry)
	if err != nil {
		return nil, err
	}
	fullSubtrees, err := log.NewTree(t.config.Suite, t.tx.LogStore()).Append(n, leaf)
	if err != nil {
		return nil, err
	}
	root, err := log.Root(t.config.Suite, n+1, fullSubtrees)
	if err != nil {
		return nil, err
	}

	// Sign and persist the new tree head.
	tbs, err := structs.Marshal(&structs.TreeHeadTBS{
		Config:   t.config.Public(),
		TreeSize: n + 1,
		Root:     root,
	})
	if err != nil {
		return nil, err
	}
	signature, err := t.config.SignatureKey.Sign(tbs)
	if err != nil {
		return nil, err
	}
	treeHead, err := structs.Marshal(&structs.TreeHead{TreeSize: n + 1, Signature: signature})
	if err != nil {
		return nil, err
	} else if err := t.tx.SetTreeHead(treeHead); err != nil {
		return nil, err
	} else if err := t.tx.Commit(); err != nil {
		return nil, err
	}

	return &structs.AuditorUpdate{
		Timestamp: logEntry.Timestamp,
		Added:     prefixAdd,
		Removed:   prefixRemove,
		Proof:     *prefixProof,
	}, nil
}

// addLabelValues adds a new set of label values to the Transparency Log. All
// entries in `add` must be for the same label.
func (t *Tree) addLabelValues(n uint64, prefixAdd *[]prefix.Entry, group []LabelValue) error {
	index, err := t.getLabelIndex(group[0].Label)
	if err != nil {
		return err
	}

	for _, pair := range group {
		ver := uint32(len(index))

		vrfOutput, _, err := t.computeVrfOutput(pair.Label, ver)
		if err != nil {
			return err
		}
		commitment, err := t.setLabelValue(group[0].Label, ver, pair.Value)
		if err != nil {
			return err
		}

		*prefixAdd = append(*prefixAdd, prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment})
		index = append(index, n)
	}

	return t.setLabelIndex(group[0].Label, index)
}

// func (t *Tree) fullTreeHead(last *uint64) (fth *structs.FullTreeHead, n uint64, nP, m *uint64, err error) {
// 	if t.treeHead == nil {
// 		return nil, 0, nil, nil, errors.New("can not operate on an empty tree")
// 	} else if last != nil {
// 		if *last == t.treeHead.TreeSize {
// 			return &structs.FullTreeHead{}, t.treeHead.TreeSize, nil, nil, nil
// 		} else if *last > t.treeHead.TreeSize {
// 			return nil, 0, nil, nil, errors.New("tree size advertised by user is greater than current tree size")
// 		}
// 	}

// 	fth = &structs.FullTreeHead{TreeHead: t.treeHead, AuditorTreeHead: t.auditorHead}
// 	n = t.treeHead.TreeSize
// 	if t.auditorHead != nil {
// 		nP = &t.auditorHead.TreeSize
// 	}
// 	if last != nil {
// 		m = last
// 	}
// 	return
// }

// func (t *Tree) updateView(last *uint64, provider *dataProvider) error {
// 	if last != nil {
// 		// Load frontier log entries.
// 		frontier := math.Frontier(*last)
// 		results, err := t.tx.BatchGet(frontier)
// 		if err != nil {
// 			return err
// 		}
// 		logEntries := make(map[uint64]structs.LogEntry)
// 		for _, pos := range frontier {
// 			raw, ok := results[pos]
// 			if !ok {
// 				return errors.New("expected frontier log entry not found")
// 			}
// 			entry, err := structs.NewLogEntry(t.config.Suite, bytes.NewBuffer(raw))
// 			if err != nil {
// 				return err
// 			}
// 			logEntries[pos] = *entry
// 		}
// 		provider.AddRetained(nil, logEntries)
// 	}

// 	return updateView(t.config.Public(), t.treeHead.TreeSize, last, provider)
// }

// func (t *Tree) Search(req *structs.SearchRequest) (*structs.SearchResponse, error) {
// 	fth, n, nP, m, err := t.fullTreeHead(req.Last)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Load label index and determine greatest version that exists, if any.
// 	index, err := t.getLabelIndex(req.Label)
// 	if err != nil {
// 		return nil, err
// 	}
// 	greatest := uint32(len(index))
// 	if greatest > 0 {
// 		greatest--
// 	}
// 	handle := newProducedProofHandler(t.config.Suite, t.tx, index)

// 	// Determine which versions we will need VRF outputs for, and also load the
// 	// target version of the label.
// 	var (
// 		ladder     []uint32
// 		labelValue *structs.LabelValue
// 	)
// 	if req.Version == nil {
// 		ladder = math.SearchBinaryLadder(greatest, greatest, nil, nil)
// 		labelValue, err = t.getLabelValue(req.Label, greatest)
// 	} else {
// 		ladder = math.SearchBinaryLadder(*req.Version, *req.Version, nil, nil)
// 		labelValue, err = t.getLabelValue(req.Label, *req.Version)
// 	}
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Compute VRF outputs and proofs for ladder.
// 	steps := make([]structs.BinaryLadderStep, len(ladder))
// 	for i, ver := range ladder {
// 		vrfOutput, proof, err := t.computeVrfOutput(req.Label, ver)
// 		if err != nil {
// 			return nil, err
// 		}
// 		handle.AddVersion(ver, vrfOutput, nil)
// 		steps[i] = structs.BinaryLadderStep{Proof: proof}
// 	}

// 	// Execute algorithms to update the user's view of the tree, and either a
// 	// greatest-version or fixed-version search.
// 	provider := newDataProvider(t.config.Suite, handle)
// 	if err := t.updateView(req.Last, provider); err != nil {
// 		return nil, err
// 	}
// 	if req.Version == nil {
// 		_, err = greatestVersionSearch(t.config.Public(), greatest, t.treeHead.TreeSize, provider)
// 	} else {
// 		_, err = fixedVersionSearch(t.config.Public(), *req.Version, t.treeHead.TreeSize, provider)
// 	}
// 	if err != nil {
// 		return nil, err
// 	}
// 	combinedProof, err := provider.Output(n, nP, m)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Populate commitment field of appropriate BinaryLadderStep structures.
// 	for i, ver := range ladder {
// 		commitment := handle.versions[ver].Commitment
// 		if req.Version == nil && ver != greatest {
// 			steps[i].Commitment = commitment
// 		} else if req.Version != nil && ver != *req.Version {
// 			steps[i].Commitment = commitment
// 		}
// 	}

// 	// Put together final SearchResponse structure.
// 	var outputVer *uint32
// 	if req.Version == nil {
// 		outputVer = &greatest
// 	}
// 	return &structs.SearchResponse{
// 		FullTreeHead: *fth,

// 		Version: outputVer,
// 		Opening: labelValue.Opening,
// 		Value:   labelValue.Value,

// 		BinaryLadder: steps,
// 		Search:       *combinedProof,
// 	}, nil
// }
