package transparency

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// Mutate takes as input a set of new label-value pairs to insert, and a set of
// existing label-version pairs to remove. Version counters are automatically
// assigned/unassigned.
//
// It returns the AuditorUpdate structure for the Third-Party Auditor, if any.
func (t *Tree) Mutate(add []LabelValue, remove [][]byte) (*structs.AuditorUpdate, error) {
	n := uint64(0)
	if t.treeHead != nil {
		n = t.treeHead.TreeSize
	}

	handle := newProducedProofHandle(t.config.Suite, t.tx, nil)
	provider := newDataProvider(t.config.Suite, handle)
	rightmostDLE, err := rightmostDistinguished(t.config.Public(), n, provider)
	if err != nil {
		return nil, err
	}

	// Group the mutation requests by label. Process the mutation for each label
	// individually and collect the set of additions and removals that we want
	// to do to the prefix tree.
	mutations, err := t.groupByLabel(add, remove)
	if err != nil {
		return nil, err
	}
	var (
		prefixAdd    []prefix.Entry
		prefixRemove [][]byte
	)
	for _, mutation := range mutations {
		pa, pr, err := t.mutateLabel(n, rightmostDLE, mutation)
		if err != nil {
			return nil, err
		}
		prefixAdd = append(prefixAdd, pa...)
		prefixRemove = append(prefixRemove, pr...)
	}

	// Sort the new additions and removals by VRF output to avoid accidentally
	// leaking information to the Third-Party Auditor (if there is one).
	slices.SortFunc(prefixAdd, func(a, b prefix.Entry) int {
		return bytes.Compare(a.VrfOutput, b.VrfOutput)
	})
	slices.SortFunc(prefixRemove, bytes.Compare)

	// Make the requested modifications to the prefix tree.
	prefixTree := prefix.NewTree(t.config.Suite, t.tx.PrefixStore())
	prefixRoot, prefixProof, commitments, err := prefixTree.Mutate(n, prefixAdd, prefixRemove)
	if err != nil {
		return nil, err
	}

	// Issue new tree head.
	timestamp := uint64(time.Now().UnixMilli())
	if n > 0 {
		rightmost, err := provider.GetTimestamp(n - 1)
		if err != nil {
			return nil, err
		} else if timestamp < rightmost {
			return nil, errors.New("refusing to issue tree head: current timestamp is less than previous timestamp")
		}
	}
	if err := t.issueTreeHead(n, timestamp, prefixRoot); err != nil {
		return nil, err
	}

	// Construct the AuditorUpdate structure to return.
	removedEntries := make([]prefix.Entry, len(prefixRemove))
	for i, vrfOutput := range prefixRemove {
		removedEntries[i] = prefix.Entry{VrfOutput: vrfOutput, Commitment: commitments[i]}
	}
	return &structs.AuditorUpdate{
		Timestamp: timestamp,
		Added:     prefixAdd,
		Removed:   removedEntries,
		Proof:     *prefixProof,
	}, nil
}

type labelMutation struct {
	label  []byte
	index  []uint64
	add    []LabelValue
	remove bool
}

// groupByLabel takes the full set of requested additions and removals and
// organizes them by label. This function also handles looking up the index for
// all of the affected labels.
func (t *Tree) groupByLabel(add []LabelValue, remove [][]byte) ([]labelMutation, error) {
	allLabels := make(map[string][]byte)

	// Group adds and removes by label.
	groupedAdds := make(map[string][]LabelValue)
	for _, pair := range add {
		labelStr := fmt.Sprintf("%x", pair.Label)
		allLabels[labelStr] = pair.Label
		groupedAdds[labelStr] = append(groupedAdds[labelStr], pair)
	}

	groupedRemoves := make(map[string]struct{})
	for _, label := range remove {
		labelStr := fmt.Sprintf("%x", label)
		allLabels[labelStr] = label
		groupedRemoves[labelStr] = struct{}{}
	}

	// Extract the full set of labels / labels converted to strings.
	labelStrs := make([]string, 0, len(allLabels))
	labels := make([][]byte, 0, len(allLabels))
	for labelStr, label := range allLabels {
		labelStrs = append(labelStrs, labelStr)
		labels = append(labels, label)
	}

	// Batch lookup the index for each label.
	indices, err := t.batchGetIndex(labels)
	if err != nil {
		return nil, err
	}

	// Combine into slice where each entry is one label's mutation information.
	out := make([]labelMutation, len(labelStrs))
	for i, labelStr := range labelStrs {
		_, ok := groupedRemoves[labelStr]
		out[i] = labelMutation{
			label:  labels[i],
			index:  indices[i],
			add:    groupedAdds[labelStr],
			remove: ok,
		}
	}
	return out, nil
}

// mutateLabel performs the requested additions and removals for a single label.
// Version counters are assigned sequentially.
func (t *Tree) mutateLabel(n uint64, rightmostDLE *uint64, mut labelMutation) ([]prefix.Entry, [][]byte, error) {
	var (
		add    []prefix.Entry
		remove [][]byte

		label, index = mut.label, mut.index
	)

	if mut.remove {
		// The label is not eligible for deletion if it has been modified since
		// the last distinguished log entry was created.
		if len(index) > 0 && rightmostDLE != nil && index[len(index)-1] >= *rightmostDLE {
			return nil, nil, fmt.Errorf("unable to delete label that was modified recently: %s", label)
		}

		// Delete the label's index.
		if err := t.tx.DeleteIndex(label); err != nil {
			return nil, nil, err
		}

		// Delete the value and VRF output of each version.
		for ver := range index {
			if err := t.tx.DeleteVersion(label, uint32(ver)); err != nil {
				return nil, nil, err
			}
			vrfOutput, _, err := t.computeVrfOutput(label, uint32(ver))
			if err != nil {
				return nil, nil, err
			}
			remove = append(remove, vrfOutput)
		}

		index = index[:0]
	}

	for _, pair := range mut.add {
		ver := uint32(len(index))

		vrfOutput, _, err := t.computeVrfOutput(pair.Label, ver)
		if err != nil {
			return nil, nil, err
		}
		commitment, err := t.putVersion(pair.Label, ver, pair.Value)
		if err != nil {
			return nil, nil, err
		}

		add = append(add, prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment})
		index = append(index, n)
	}
	if len(mut.add) > 0 {
		if err := t.putIndex(mut.add[0].Label, index); err != nil {
			return nil, nil, err
		}
	}

	return add, remove, nil
}

// issueTreeHead takes as input the current tree size, the new rightmost
// timestamp, and the new prefix tree root. It adds a new log entry to the right
// edge of the log tree and then signs and commits a new tree head.
func (t *Tree) issueTreeHead(n, timestamp uint64, prefixRoot []byte) error {
	logEntry := structs.LogEntry{
		Timestamp:  timestamp,
		PrefixTree: prefixRoot,
	}

	// Encode the new log entry and write it to the database.
	raw, err := structs.Marshal(&logEntry)
	if err != nil {
		return err
	} else if err := t.tx.Put(n, raw); err != nil {
		return err
	}

	// Compute the new log entry leaf hash and append it to the log tree.
	leaf, err := logEntryHash(t.config.Suite, logEntry)
	if err != nil {
		return err
	}
	fullSubtrees, err := log.NewTree(t.config.Suite, t.tx.LogStore()).Append(n, leaf)
	if err != nil {
		return err
	}
	root, err := log.Root(t.config.Suite, n+1, fullSubtrees)
	if err != nil {
		return err
	}

	// Sign and persist the new tree head.
	tbs, err := structs.Marshal(&structs.TreeHeadTBS{
		Config:   t.config.Public(),
		TreeSize: n + 1,
		Root:     root,
	})
	if err != nil {
		return err
	}
	signature, err := t.config.SignatureKey.Sign(tbs)
	if err != nil {
		return err
	}
	treeHead := &structs.TreeHead{TreeSize: n + 1, Signature: signature}
	rawTreeHead, err := structs.Marshal(treeHead)
	if err != nil {
		return err
	} else if err := t.tx.PutTreeHead(rawTreeHead); err != nil {
		return err
	} else if err := t.tx.Commit(); err != nil {
		return err
	}

	t.treeHead = treeHead

	return nil
}
