package transparency

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// Mutate takes as input a set of new label-value pairs to insert, and a set of
// existing labels to remove. Version counters are automatically assigned. Both
// `add` and `remove` may be empty, in which case a new log entry is added
// without modifying the prefix tree.
//
// It returns the AuditorUpdate structure for the Third-Party Auditor, if any.
// If an error is returned, no changes are made to the tree.
func (t *Tree) Mutate(add []LabelValue, remove [][]byte) (*structs.AuditorUpdate, error) {
	if err := t.checkWritable(); err != nil {
		return nil, err
	}
	// Discard any changes that were buffered before an error. This is a no-op
	// after a successful commit, since committing clears the buffer.
	defer t.tx.Rollback()

	n := t.n()
	handle := algorithms.NewProducedProofHandle(t.config.Suite, t.tx, nil)
	provider := algorithms.NewDataProvider(t.config.Suite, handle)

	// Decide on the timestamp for the new log entry. We do this so early
	// because it affects which distinguished log entries exist, which affects
	// which modifications are allowable.
	timestamp := uint64(t.now().UnixMilli())
	if n > 0 {
		rightmost, err := provider.GetTimestamp(n - 1)
		if err != nil {
			return nil, err
		} else if timestamp < rightmost {
			return nil, errors.New("refusing to issue tree head: current time is less than previous timestamp")
		}
	}

	// Compute what the rightmost distinguished log entry will be after the new
	// log entry is added.
	provider.AddRetained(nil, map[uint64]structs.LogEntry{n: {Timestamp: timestamp}})
	prevDLE, err := algorithms.PreviousRightmost(t.config.Public(), n+1, provider)
	if err != nil {
		return nil, err
	}

	// Group the mutation requests by label. Process the mutation for each label
	// individually and collect the set of additions and removals that we want
	// to do to the prefix tree.
	mutations, err := t.groupByLabel(add, remove)
	if err != nil {
		return nil, err
	} else if err := t.checkMutationSize(mutations); err != nil {
		return nil, err
	}
	var (
		prefixAdd    []prefix.Entry
		prefixRemove [][]byte
	)
	for _, mutation := range mutations {
		pa, pr, err := t.mutateLabel(n, prevDLE, mutation)
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
	mut, err := prefixTree.Mutate(n, prefixAdd, prefixRemove)
	if err != nil {
		return nil, err
	}

	// Issue new tree head.
	if err := t.issueTreeHead(n, timestamp, mut.Root); err != nil {
		return nil, err
	}

	// Construct the AuditorUpdate structure to return.
	removedEntries := make([]prefix.Entry, len(prefixRemove))
	for i, vrfOutput := range prefixRemove {
		removedEntries[i] = prefix.Entry{VrfOutput: vrfOutput, Commitment: mut.Commitments[i]}
	}
	return &structs.AuditorUpdate{
		Timestamp: timestamp,

		Added:   prefixAdd,
		Removed: removedEntries,
		Leaves:  mut.Leaves,

		Proof: mut.Proof,
	}, nil
}

type labelMutation struct {
	label  []byte
	index  []uint64
	add    []structs.UpdateValue
	remove bool
}

// groupByLabel takes the full set of requested additions and removals and
// organizes them by label. This function also handles looking up the index for
// all of the affected labels.
func (t *Tree) groupByLabel(add []LabelValue, remove [][]byte) ([]labelMutation, error) {
	allLabels := make(map[string][]byte)

	// Group adds and removes by label.
	groupedAdds := make(map[string][]structs.UpdateValue)
	for _, pair := range add {
		labelStr := fmt.Sprintf("%x", pair.Label)
		allLabels[labelStr] = pair.Label
		groupedAdds[labelStr] = append(groupedAdds[labelStr], pair.Value)
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

// checkMutationSize returns an error if the requested mutations would produce
// an AuditorUpdate that is too large to serialize. This is checked before
// anything is written to the database.
//
// Every list in an AuditorUpdate, including those in its PrefixProof, is
// prefixed with a uint32 count. Given `a` added and `r` removed prefix tree
// entries:
//   - At most `r` leaves are moved, since each removal can move at most one
//     sibling leaf.
//   - The PrefixProof has one search result per added, removed, or moved
//     entry, so at most `a + 2r` results.
//   - Each search result contributes at most one proof element per level of
//     the prefix tree, and the prefix tree has at most 8*HashSize levels.
//
// So it suffices to check that `(a + 2r) * 8*HashSize` fits in a uint32.
func (t *Tree) checkMutationSize(mutations []labelMutation) error {
	var added, removed uint64
	for _, mut := range mutations {
		added += uint64(len(mut.add))
		if mut.remove {
			removed += uint64(len(mut.index))
		}
	}

	maxDepth := 8 * uint64(t.config.Suite.HashSize())
	maxEntries := uint64(math.MaxUint32) / maxDepth
	if added+2*removed > maxEntries {
		return fmt.Errorf("too many changes to fit in an auditor update: %d added, %d removed", added, removed)
	}
	return nil
}

// mutateLabel performs the requested additions and removals for a single label.
// Version counters are assigned sequentially.
func (t *Tree) mutateLabel(n uint64, prevDLE *uint64, mut labelMutation) ([]prefix.Entry, [][]byte, error) {
	var (
		add    []prefix.Entry
		remove [][]byte

		label, index = mut.label, mut.index
	)

	if mut.remove && len(index) > 0 {
		// The label is not eligible for deletion if it has been modified since
		// the last distinguished log entry was created.
		if prevDLE == nil || index[len(index)-1] > *prevDLE {
			return nil, nil, fmt.Errorf("unable to delete label that was modified recently: %s", label)
		}
		// A Third-Party Auditor can only verify that a label was published in
		// a distinguished log entry if it processed that log entry.
		if t.config.Mode == structs.ThirdPartyAuditing && *prevDLE < t.config.AuditorStartPos {
			return nil, nil, fmt.Errorf("unable to delete label before auditor has processed a distinguished log entry: %s", label)
		}

		// Delete the label's index.
		t.tx.DeleteIndex(label)

		// Delete the value and VRF output of each version.
		for ver := range index {
			t.tx.DeleteVersion(label, uint32(ver))

			vrfOutput, _, err := t.computeVrfOutput(label, uint32(ver))
			if err != nil {
				return nil, nil, err
			}
			remove = append(remove, vrfOutput)
		}

		index = index[:0]
	}

	for _, value := range mut.add {
		ver := uint32(len(index))

		vrfOutput, _, err := t.computeVrfOutput(mut.label, ver)
		if err != nil {
			return nil, nil, err
		}
		commitment, err := t.putVersion(mut.label, ver, value)
		if err != nil {
			return nil, nil, err
		}

		add = append(add, prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment})
		index = append(index, n)
	}
	if len(mut.add) > 0 {
		if err := t.putIndex(mut.label, index); err != nil {
			return nil, nil, err
		}
	} // TODO: Sequence dummy versions if necessary.

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
	}
	t.tx.Put(n, raw)

	// Compute the new log entry leaf hash and append it to the log tree.
	leaf, err := logEntry.Hash(t.config.Suite)
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
	}
	t.tx.PutTreeHead(rawTreeHead)
	if err := t.commit(); err != nil {
		return err
	}

	t.treeHead = treeHead
	return nil
}
