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

// Mutate takes as input a set of new label versions to insert, and a set of
// existing labels to remove. Each label may appear at most once in `add`.
// Version counters are automatically assigned, unless a starting version is
// given in Third-Party Management mode, in which case dummy versions are
// sequenced as necessary to skip to it. Both `add` and `remove` may be empty,
// in which case a new log entry is added without modifying the prefix tree.
//
// It returns the AuditorUpdate structure for the Third-Party Auditor, if any.
// If an error is returned, no changes are made to the tree.
func (t *Tree) Mutate(add []LabelUpdate, remove [][]byte) (*structs.AuditorUpdate, error) {
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
	skip   uint32                // The number of dummy versions to sequence
	add    []structs.UpdateValue // New versions of label to create
	remove bool                  // Whether to remove existing versions of label
}

// groupByLabel takes the full set of requested additions and removals and
// organizes them by label. This function also handles looking up the index for
// all of the affected labels, and determining how many dummy versions need to
// be sequenced for each.
func (t *Tree) groupByLabel(add []LabelUpdate, remove [][]byte) ([]labelMutation, error) {
	out := make([]labelMutation, 0, len(add)+len(remove))
	startVers := make([]*uint32, 0, len(add))
	byLabel := make(map[string]int, len(add)+len(remove)) // Position of each label in `out`.

	for _, update := range add {
		if len(update.Values) == 0 {
			return nil, fmt.Errorf("no values given for new versions of label: %s", update.Label)
		} else if update.StartingVersion != nil && t.config.Mode != structs.ThirdPartyManagement {
			return nil, errors.New("starting version may only be given in third party management mode")
		} else if _, ok := byLabel[string(update.Label)]; ok {
			return nil, fmt.Errorf("multiple update requests for same label: %s", update.Label)
		}
		byLabel[string(update.Label)] = len(out)
		startVers = append(startVers, update.StartingVersion)
		out = append(out, labelMutation{label: update.Label, add: update.Values})
	}

	for _, label := range remove {
		i, ok := byLabel[string(label)]
		if ok && out[i].remove {
			return nil, fmt.Errorf("multiple remove requests for same label: %s", label)
		} else if ok {
			out[i].remove = true
		} else {
			byLabel[string(label)] = len(out)
			out = append(out, labelMutation{label: label, remove: true})
		}
	}

	// Batch lookup the index for each label.
	labels := make([][]byte, len(out))
	for i, mut := range out {
		labels[i] = mut.label
	}
	indices, err := t.batchGetIndex(labels)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].index = indices[i]
		if i < len(add) {
			out[i].skip, err = skippedVersions(out[i], startVers[i])
			if err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// skippedVersions returns the number of dummy versions that need to be
// sequenced before the new versions in `mut`, such that the first new version
// is assigned the requested starting version, if any.
func skippedVersions(mut labelMutation, startVer *uint32) (uint32, error) {
	if startVer == nil {
		return 0, nil
	}
	next := int64(len(mut.index))
	if mut.remove {
		next = 0
	}
	if int64(*startVer) < next {
		return 0, fmt.Errorf("starting version %d of label is less than next version %d: %s", *startVer, next, mut.label)
	}
	return uint32(int64(*startVer) - next), nil
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
		added += uint64(mut.skip) + uint64(len(mut.add))
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
// Version counters are assigned sequentially, starting with any dummy versions.
func (t *Tree) mutateLabel(n uint64, prevDLE *uint64, mut labelMutation) ([]prefix.Entry, [][]byte, error) {
	var (
		add    []prefix.Entry
		remove [][]byte

		label, index = mut.label, mut.index
	)

	// If requested, delete all existing versions of the label.
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

	// Sequence dummy versions, which map the VRF output of each skipped
	// label-version pair to an all-zero commitment. No value is stored for
	// these versions.
	for range mut.skip {
		ver := uint32(len(index))

		vrfOutput, _, err := t.computeVrfOutput(mut.label, ver)
		if err != nil {
			return nil, nil, err
		}
		commitment := make([]byte, t.config.Suite.HashSize())

		add = append(add, prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment})
		index = append(index, n)
	}

	// Add new versions of the label to the tree.
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
