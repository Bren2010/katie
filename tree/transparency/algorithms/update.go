package algorithms

import (
	"errors"

	"github.com/Bren2010/katie/tree/transparency/math"
)

// nonDistinguishedAncestor starts at the root node and proceeds down towards
// `target`. It returns the first node in this path that is not distinguished,
// or `nil` if `target` itself is distinguished.
func (m *Monitor) nonDistinguishedAncestor(target uint64) (*uint64, error) {
	x := math.Root(m.treeSize)
	left := uint64(0)
	right, err := m.provider.GetTimestamp(m.treeSize - 1)
	if err != nil {
		return nil, err
	}

	for {
		if !m.config.IsDistinguished(left, right) {
			return &x, nil
		} else if x == target {
			return nil, nil
		}

		// Get the log entry timestamp and proceed to the left or right child,
		// depending on which gets us closer to `target`.
		timestamp, err := m.provider.GetTimestamp(x)
		if err != nil {
			return nil, err
		}
		if x < target {
			x = math.Right(x, m.treeSize)
			left = timestamp
		} else {
			x = math.Left(x)
			right = timestamp
		}
	}
}

func (m *Monitor) verifyPreviousTree(pos uint64) error {
	if pos == 0 {
		panic("unreachable")
	}
	greatestVer := m.Owner.GreatestVersion()
	lastUpdate := m.Owner.LastUpdate()

	// Determine the first log entry in the previous tree that is not
	// distinguished in the current tree.
	res, err := m.nonDistinguishedAncestor(pos - 1)
	if err != nil {
		return err
	} else if res == nil {
		return nil
	}
	x := *res
	for x > pos-1 {
		x = math.Left(x)
	}

	// Populate the version tracker with information on what lookups to omit.
	if greatestVer >= 0 {
		tracker := m.provider.handle.Tracker()
		ladder := math.SearchBinaryLadder(uint32(greatestVer), uint32(greatestVer), nil, nil)

		// Compute version omissions from x itself. This requires looking at
		// which lookups might've succeeded in a Greatest Version search that
		// started at x's parent (if any).
		if x != math.Root(pos) {
			parent := math.Parent(x, pos)
			tracker.AddLadder(parent, true, m.Owner.GreatestVersionAt(parent), ladder)
		}
		// Compute version omissions from all of x's children. It's not strictly
		// true that `greatestVer` exists at `x` (in fact, it might not). But
		// we know we won't do any lookups until `greatestVer` exists, so it
		// doesn't change the algorithm's output.
		tracker.AddLadder(x, true, greatestVer, ladder)
	}

	// Starting from the identified log entry, proceed down the remainder of
	// the previous tree's frontier from left to right.
	for {
		// If a binary ladder would have already been received from this log
		// entry in step 2.2 when processing a previous label update, skip
		// this log entry.
		if x <= lastUpdate {
			goto MoveRight
		}

		// Obtain a search binary ladder from this log entry where the target
		// version is the previous greatest version of the label. Verify that
		// the binary ladder terminates in a way that is consistent with the
		// previous greatest version of the label being the greatest that
		// existed.
		if greatestVer < 0 {
			res, err := m.provider.GetSearchBinaryLadder(x, 0, true)
			if err != nil {
				return err
			} else if res != -1 {
				return errors.New("binary ladder inconsistent with expected greatest version of label")
			}
		} else {
			res, err := m.provider.GetSearchBinaryLadder(x, uint32(greatestVer), true)
			if err != nil {
				return err
			} else if res != 0 {
				return errors.New("binary ladder inconsistent with expected greatest version of label")
			}
		}

	MoveRight:
		if x == pos-1 {
			return nil
		}
		x = math.Right(x, pos)
	}
}

// Update verifies that some new versions of the label were added to the tree
// correctly. `pos` is the position of the log entry where the new versions were
// added. `versions` is the number of new versions added.
func (m *Monitor) Update(pos uint64, versions int) error {
	if m.Owner == nil {
		return errors.New("label owner state has not been initialized")
	} else if pos >= m.treeSize {
		return errors.New("given log entry does not exist")
	} else if pos <= m.Owner.LastUpdate() {
		return errors.New("update position must be to the right of any previous version")
	} else if versions < 1 {
		return errors.New("unexpected number of new versions created")
	}

	greatestVer := m.Owner.GreatestVersion()
	if val := greatestVer + versions; val < 0 || val >= (1<<32)-1 {
		return errors.New("unexpected number of new versions created")
	}
	startVer := uint32(greatestVer + 1)
	endVer := uint32(greatestVer + versions)

	// Compute the list of versions that were created in this update but that
	// wouldn't be looked up in a search binary ladder for the greatest version.
	ladder := make(map[uint32]struct{})
	for _, ver := range math.SearchBinaryLadder(endVer, endVer, nil, nil) {
		ladder[ver] = struct{}{}
	}
	additional := make([]uint32, 0)
	for ver := startVer; ver <= endVer; ver++ {
		if _, ok := ladder[ver]; !ok {
			additional = append(additional, ver)
		}
	}

	// Verify that no unexpected new versions exist in the previous tree.
	if err := m.verifyPreviousTree(pos); err != nil {
		return err
	}

	// Determine if the new log entry is distinguished.
	res, err := m.nonDistinguishedAncestor(pos)
	if err != nil {
		return err
	}
	if res == nil { // The log entry is distinguished.
		// Obtain a PrefixProof with lookups corresponding only to new versions
		// of the label that would not be looked up in a search binary ladder
		// for the new greatest version.
		if err := m.provider.GetInclusionProof(pos, additional); err != nil {
			return err
		}
	} else { // The log entry is not distinguished.
		// Obtain a PrefixProof with a search binary ladder for the new greatest
		// version, and a PrefixProof with lookups corresponding to any other
		// new versions that weren't looked up in the search binary ladder.
		res, err := m.provider.GetSearchBinaryLadder(pos, endVer, true)
		if err != nil {
			return err
		} else if res != 0 {
			return errors.New("binary ladder inconsistent with expected greatest version of label")
		}
		if err := m.provider.GetInclusionProof(pos, additional); err != nil {
			return err
		}

		// Add the new version to the owner's contact monitoring state.
		if m.Contact == nil {
			m.Contact = &ContactState{Ptrs: make(map[uint64]uint32)}
		}
		m.Contact.Ptrs[pos] = endVer
	}

	// Retain the position of the new versions for later verification.
	for range versions {
		m.Owner.UpcomingVers = append(m.Owner.UpcomingVers, pos)
	}
	return nil
}
