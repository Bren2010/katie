package algorithms

import (
	"errors"
	"slices"

	"github.com/Bren2010/katie/tree/transparency/math"
)

// nonDistinguishedAncestor starts at the root node and proceeds down towards
// `target`. It returns the first node in this path that is not distinguished,
// or `nil` if `target` itself is distinguished.
func (m *Monitor) nonDistinguishedAncestor(target uint64) (*uint64, error) {
	x, left, right := math.Root(m.treeSize), uint64(0), m.rightmost

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
			x, left = math.Right(x, m.treeSize), timestamp
		} else {
			x, right = math.Left(x), timestamp
		}
	}
}

// verifyPreviousTree verifies that no unexpected versions of the label exist in
// the previous tree, which is the log tree up to but excluding the log entry
// `pos` where new versions of the label were added. This is a greatest-version
// search for the previous greatest version of the label, starting from the
// first log entry on the previous tree's frontier that isn't distinguished in
// the current tree.
func (m *Monitor) verifyPreviousTree(pos uint64) error {
	// If the new versions were added in log entry 0, the previous tree is
	// empty and there is nothing to verify.
	if pos == 0 {
		return nil
	}

	greatestVer := m.Owner.GreatestVersion()
	lastUpdate := m.Owner.LastUpdate()

	// Determine the first log entry in the previous tree that is not
	// distinguished in the current tree. This is done by finding the first log
	// entry in the direct path of `pos-1` that is not distinguished, and then
	// moving left until we get an x <= pos-1. Moving left without checking if
	// the left child exists is safe because we already know we're on the direct
	// path of `pos-1`.
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

	// Lookups that would be omitted in a greatest-version search are omitted
	// here too. That search would've already inspected x's parent on the
	// frontier (if any), so record the versions it would've proven to be
	// included there. If no version of the label existed, there's nothing to
	// record.
	tracker := m.provider.handle.Tracker()
	var ladder []uint32
	if greatestVer >= 0 {
		ladder = math.SearchBinaryLadder(uint32(greatestVer), uint32(greatestVer), nil, nil)
	}
	if x != math.Root(pos) {
		parent := math.Parent(x, pos)
		tracker.AddLadder(parent, true, m.Owner.GreatestVersionAt(parent), ladder)
	}

	// Starting from the identified log entry, proceed down the remainder of
	// the previous tree's frontier from left to right.
	for {
		if lastUpdate != nil && x <= *lastUpdate {
			// A binary ladder would have already been received from this log
			// entry when processing a previous label update, so skip it. The
			// lookups it would have contained are still omitted from later
			// ladders, as if it had been inspected.
			tracker.AddLadder(x, true, m.Owner.GreatestVersionAt(x), ladder)
		} else if err := m.verifyGreatestVersion(x, greatestVer, true); err != nil {
			return err
		}

		if x == pos-1 {
			return nil
		}
		x = math.Right(x, pos)
	}
}

// Update runs the algorithm from Section 9.1 to verify that some new versions
// of the label were added to the tree correctly. `pos` is the position of the
// log entry where the new versions were added. `versions` is the number of new
// versions added.
func (m *Monitor) Update(pos uint64, versions int) error {
	if m.Owner == nil {
		return errors.New("label owner state has not been initialized")
	} else if pos >= m.treeSize {
		return errors.New("given log entry does not exist")
	} else if last := m.Owner.LastUpdate(); last != nil && pos <= *last {
		return errors.New("update position must be to the right of any previous version")
	} else if versions < 1 {
		return errors.New("unexpected number of new versions created")
	}

	greatestVer := m.Owner.GreatestVersion()
	endVer := greatestVer + int64(versions)
	if endVer >= 1<<32 {
		return errors.New("unexpected number of new versions created")
	}

	// Compute the list of versions that were created in this update but that
	// wouldn't be looked up in a search binary ladder for the greatest version.
	ladder := math.SearchBinaryLadder(uint32(endVer), uint32(endVer), nil, nil)
	var additional []uint32
	for ver := greatestVer + 1; ver <= endVer; ver++ {
		if !slices.Contains(ladder, uint32(ver)) {
			additional = append(additional, uint32(ver))
		}
	}

	// Verify that no unexpected new versions exist in the previous tree.
	if err := m.verifyPreviousTree(pos); err != nil {
		return err
	}

	// Determine if the new log entry is distinguished. If it isn't, obtain a
	// PrefixProof with a search binary ladder for the new greatest version.
	res, err := m.nonDistinguishedAncestor(pos)
	if err != nil {
		return err
	}
	distinguished := res == nil
	if !distinguished {
		if err := m.verifyGreatestVersion(pos, endVer, true); err != nil {
			return err
		}
	}
	// Obtain a PrefixProof with lookups corresponding to any new versions of
	// the label that weren't looked up in a search binary ladder for the new
	// greatest version.
	if err := m.provider.GetInclusionProof(pos, additional); err != nil {
		return err
	}

	// If the log entry isn't distinguished, add the new version to the owner's
	// contact monitoring state.
	if !distinguished {
		if m.Contact == nil {
			m.Contact = &ContactState{}
		}
		if err := m.Contact.Set(pos, uint32(endVer), m.treeSize); err != nil {
			return err
		}
	}

	// Retain the position of the new versions for later verification.
	for range versions {
		m.Owner.UpcomingVers = append(m.Owner.UpcomingVers, pos)
	}
	return nil
}
