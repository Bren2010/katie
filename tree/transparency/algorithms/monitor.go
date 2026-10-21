package algorithms

import (
	"cmp"
	"errors"
	"slices"

	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// ContactState wraps the state maintained by a user that has looked up
// (potentially multiple versions of) a single label.
type ContactState struct {
	// Entries contains a slice of log entries with the greatest version of the
	// label that's been proven to exist at that point. It is sorted by
	// position and no position is duplicate.
	Entries []structs.MonitorMapEntry
}

// newContactState returns a new ContactState containing `entries`, which may be
// in any order. `n` is the size of the tree. It returns an error if any
// position is duplicate or not in the tree.
func newContactState(entries []structs.MonitorMapEntry, n uint64) (*ContactState, error) {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b structs.MonitorMapEntry) int {
		return cmp.Compare(a.Position, b.Position)
	})
	if len(sorted) > 0 && sorted[len(sorted)-1].Position >= n {
		return nil, errors.New("contact monitoring state has position not in tree")
	}
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Position == sorted[i-1].Position {
			return nil, errors.New("contact monitoring state has duplicate position")
		}
	}
	return &ContactState{Entries: sorted}, nil
}

// Set sets the version of the label for log entry `pos` to `ver`, adding an
// entry for it if one doesn't exist. `n` is the size of the tree.
func (cs *ContactState) Set(pos uint64, ver uint32, n uint64) error {
	entries := make([]structs.MonitorMapEntry, 0, len(cs.Entries)+1)

	path := math.RightDirectPath(pos, n)
	newEntry := structs.MonitorMapEntry{Position: pos, Version: ver}
	inserted := false

	for _, entry := range cs.Entries {
		if entry.Position < pos {
			entries = append(entries, entry)
			continue
		} else if entry.Version > ver {
			return errors.New("contact monitoring state has unexpectedly great version of label")
		}
		if !inserted {
			entries, inserted = append(entries, newEntry), true
		}
		if entry.Position != pos && !slices.Contains(path, entry.Position) {
			entries = append(entries, entry)
		}
	}
	if !inserted {
		entries = append(entries, newEntry)
	}

	cs.Entries = entries
	return nil
}

// OwnerState wraps the state maintained by the owner of a single label.
type OwnerState struct {
	// Starting is the position of the rightmost distinguished log entry that
	// has been verified by owner monitoring, or nil if no log entries have been
	// verified yet.
	Starting *uint64
	// PreviousVers is the greatest version of the label that existed at
	// `Starting`, followed by the greatest version at each log entry in the
	// left direct path of `Starting`, ending at the first log entry that was
	// expired or where the label doesn't exist.
	PreviousVers []uint32
	// UpcomingVers is the position of each upcoming new version of the label.
	UpcomingVers []uint64
}

// newOwnerState returns a new OwnerState from the retained state in `from`.
// `n` is the size of the tree. It returns an error if the retained state is not
// internally consistent or references log entries not in the tree.
func newOwnerState(from *structs.LabelOwnerState, n uint64) (*OwnerState, error) {
	if from == nil {
		return nil, errors.New("label owner state not provided")
	} else if from.Starting != nil && *from.Starting >= n {
		return nil, errors.New("starting position is not in tree")
	} else if len(from.UpcomingVers) > 0 && slices.Max(from.UpcomingVers) >= n {
		return nil, errors.New("upcoming version is not in tree")
	}

	// Verify that PreviousVers has at most one entry for `Starting` and each
	// log entry in its left direct path, and that it never increases.
	if from.Starting == nil {
		if len(from.PreviousVers) != 0 {
			return nil, errors.New("previous versions provided without starting position")
		}
	} else if len(from.PreviousVers) > 1+len(math.LeftDirectPath(*from.Starting)) {
		return nil, errors.New("unexpected number of previous versions")
	}
	for i := 1; i < len(from.PreviousVers); i++ {
		if from.PreviousVers[i] > from.PreviousVers[i-1] {
			return nil, errors.New("previous versions are not monotonic")
		}
	}

	// Verify that UpcomingVers is sorted and to the right of `Starting`.
	for i, pos := range from.UpcomingVers {
		if from.Starting != nil && pos <= *from.Starting {
			return nil, errors.New("upcoming version is not to the right of starting position")
		} else if i > 0 && pos < from.UpcomingVers[i-1] {
			return nil, errors.New("upcoming versions are not sorted")
		}
	}

	os := &OwnerState{
		Starting:     from.Starting,
		PreviousVers: from.PreviousVers,
		UpcomingVers: from.UpcomingVers,
	}
	if os.GreatestVersion() >= 1<<32 {
		return nil, errors.New("greatest version of label is too large")
	}
	return os, nil
}

func (os *OwnerState) Struct() *structs.LabelOwnerState {
	return &structs.LabelOwnerState{
		Starting:     os.Starting,
		PreviousVers: os.PreviousVers,
		UpcomingVers: os.UpcomingVers,
	}
}

func (os *OwnerState) previousVer(i int) int64 {
	if i >= len(os.PreviousVers) {
		return -1
	}
	return int64(os.PreviousVers[i])
}

// VerAtStarting returns the version of the label that exists at `os.Starting`,
// or -1 if the label didn't exist yet (or `os.Starting` is nil).
func (os *OwnerState) VerAtStarting() int64 { return os.previousVer(0) }

// SetStarting sets the owner's starting position to be `x`, which must not be
// to the left of the current starting position. It consumes any values from
// `os.UpcomingVers` and recomputes `os.PreviousVers`.
func (os *OwnerState) SetStarting(x uint64) {
	// Every log entry in the direct path of `x` and to its left is either:
	// - to the right of the current starting position,
	// - the current starting position itself, or
	// - in the left direct path of the current starting position.
	// The greatest version at any of these points is already known.
	var previousVers []uint32
	for _, y := range append([]uint64{x}, math.LeftDirectPath(x)...) {
		ver := os.GreatestVersionAt(y)
		if ver < 0 {
			break
		}
		previousVers = append(previousVers, uint32(ver))
	}

	idx, _ := slices.BinarySearch(os.UpcomingVers, x+1)
	os.Starting = &x
	os.PreviousVers = previousVers
	os.UpcomingVers = os.UpcomingVers[idx:]
}

// GreatestVersionAt returns the greatest version of the label that would've
// been expected to exist at `x`, or -1 if the label didn't exist yet.
//
// For `x` to the left of `os.Starting`, this is only accurate if `x` is in the
// direct path of `os.Starting` (and wasn't expired when the owner's state was
// initialized). Otherwise, the version at `Starting` is returned.
func (os *OwnerState) GreatestVersionAt(x uint64) int64 {
	if os.Starting != nil && x < *os.Starting {
		i := slices.Index(math.LeftDirectPath(*os.Starting), x)
		return os.previousVer(i + 1)
	}
	idx, _ := slices.BinarySearch(os.UpcomingVers, x+1)
	return os.VerAtStarting() + int64(idx)
}

// GreatestVersion returns the absolute greatest version of the label known.
func (os *OwnerState) GreatestVersion() int64 {
	return os.VerAtStarting() + int64(len(os.UpcomingVers))
}

// LastUpdate returns the position of the last known update, or `os.Starting` if
// there have been no recent updates. It returns nil if neither exists, meaning
// that an update may be at any position, including 0.
func (os *OwnerState) LastUpdate() *uint64 {
	if len(os.UpcomingVers) > 0 {
		last := os.UpcomingVers[len(os.UpcomingVers)-1]
		return &last
	}
	return os.Starting
}

// Monitor wraps the state that needs to be passed in to a monitoring operation.
type Monitor struct {
	config    *structs.PublicConfig
	provider  *DataProvider
	rightmost uint64 // Timestamp of rightmost log entry.
	treeSize  uint64 // Number of log entries.

	Contact *ContactState
	Owner   *OwnerState
}

// NewMonitor returns a new Monitor structure. The public config for the
// Transparency Log is `config` and the size of the tree is `treeSize`.
func NewMonitor(config *structs.PublicConfig, treeSize uint64, provider *DataProvider) (*Monitor, error) {
	if treeSize == 0 {
		return nil, errors.New("unable to monitor empty tree")
	}
	rightmost, err := provider.GetTimestamp(treeSize - 1)
	if err != nil {
		return nil, err
	}

	return &Monitor{
		config:    config,
		provider:  provider,
		rightmost: rightmost,
		treeSize:  treeSize,
	}, nil
}

// SetContactState sets the contact monitoring state to contain `entries`, which
// may be in any order. It returns an error if any position is duplicate or not
// in the tree.
func (m *Monitor) SetContactState(entries []structs.MonitorMapEntry) error {
	contact, err := newContactState(entries, m.treeSize)
	if err != nil {
		return err
	}
	m.Contact = contact
	return nil
}

// SetOwnerState sets the label owner's state from the retained state in `from`.
// It returns an error if the retained state is not internally consistent or
// references log entries not in the tree.
func (m *Monitor) SetOwnerState(from *structs.LabelOwnerState) error {
	owner, err := newOwnerState(from, m.treeSize)
	if err != nil {
		return err
	}
	m.Owner = owner
	return nil
}

// verifyGreatestVersion obtains a search binary ladder from log entry `x` and
// verifies that `ver` is the greatest version of the label that exists there,
// or that no version of the label exists if `ver` is -1. Redundant lookups are
// omitted if `omit` is true.
func (m *Monitor) verifyGreatestVersion(x uint64, ver int64, omit bool) error {
	target, expected := uint32(0), -1
	if ver >= 0 {
		target, expected = uint32(ver), 0
	}
	res, err := m.provider.GetSearchBinaryLadder(x, target, omit)
	if err != nil {
		return err
	} else if res != expected {
		return errors.New("binary ladder inconsistent with expected greatest version of label")
	}
	return nil
}

// distinguishedAncestor returns the first distinguished log entry that is on
// the direct path of `target` and to its right. It may return `target` itself
// if `target` is distinguished.
func (m *Monitor) distinguishedAncestor(target uint64) (*uint64, error) {
	// List all distinguished log entries in the direct path of `target` and to
	// its right.
	var (
		distinguished []uint64

		curr  uint64 = math.Root(m.treeSize)
		left  uint64 = 0
		right uint64 = m.rightmost
	)
	for m.config.IsDistinguished(left, right) {
		if curr >= target {
			distinguished = append(distinguished, curr)
		}

		if curr == target {
			break
		}

		timestamp, err := m.provider.GetTimestamp(curr)
		if err != nil {
			return nil, err
		}
		if curr > target {
			curr, right = math.Left(curr), timestamp
		} else {
			curr, left = math.Right(curr, m.treeSize), timestamp
		}
	}

	// Return the lowest one.
	if len(distinguished) == 0 {
		return nil, nil
	}
	return &distinguished[len(distinguished)-1], nil
}

func (m *Monitor) contactMonitor(x uint64, ver uint32, received map[uint64]uint32) (*uint64, error) {
	// Determine whether this log entry is distinguished, or what the first
	// distinguished log entry on its direct path and to its right is.
	stop, err := m.distinguishedAncestor(x)
	if err != nil {
		return nil, err
	} else if stop != nil && *stop == x { // If distinguished, we're done.
		return nil, nil
	}

	// Compute the list of log entries to inspect: those on the direct path of
	// `x` and to its right, stopping just after the first distinguished one.
	var inspect []uint64
	for _, parent := range math.RightDirectPath(x, m.treeSize) {
		inspect = append(inspect, parent)
		if stop != nil && *stop == parent {
			// If the Contact Monitoring operation is being executed in the
			// context of an Owner Monitoring operation, and the given log entry
			// is equal to or to the right of the owner's `start` position, skip
			// inspecting the final distinguished log entry.
			if m.Owner != nil && (m.Owner.Starting == nil || *m.Owner.Starting <= x) {
				inspect = inspect[:len(inspect)-1]
			}
			break
		}
	}

	// For each log entry in the computed list:
	for _, y := range inspect {
		// If a binary ladder was already received from this log entry, verify
		// that it was for a greater version.
		if receivedVer, ok := received[y]; ok {
			if receivedVer <= ver {
				return nil, errors.New("monitoring detected versions that are not monotonic")
			}
			return nil, nil
		}
		// Obtain and verify a monitoring binary ladder.
		if err := m.provider.GetMonitoringBinaryLadder(y, ver); err != nil {
			return nil, err
		}
		received[y] = ver
	}

	if stop != nil { // We reached a distinguished log entry.
		return nil, nil
	} else if len(inspect) > 0 { // We moved forward without reaching a DLE.
		return &inspect[len(inspect)-1], nil
	} // We made no progress...
	return &x, nil
}

// ContactMonitor executes the algorithm from Section 8.2 using the contact
// monitoring state in m.Contact. If no future monitoring is required, m.Contact
// is set to be nil. Otherwise, m.Contact is updated with the state for the next
// monitoring request.
func (m *Monitor) ContactMonitor() error {
	if m.Contact == nil {
		return nil
	}

	// Setup our map of log entries that we've already received a binary ladder
	// from. This is initialized with the current contents of m.Contact to catch
	// the case where one monitoring path ends where another one starts.
	received := make(map[uint64]uint32)
	for _, entry := range m.Contact.Entries {
		received[entry.Position] = entry.Version
	}

	// Monitor each version of the label, from right to left.
	var entries []structs.MonitorMapEntry
	for _, entry := range slices.Backward(m.Contact.Entries) {
		updated, err := m.contactMonitor(entry.Position, entry.Version, received)
		if err != nil {
			return err
		} else if updated != nil {
			entries = append(entries, structs.MonitorMapEntry{Position: *updated, Version: entry.Version})
		}
	}

	// Update retained state.
	if len(entries) == 0 {
		m.Contact = nil
		return nil
	}
	return m.SetContactState(entries)
}

// init returns the list of log entries to verify if an owner is starting their
// monitoring at `starting`. `x` is the current log entry, and `left` and
// `right` are the bounds used to determine distinguished status.
func (m *Monitor) init(starting, x, left, right uint64) ([]uint64, error) {
	if !m.config.IsDistinguished(left, right) {
		return nil, errors.New("requested starting position is not distinguished")
	}
	timestamp, err := m.provider.GetTimestamp(x)
	if err != nil {
		return nil, err
	}
	isExpired := m.config.IsExpired(timestamp, m.rightmost)

	if x < starting {
		// Starting position is to our right, so recurse right.
		if noRightChild(x, m.treeSize) {
			return nil, errors.New("requested starting position is right of the rightmost log entry")
		}
		children, err := m.init(starting, math.Right(x, m.treeSize), timestamp, right)
		if err != nil {
			return nil, err
		} else if isExpired {
			return children, nil
		}
		return append(children, x), nil
	} else if x == starting {
		// We've reached the requested starting position. We already know it's
		// distinguished and just need to verify that it's unexpired.
		if isExpired {
			return nil, errors.New("requested starting position is expired")
		}
		return []uint64{x}, nil
	}
	// Starting position is to our left, so recurse left.
	if noLeftChild(x) || isExpired {
		return nil, errors.New("requested starting position is invalid")
	}
	return m.init(starting, math.Left(x), left, timestamp)
}

// InitEntries returns the log entries that will be inspected while initializing
// the owner's state with the given starting position. This does not actually
// perform owner state initialization, that is done by OwnerInit.
func (m *Monitor) InitEntries(starting *uint64) ([]uint64, error) {
	if starting == nil {
		return nil, nil
	}
	return m.init(*starting, math.Root(m.treeSize), 0, m.rightmost)
}

// OwnerInit runs the algorithm from the first portion of Section 8.3 to
// initialize a label owner's state. `starting` contains the log entry where the
// label owner wants their ownership to start, and `vers` contains the version
// of the label that exists at each log entry returned by InitEntries.
func (m *Monitor) OwnerInit(starting *uint64, vers []uint32) ([]uint64, error) {
	if m.Owner != nil {
		return nil, errors.New("label owner state is already initialized")
	}
	xs, err := m.InitEntries(starting)
	if err != nil {
		return nil, err
	}

	// Verify that the expected number of versions was provided and that each
	// version is less than or equal to the one prior.
	if len(vers) > len(xs) {
		return nil, errors.New("unexpected number of versions provided to owner initialization algorithm")
	}
	for i := 1; i < len(vers); i++ {
		if vers[i] > vers[i-1] {
			return nil, errors.New("unexpected increase in label version")
		}
	}

	// Obtain a search binary ladder from each log entry in `xs`. Verify that
	// the ladder terminates in a way that is consistent with the version
	// provided in `vers`.
	for i, x := range xs {
		ver := int64(-1)
		if i < len(vers) {
			ver = int64(vers[i])
		}
		if err := m.verifyGreatestVersion(x, ver, false); err != nil {
			return nil, err
		}
	}

	// Setup OwnerState object.
	m.Owner = &OwnerState{Starting: starting, PreviousVers: slices.Clone(vers)}

	return xs, nil
}

// ownerMonitor performs a depth-first walk of every distinguished log entry
// that is to the right of `owner.state.Starting` and requests a search binary
// ladder from each of them for the expected greatest version of the label. `x`
// is the current log entry, `left` and `right` are the bounds used for
// determining distinguished status.
//
// It returns the position of the rightmost log entry verified in the subtree
// rooted at `x`, or nil if none were. The owner's state is not modified.
func (m *Monitor) ownerMonitor(x, left, right uint64) (*uint64, error) {
	// If the current log entry is not distinguished, stop.
	if !m.config.IsDistinguished(left, right) {
		return nil, nil
	}

	// If the current log entry's index is less than or equal to that of the log
	// entry advertised by the user, recurse to its right child.
	if m.Owner.Starting != nil && x <= *m.Owner.Starting {
		if noRightChild(x, m.treeSize) {
			return nil, nil
		}
		timestamp, err := m.provider.GetTimestamp(x)
		if err != nil {
			return nil, err
		}
		return m.ownerMonitor(math.Right(x, m.treeSize), timestamp, right)
	}

	// If the current log entry has a left child, recurse to the left child.
	var verified *uint64
	if hasLeftChild(x) {
		timestamp, err := m.provider.GetTimestamp(x)
		if err != nil {
			return nil, err
		}
		verified, err = m.ownerMonitor(math.Left(x), left, timestamp)
		if err != nil {
			return nil, err
		}
	}

	// If a stop condition has been reached, stop.
	ver := m.Owner.GreatestVersionAt(x)
	if m.provider.StopCondition(x, ver) {
		return verified, nil
	}

	// Obtain a search binary ladder from the current log entry where the target
	// version is the greatest version of the label expected to exist at this
	// point, based on the label owner's state.
	if err := m.verifyGreatestVersion(x, ver, false); err != nil {
		return nil, err
	}
	verified = &x

	// If the current log entry has a right child, recurse to the right child.
	if noRightChild(x, m.treeSize) {
		return verified, nil
	}
	timestamp, err := m.provider.GetTimestamp(x)
	if err != nil {
		return nil, err
	}
	rightVerified, err := m.ownerMonitor(math.Right(x, m.treeSize), timestamp, right)
	if err != nil {
		return nil, err
	} else if rightVerified != nil {
		return rightVerified, nil
	}
	return verified, nil
}

// OwnerMonitor runs the algorithm from the second portion of Section 8.3. It
// performs owner monitoring, ensuring that the label has not been modified
// without the label owner's permission.
func (m *Monitor) OwnerMonitor() error {
	if m.Owner == nil {
		return errors.New("label owner state has not been initialized")
	}

	verified, err := m.ownerMonitor(math.Root(m.treeSize), 0, m.rightmost)
	if err != nil {
		return err
	} else if verified != nil {
		m.Owner.SetStarting(*verified)
	}

	return nil
}
