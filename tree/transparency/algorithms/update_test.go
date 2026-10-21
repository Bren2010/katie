package algorithms

import (
	"slices"
	"testing"
	"time"

	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/test"
)

func TestUpdate(t *testing.T) {
	config := test.Config(t)
	rmw := config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())
	tsMap := make(map[uint64]uint64)
	for pos := range uint64(100) {
		tsMap[pos] = now - 99 + pos
	}

	type testVector struct {
		verMap   map[uint64]uint32
		contact  *ContactState
		owner    *OwnerState
		pos      uint64
		versions int

		requests        []uint64
		searchLadders   []uint64
		inclusionProofs []uint64
	}
	runTest := func(vec testVector) (*ContactState, *OwnerState, error) {
		t.Helper()
		public := config.Public()

		handle := test.NewProofHandle(tsMap, vec.verMap)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, now, provider); err != nil {
			t.Fatal(err)
		}
		monitor, err := NewMonitor(public, 100, provider)
		if err != nil {
			t.Fatal(err)
		}
		monitor.Contact, monitor.Owner = vec.contact, vec.owner
		err = monitor.Update(vec.pos, vec.versions)

		if err := handle.Verify(vec.requests, vec.searchLadders, nil, vec.inclusionProofs); err != nil {
			t.Fatal(err)
		}
		return monitor.Contact, monitor.Owner, err
	}

	// Previous tree is entirely distinguished.
	contact, owner, err := runTest(testVector{
		verMap:   map[uint64]uint32{1: 0},
		owner:    &OwnerState{Starting: new(uint64(0))},
		pos:      1,
		versions: 1,

		requests:      []uint64{63, 95, 99, 31, 15, 7, 3, 1},
		searchLadders: []uint64{},
	})
	if err != nil {
		t.Fatal(err)
	} else if contact != nil {
		t.Fatal("unexpected contact monitoring state")
	}
	verifyOwnerState(t, owner, 0, nil, []uint64{1})

	// Previous tree root is distinguished but path is not.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{63: 0},
		owner:    &OwnerState{Starting: new(uint64(0))},
		pos:      63,
		versions: 1,

		requests:      []uint64{63, 95, 99, 31, 47, 55, 59, 61, 62},
		searchLadders: []uint64{47, 55, 59, 61, 62},
	})
	if err != nil {
		t.Fatal(err)
	} else if contact != nil {
		t.Fatal("unexpected contact monitoring state")
	}
	verifyOwnerState(t, owner, 0, nil, []uint64{63})

	// Previous tree has no distinguished log entries.
	config.ReasonableMonitoringWindow = now
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{63: 0},
		owner:    &OwnerState{Starting: new(uint64(0))},
		pos:      63,
		versions: 1,

		requests:      []uint64{63, 95, 99, 31, 47, 55, 59, 61, 62},
		searchLadders: []uint64{31, 47, 55, 59, 61, 62},
	})
	if err != nil {
		t.Fatal(err)
	} else if contact != nil {
		t.Fatal("unexpected contact monitoring state")
	}
	verifyOwnerState(t, owner, 0, nil, []uint64{63})
	config.ReasonableMonitoringWindow = rmw

	// Skips lookups that overlap with previous Update operations.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{97: 1, 98: 1, 99: 2},
		contact:  contactState(map[uint64]uint32{96: 1}),
		owner:    &OwnerState{Starting: new(uint64(63)), PreviousVers: []uint32{0}, UpcomingVers: []uint64{96}},
		pos:      99,
		versions: 1,

		requests:      []uint64{63, 95, 99, 97, 98},
		searchLadders: []uint64{97, 98, 99},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyContactState(t, contact, map[uint64]uint32{96: 1, 99: 2})
	verifyOwnerState(t, owner, 63, []uint32{0}, []uint64{96, 99})

	// Skips all previous tree lookups if they're unnecessary.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{99: 2},
		contact:  contactState(map[uint64]uint32{98: 1}),
		owner:    &OwnerState{Starting: new(uint64(63)), PreviousVers: []uint32{0}, UpcomingVers: []uint64{98}},
		pos:      99,
		versions: 1,

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{99},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyContactState(t, contact, map[uint64]uint32{98: 1, 99: 2})
	verifyOwnerState(t, owner, 63, []uint32{0}, []uint64{98, 99})

	// New log entry contains multiple versions and is not distinguished.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{99: 9},
		owner:    &OwnerState{Starting: new(uint64(0))},
		pos:      99,
		versions: 10,

		requests:        []uint64{63, 95, 99, 97, 98},
		searchLadders:   []uint64{95, 97, 98, 99},
		inclusionProofs: []uint64{99},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyContactState(t, contact, map[uint64]uint32{99: 9})
	verifyOwnerState(t, owner, 0, nil, []uint64{99, 99, 99, 99, 99, 99, 99, 99, 99, 99})

	// New log entry contains multiple versions and is distinguished.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{63: 9},
		owner:    &OwnerState{Starting: new(uint64(0))},
		pos:      63,
		versions: 10,

		requests:        []uint64{63, 95, 99, 31, 47, 55, 59, 61, 62},
		searchLadders:   []uint64{47, 55, 59, 61, 62},
		inclusionProofs: []uint64{63},
	})
	if err != nil {
		t.Fatal(err)
	} else if contact != nil {
		t.Fatal("unexpected contact monitoring state")
	}
	verifyOwnerState(t, owner, 0, nil, []uint64{63, 63, 63, 63, 63, 63, 63, 63, 63, 63})

	// Rejects proof where previous tree has overlapping version.
	_, _, err = runTest(testVector{
		verMap:   map[uint64]uint32{62: 0, 63: 9},
		owner:    &OwnerState{Starting: new(uint64(0))},
		pos:      63,
		versions: 10,

		requests:        []uint64{63, 95, 99, 31, 47, 55, 59, 61, 62},
		searchLadders:   []uint64{47, 55, 59, 61, 62},
		inclusionProofs: []uint64{},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatal(err)
	}

	// Rejects proof where new log entry has greater than expected version.
	_, _, err = runTest(testVector{
		verMap:   map[uint64]uint32{99: 10},
		owner:    &OwnerState{Starting: new(uint64(0))},
		pos:      99,
		versions: 10,

		requests:        []uint64{63, 95, 99, 97, 98},
		searchLadders:   []uint64{95, 97, 98, 99},
		inclusionProofs: []uint64{},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatal(err)
	}

	// Owner with no starting position can update in log entry 0, where the
	// previous tree is empty.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{0: 0},
		owner:    &OwnerState{},
		pos:      0,
		versions: 1,

		requests:      []uint64{63, 95, 99, 31, 15, 7, 3, 1},
		searchLadders: []uint64{},
	})
	if err != nil {
		t.Fatal(err)
	} else if contact != nil {
		t.Fatal("unexpected contact monitoring state")
	} else if owner.Starting != nil || owner.VerAtStarting() != -1 || !slices.Equal(owner.UpcomingVers, []uint64{0}) {
		t.Fatalf("unexpected owner state: %+v", owner)
	}

	// Owner with no starting position does not skip log entry 0 when verifying
	// the previous tree.
	config.ReasonableMonitoringWindow = now
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{1: 0},
		owner:    &OwnerState{},
		pos:      1,
		versions: 1,

		requests:      []uint64{63, 95, 99, 0, 1},
		searchLadders: []uint64{0, 1},
	})
	if err != nil {
		t.Fatal(err)
	} else if owner.Starting != nil || !slices.Equal(owner.UpcomingVers, []uint64{1}) {
		t.Fatalf("unexpected owner state: %+v", owner)
	}
	verifyContactState(t, contact, map[uint64]uint32{1: 0})
	config.ReasonableMonitoringWindow = rmw

	// New log entry contains one version and is not distinguished.
	// Covered sufficiently above.

	// New log entry contains one version and is distinguished.
	// Covered sufficiently above.
}

// TestUpdateVersionOmission verifies which lookups are omitted from the search
// binary ladders requested by Update.
func TestUpdateVersionOmission(t *testing.T) {
	config := test.Config(t)
	now := uint64(time.Now().UnixMilli())

	tsMap := make(map[uint64]uint64)
	for pos := range uint64(100) {
		tsMap[pos] = now - 99 + pos
	}
	config.ReasonableMonitoringWindow = now + 1

	type testVector struct {
		owner  *OwnerState
		verMap map[uint64]uint32
		prev   uint32
		pos    uint64

		requests      []uint64
		searchLadders []uint64
	}
	runTest := func(vec testVector) {
		t.Helper()
		public := config.Public()

		// Perform a greatest version search.
		handle := test.NewProofHandle(tsMap, vec.verMap)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, vec.pos, nil, now, provider); err != nil {
			t.Fatal(err)
		}
		_, err := GreatestVersionSearch(public, vec.prev, vec.pos, provider)
		if err != nil {
			t.Fatal(err)
		}

		// Use the greatest version search we just did to compute the exact
		// versions we expect to be in each binary ladder that Update requests.
		expected := handle.SearchLadders()

		leftInclusion, rightNonInclusion := handle.Tracker().SearchMaps(vec.pos, true)
		ladder := math.SearchBinaryLadder(vec.prev+1, vec.prev+1, leftInclusion, rightNonInclusion)
		expected = append(expected, ladder)

		expected = expected[len(expected)-len(vec.searchLadders):]

		// Perform the Update operation and check for consistency.
		handle = test.NewProofHandle(tsMap, vec.verMap)
		provider = NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, now, provider); err != nil {
			t.Fatal(err)
		}
		monitor, err := NewMonitor(public, 100, provider)
		if err != nil {
			t.Fatal(err)
		}
		monitor.Owner = vec.owner
		if err := monitor.Update(vec.pos, 1); err != nil {
			t.Fatal(err)
		}

		if err := handle.Verify(vec.requests, vec.searchLadders, nil, nil); err != nil {
			t.Fatal(err)
		} else if err := handle.VerifySearchLadders(expected); err != nil {
			t.Fatal(err)
		}
	}

	// The root of the previous tree is the first log entry inspected, so nothing
	// is omitted from its ladder. Each subsequent ladder omits the versions
	// proven to be included in the one before it.
	runTest(testVector{
		owner:  &OwnerState{Starting: new(uint64(31)), PreviousVers: []uint32{1}},
		verMap: map[uint64]uint32{63: 1, 95: 1, 97: 1, 98: 1, 99: 2},
		prev:   1,
		pos:    99,

		requests:      []uint64{63, 95, 99, 97, 98},
		searchLadders: []uint64{63, 95, 97, 98, 99},
	})

	// Log entries 63 and 95 are skipped because they're at or before the
	// owner's starting position, but the first log entry inspected still omits
	// the versions proven to be included at 95, as if it had been inspected.
	runTest(testVector{
		owner:  &OwnerState{Starting: new(uint64(95)), PreviousVers: []uint32{1}},
		verMap: map[uint64]uint32{63: 1, 95: 1, 97: 1, 98: 1, 99: 2},
		prev:   1,
		pos:    99,

		requests:      []uint64{63, 95, 99, 97, 98},
		searchLadders: []uint64{97, 98, 99},
	})

	// Log entries 63, 95, and 97 are skipped because they're at or before the
	// owner's last update. The greatest version at 97 was only created there,
	// but the search is considered to have covered it.
	runTest(testVector{
		owner:  &OwnerState{Starting: new(uint64(63)), PreviousVers: []uint32{0}, UpcomingVers: []uint64{97}},
		verMap: map[uint64]uint32{63: 0, 95: 0, 97: 1, 98: 1, 99: 2},
		prev:   1,
		pos:    99,

		requests:      []uint64{63, 95, 99, 98},
		searchLadders: []uint64{98, 99},
	})

	// Log entries 63 and 95 are skipped because they're before the owner's last
	// update at 96. The previous greatest version was only created at 96, so it
	// wasn't proven to be included at either of them, and the first log entry
	// inspected still looks it up.
	runTest(testVector{
		owner:  &OwnerState{Starting: new(uint64(63)), UpcomingVers: []uint64{96}},
		verMap: map[uint64]uint32{96: 0, 97: 0, 98: 0, 99: 1},
		prev:   0,
		pos:    99,

		requests:      []uint64{63, 95, 99, 97, 98},
		searchLadders: []uint64{97, 98, 99},
	})

	// The owner's starting position is 96, so 63 and 95 are skipped. Both are
	// in the direct path of 96 and to its left, so the owner retained the
	// greatest version of the label at each, and lookups for versions included
	// at 95 are omitted from the first log entry inspected.
	runTest(testVector{
		owner:  &OwnerState{Starting: new(uint64(96)), PreviousVers: []uint32{1, 0, 0}},
		verMap: map[uint64]uint32{63: 0, 95: 0, 96: 1, 97: 1, 98: 1, 99: 2},
		prev:   1,
		pos:    99,

		requests:      []uint64{63, 95, 99, 97, 98},
		searchLadders: []uint64{97, 98, 99},
	})

	// The previous greatest version was created at the starting position, so
	// the label didn't exist at 95 and nothing is omitted from the first log
	// entry inspected.
	runTest(testVector{
		owner:  &OwnerState{Starting: new(uint64(96)), PreviousVers: []uint32{0}},
		verMap: map[uint64]uint32{96: 0, 97: 0, 98: 0, 99: 1},
		prev:   0,
		pos:    99,

		requests:      []uint64{63, 95, 99, 97, 98},
		searchLadders: []uint64{97, 98, 99},
	})

	// Same as the first case, but the root of the tree is now distinguished.
	config.ReasonableMonitoringWindow = now
	runTest(testVector{
		owner:  &OwnerState{Starting: new(uint64(31)), PreviousVers: []uint32{1}},
		verMap: map[uint64]uint32{63: 1, 95: 1, 97: 1, 98: 1, 99: 2},
		prev:   1,
		pos:    99,

		requests:      []uint64{63, 95, 99, 97, 98},
		searchLadders: []uint64{95, 97, 98, 99},
	})
}

// TestUpdateContactState verifies how Update changes the owner's contact
// monitoring state when the new log entry isn't distinguished.
func TestUpdateContactState(t *testing.T) {
	config := test.Config(t)
	now := uint64(time.Now().UnixMilli())

	tsMap := make(map[uint64]uint64)
	for pos := range uint64(100) {
		tsMap[pos] = now - 99 + pos
	}

	// Version 0 of the label was created at log entry 96, and version 1 at 98.
	// The right direct path of 96 is [97 99], and of 98 is [99].
	verMap := map[uint64]uint32{96: 0, 97: 0, 98: 1, 99: 1}

	// runTest processes the creation of version 1 at log entry 98, and then
	// performs contact monitoring with the resulting state.
	runTest := func(contact *ContactState) (*ContactState, error) {
		t.Helper()
		public := config.Public()

		handle := test.NewProofHandle(tsMap, verMap)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, now, provider); err != nil {
			t.Fatal(err)
		}
		monitor, err := NewMonitor(public, 100, provider)
		if err != nil {
			t.Fatal(err)
		}
		monitor.Contact = contact
		monitor.Owner = &OwnerState{Starting: new(uint64(63)), UpcomingVers: []uint64{96}}
		if err := monitor.Update(98, 1); err != nil {
			return nil, err
		}
		return monitor.Contact, nil
	}

	// An entry to the left of the new log entry is kept.
	contact, err := runTest(contactState(map[uint64]uint32{96: 0}))
	if err != nil {
		t.Fatal(err)
	}
	verifyContactState(t, contact, map[uint64]uint32{96: 0, 98: 1})

	// Contact monitoring has already moved the entry for version 0 up its direct
	// path to 99, which is to the right of the new log entry. Monitoring
	// version 1 from 98 covers 99, so that entry is removed. Otherwise, the
	// state would map a log entry to a lesser version than a log entry to its
	// left, which contact monitoring rejects.
	contact, err = runTest(contactState(map[uint64]uint32{99: 0}))
	if err != nil {
		t.Fatal(err)
	}
	verifyContactState(t, contact, map[uint64]uint32{98: 1})

	// An entry on the direct path of the new log entry can only be for a
	// version that the owner already knew about, which must be less than the
	// version being created. Version 1 at 99 means the state is corrupt, so the
	// update is rejected and the state is left as it was.
	contact = contactState(map[uint64]uint32{99: 2})
	_, err = runTest(contact)
	if err == nil || err.Error() != "contact monitoring state has unexpectedly great version of label" {
		t.Fatalf("unexpected error: %v", err)
	}
	verifyContactState(t, contact, map[uint64]uint32{99: 2})
}

// TestUpdateMaxVersion verifies that Update handles creating the greatest
// version of a label that can be represented, and rejects going past it.
func TestUpdateMaxVersion(t *testing.T) {
	config := test.Config(t)
	now := uint64(time.Now().UnixMilli())

	tsMap := make(map[uint64]uint64)
	for pos := range uint64(100) {
		tsMap[pos] = now - 99 + pos
	}

	// The owner has verified every log entry up to 98, where version
	// MaxUint32-1 of the label exists.
	const maxVer = 1<<32 - 1
	runTest := func(versions int) error {
		t.Helper()
		public := config.Public()

		handle := test.NewProofHandle(tsMap, map[uint64]uint32{98: maxVer - 1, 99: maxVer})
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, now, provider); err != nil {
			t.Fatal(err)
		}
		monitor, err := NewMonitor(public, 100, provider)
		if err != nil {
			t.Fatal(err)
		}
		monitor.Owner = &OwnerState{
			Starting:     new(uint64(98)),
			PreviousVers: []uint32{maxVer - 1},
		}

		return monitor.Update(99, versions)
	}

	err := runTest(1)
	if err != nil {
		t.Fatal(err)
	}
	err = runTest(2)
	if err == nil || err.Error() != "unexpected number of new versions created" {
		t.Fatalf("unexpected error: %v", err)
	}
}
