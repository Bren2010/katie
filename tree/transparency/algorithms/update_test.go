package algorithms

import (
	"testing"
	"time"

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
		public := config.Public()
		handle := test.NewProofHandle(tsMap, vec.verMap)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, provider); err != nil {
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
		owner:    &OwnerState{Starting: 0, VerAtStarting: -1},
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
	verifyOwnerState(t, owner, 0, -1, []uint64{1})

	// Previous tree root is distinguished but path is not.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{63: 0},
		owner:    &OwnerState{Starting: 0, VerAtStarting: -1},
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
	verifyOwnerState(t, owner, 0, -1, []uint64{63})

	// Previous tree has no distinguished log entries.
	config.ReasonableMonitoringWindow = now
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{63: 0},
		owner:    &OwnerState{Starting: 0, VerAtStarting: -1},
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
	verifyOwnerState(t, owner, 0, -1, []uint64{63})
	config.ReasonableMonitoringWindow = rmw

	// Skips lookups that overlap with previous Update operations.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{97: 1, 98: 1, 99: 2},
		contact:  &ContactState{Ptrs: map[uint64]uint32{96: 1}},
		owner:    &OwnerState{Starting: 63, VerAtStarting: 0, UpcomingVers: []uint64{96}},
		pos:      99,
		versions: 1,

		requests:      []uint64{63, 95, 99, 97, 98},
		searchLadders: []uint64{97, 98, 99},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(contact.Ptrs) != 2 || contact.Ptrs[96] != 1 || contact.Ptrs[99] != 2 {
		t.Fatal("unexpected contact monitoring state")
	}
	verifyOwnerState(t, owner, 63, 0, []uint64{96, 99})

	// Skips all previous tree lookups if they're unnecessary.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{99: 2},
		contact:  &ContactState{Ptrs: map[uint64]uint32{98: 1}},
		owner:    &OwnerState{Starting: 63, VerAtStarting: 0, UpcomingVers: []uint64{98}},
		pos:      99,
		versions: 1,

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{99},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(contact.Ptrs) != 2 || contact.Ptrs[98] != 1 || contact.Ptrs[99] != 2 {
		t.Fatal("unexpected contact monitoring state")
	}
	verifyOwnerState(t, owner, 63, 0, []uint64{98, 99})

	// New log entry contains multiple versions and is not distinguished.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{99: 9},
		owner:    &OwnerState{Starting: 0, VerAtStarting: -1},
		pos:      99,
		versions: 10,

		requests:        []uint64{63, 95, 99, 97, 98},
		searchLadders:   []uint64{95, 97, 98, 99},
		inclusionProofs: []uint64{99},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(contact.Ptrs) != 1 || contact.Ptrs[99] != 9 {
		t.Fatal("unexpected contact monitoring state")
	}
	verifyOwnerState(t, owner, 0, -1, []uint64{99, 99, 99, 99, 99, 99, 99, 99, 99, 99})

	// New log entry contains multiple versions and is distinguished.
	contact, owner, err = runTest(testVector{
		verMap:   map[uint64]uint32{63: 9},
		owner:    &OwnerState{Starting: 0, VerAtStarting: -1},
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
	verifyOwnerState(t, owner, 0, -1, []uint64{63, 63, 63, 63, 63, 63, 63, 63, 63, 63})

	// Rejects proof where previous tree has overlapping version.
	_, _, err = runTest(testVector{
		verMap:   map[uint64]uint32{62: 0, 63: 9},
		owner:    &OwnerState{Starting: 0, VerAtStarting: -1},
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
		owner:    &OwnerState{Starting: 0, VerAtStarting: -1},
		pos:      99,
		versions: 10,

		requests:        []uint64{63, 95, 99, 97, 98},
		searchLadders:   []uint64{95, 97, 98, 99},
		inclusionProofs: []uint64{},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatal(err)
	}

	// New log entry contains one version and is not distinguished.
	// Covered sufficiently above.

	// New log entry contains one version and is distinguished.
	// Covered sufficiently above.
}

// TODO: Test version omission is correct.
