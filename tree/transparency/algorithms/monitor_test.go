package algorithms

import (
	"slices"
	"testing"
	"time"

	"github.com/Bren2010/katie/tree/transparency/test"
)

func TestContactMonitoring(t *testing.T) {
	config := test.Config(t)
	rmw := config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())
	tsMap := map[uint64]uint64{
		63: now - 5,
		71: now - 4,
		77: now - 3,
		79: now - 2,
		95: now - 1,
		99: now,
	}

	type testVector struct {
		state *ContactState
		tsMap map[uint64]uint64

		requests       []uint64
		monitorLadders []uint64
	}
	runTest := func(vec testVector) (*ContactState, error) {
		public := config.Public()
		handle := test.NewProofHandle(vec.tsMap, nil)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, provider); err != nil {
			t.Fatal(err)
		}
		monitor, err := NewMonitor(public, 100, provider)
		if err != nil {
			t.Fatal(err)
		}
		monitor.Contact = vec.state
		err = monitor.ContactMonitor()

		if err := handle.Verify(vec.requests, nil, vec.monitorLadders, nil); err != nil {
			t.Fatal(err)
		}
		return monitor.Contact, err
	}

	// TEST BLOCK 1: If a monitoring path ends in a non-distinguished log entry,
	// that log entry is left in the monitoring state.
	res, err := runTest(testVector{
		state: &ContactState{Ptrs: map[uint64]uint32{70: 1}},
		tsMap: tsMap,

		requests:       []uint64{63, 95, 99, 71, 79},
		monitorLadders: []uint64{71, 79, 95},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(res.Ptrs) != 1 || res.Ptrs[95] != 1 {
		t.Fatal("unexpected monitoring state output")
	}

	// TEST BLOCK 2: If a monitoring path ends in a distinguished log entry,
	// that log entry is excluded from the monitoring state.
	res, err = runTest(testVector{
		state: &ContactState{Ptrs: map[uint64]uint32{70: 1}},
		tsMap: map[uint64]uint64{
			63: now - rmw - 3,
			71: now - rmw - 2,
			79: now - rmw - 1,
			95: now - rmw,
			99: now,
		},

		requests:       []uint64{63, 95, 99, 71, 79},
		monitorLadders: []uint64{71, 79, 95},
	})
	if err != nil {
		t.Fatal(err)
	} else if res != nil {
		t.Fatal("unexpected monitoring state output")
	}

	// TEST BLOCK 3: When multiple monitoring paths intersect, the intersection
	// is only monitored once.
	res, err = runTest(testVector{
		state: &ContactState{Ptrs: map[uint64]uint32{70: 1, 76: 2}},
		tsMap: tsMap,

		requests:       []uint64{63, 95, 99, 77, 79, 71},
		monitorLadders: []uint64{77, 79, 95, 71},
	})
	if err != nil {
		t.Fatal(err)
	} else if len(res.Ptrs) != 1 || res.Ptrs[95] != 2 {
		t.Fatal("unexpected monitoring state output")
	}

	// TEST BLOCK 4: When multiple monitoring paths intersect, monotonicity is
	// verified.
	res, err = runTest(testVector{
		state: &ContactState{Ptrs: map[uint64]uint32{70: 2, 76: 1}},
		tsMap: tsMap,

		requests:       []uint64{63, 95, 99, 77, 79, 71},
		monitorLadders: []uint64{77, 79, 95, 71},
	})
	if err.Error() != "monitoring detected versions that are not monotonic" {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestInitEntries(t *testing.T) {
	config := test.Config(t)
	config.MaximumLifetime = 3 * config.ReasonableMonitoringWindow / 2

	ml, rmw := config.MaximumLifetime, config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())
	tsMap := map[uint64]uint64{
		63: now - ml,           // bounds = [0, 99] expired
		79: now - ml + 1,       // bounds = [63, 95] distinguished to left
		83: now - ml + 2,       // bounds = [79, 87] not distinguished
		87: now - ml + 3,       // bounds = [79, 95] distinguished start point
		95: now - ml + rmw + 1, // bounds = [63, 99] distinguished to right
		99: now,
	} // DirectPath(83) = [87, 79, 95, 63]

	handle := test.NewProofHandle(tsMap, nil)
	provider := NewDataProvider(config.Suite, handle)
	monitor, err := NewMonitor(config.Public(), 100, provider)
	if err != nil {
		t.Fatal(err)
	}

	// Owner initialization rejects non-distinguished log entries.
	_, err = monitor.InitEntries(83)
	if err.Error() != "requested starting position is not distinguished" {
		t.Fatalf("unexpected error returned: %v", err)
	}

	// Owner initialization accepts distinguished log entries; doesn't return
	// expired log entries or those to the right.
	entries, err := monitor.InitEntries(87)
	if err != nil {
		t.Fatal(err)
	} else if !slices.Equal(entries, []uint64{87, 79}) {
		t.Fatal("unexpected result from owner initialization")
	}
}

func verifyOwnerState(
	t *testing.T,
	state *OwnerState,
	starting uint64,
	verAtStarting int,
	upcomingVers []uint64,
) {
	if state == nil {
		t.Fatal("owner state not found when expected")
	} else if state.Starting != starting {
		t.Fatalf("unexpected owner state starting position: got=%v expected=%v", state.Starting, starting)
	} else if state.VerAtStarting != verAtStarting {
		t.Fatalf("unexpected owner state version at starting: got=%v expected=%v", state.VerAtStarting, verAtStarting)
	} else if len(upcomingVers) == 0 && len(state.UpcomingVers) != 0 {
		t.Fatalf("unexpected owner state upcoming versions: got=%v expected=nil", state.UpcomingVers)
	} else if len(upcomingVers) > 0 && !slices.Equal(state.UpcomingVers, upcomingVers) {
		t.Fatalf("unexpected owner state upcoming versions: got=%v expected=%v", state.UpcomingVers, upcomingVers)
	}
}

func TestOwnerInit(t *testing.T) {
	config := test.Config(t)
	config.MaximumLifetime = 3 * config.ReasonableMonitoringWindow / 2

	ml, rmw := config.MaximumLifetime, config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())
	tsMap := map[uint64]uint64{ // Same map as TestInitEntries
		63: now - ml,
		79: now - ml + 1,
		83: now - ml + 2,
		87: now - ml + 3,
		95: now - ml + rmw + 1,
		99: now,
	}

	type testVector struct {
		verMap map[uint64]uint32
		vers   []uint32

		requests      []uint64
		searchLadders []uint64
	}
	runTest := func(vec testVector) (*OwnerState, error) {
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
		_, err = monitor.OwnerInit(87, vec.vers)

		if err := handle.Verify(vec.requests, vec.searchLadders, nil, nil); err != nil {
			t.Fatal(err)
		}
		return monitor.Owner, err
	}

	// Search ladder returns expected results.
	state, err := runTest(testVector{
		verMap: map[uint64]uint32{87: 1},
		vers:   []uint32{1},

		requests:      []uint64{63, 95, 99, 79, 87},
		searchLadders: []uint64{87, 79},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerState(t, state, 87, 1, nil)

	// Search ladder returns version too great.
	_, err = runTest(testVector{
		verMap: map[uint64]uint32{87: 1},
		vers:   []uint32{0},

		requests:      []uint64{63, 95, 99, 79, 87},
		searchLadders: []uint64{87},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatalf("unexpected error returned: %v", err)
	}

	// Search ladder returns version too small.
	_, err = runTest(testVector{
		verMap: map[uint64]uint32{87: 31},
		vers:   []uint32{32},

		requests:      []uint64{63, 95, 99, 79, 87},
		searchLadders: []uint64{87},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatalf("unexpected error returned: %v", err)
	}

	// Search ladder returns version exists when it shouldn't.
	_, err = runTest(testVector{
		verMap: map[uint64]uint32{87: 0, 79: 0},
		vers:   []uint32{0},

		requests:      []uint64{63, 95, 99, 79, 87},
		searchLadders: []uint64{87, 79},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestOwnerMonitor(t *testing.T) {
	config := test.Config(t)
	config.MaximumLifetime = 3 * config.ReasonableMonitoringWindow / 2

	ml, rmw := config.MaximumLifetime, config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())
	tsMap := map[uint64]uint64{
		63: now - ml,
		79: now - ml + 1,
		83: now - ml + 2,
		87: now - ml + 3,
		99: now,

		// 97 will always be distinguished if 99 is. These timestamps are chosen
		// to make 97's children (96 and 98) non-distinguished.
		95: now - 3*rmw/2,
		97: now - 3*rmw/4,
	}

	type testVector struct {
		state   *OwnerState
		verMap  map[uint64]uint32
		stopPos uint64

		requests      []uint64
		searchLadders []uint64
	}
	runTest := func(vec testVector) error {
		public := config.Public()
		handle := test.NewProofHandle(tsMap, vec.verMap)
		handle.SetStopPos(vec.stopPos)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, provider); err != nil {
			t.Fatal(err)
		}
		monitor, err := NewMonitor(public, 100, provider)
		if err != nil {
			t.Fatal(err)
		}
		monitor.Owner = vec.state
		err = monitor.OwnerMonitor()

		if err := handle.Verify(vec.requests, vec.searchLadders, nil, nil); err != nil {
			t.Fatal(err)
		}
		return err
	}

	// When search ladders return expected results, starting position is set to
	// the last distinguished log entry that was verified.
	state := &OwnerState{Starting: 87, VerAtStarting: 1}
	err := runTest(testVector{
		state:  state,
		verMap: map[uint64]uint32{95: 1, 97: 1, 99: 1},

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95, 97, 99},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerState(t, state, 99, 1, nil)

	// When search ladders return expected results but the algorithm hits a
	// stopping condition, starting position is set to where we stopped.
	state = &OwnerState{Starting: 87, VerAtStarting: 1}
	err = runTest(testVector{
		state:   state,
		verMap:  map[uint64]uint32{95: 1},
		stopPos: 96,

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerState(t, state, 95, 1, nil)

	// When search ladders return expected results and new versions of the label
	// are processed, they are removed from the list of upcoming versions.
	state = &OwnerState{Starting: 87, VerAtStarting: 1, UpcomingVers: []uint64{95, 97}}
	err = runTest(testVector{
		state:  state,
		verMap: map[uint64]uint32{95: 2, 97: 3, 99: 3},

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95, 97, 99},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerState(t, state, 99, 3, nil)

	// When some but not all new versions of the label are processed, only
	// processed versions are removed from the list of upcoming versions.
	state = &OwnerState{Starting: 87, VerAtStarting: 1, UpcomingVers: []uint64{95, 97}}
	err = runTest(testVector{
		state:   state,
		verMap:  map[uint64]uint32{95: 2},
		stopPos: 96,

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerState(t, state, 95, 2, []uint64{97})

	// When a new version of a label is added in a log entry that isn't directly
	// inspected, the increase in version is still verified.
	state = &OwnerState{Starting: 87, VerAtStarting: 1, UpcomingVers: []uint64{96, 97, 99}}
	err = runTest(testVector{
		state:  state,
		verMap: map[uint64]uint32{95: 1, 97: 3, 99: 4},

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95, 97, 99},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerState(t, state, 99, 4, nil)

	// When multiple new versions of a label are added in a single log entry,
	// the increase in version is verified atomically.
	state = &OwnerState{Starting: 87, VerAtStarting: 1, UpcomingVers: []uint64{97, 97, 97, 99}}
	err = runTest(testVector{
		state:  state,
		verMap: map[uint64]uint32{95: 1, 97: 4, 99: 5},

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95, 97, 99},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerState(t, state, 99, 5, nil)

	// When a label is expected not to exist and the search ladder shows that it
	// doesn't exist, this is accepted.
	state = &OwnerState{Starting: 87, VerAtStarting: -1, UpcomingVers: []uint64{97}}
	err = runTest(testVector{
		state:  state,
		verMap: map[uint64]uint32{97: 0, 99: 0},

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95, 97, 99},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnerState(t, state, 99, 0, nil)

	// When a label is expected not to exist but the search ladder shows that it
	// does exist, this is rejected.
	state = &OwnerState{Starting: 87, VerAtStarting: -1, UpcomingVers: []uint64{97}}
	err = runTest(testVector{
		state:  state,
		verMap: map[uint64]uint32{95: 0},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{95},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatalf("unexpected error returned: %v", err)
	}
	verifyOwnerState(t, state, 87, -1, []uint64{97})

	// When a search ladder indicates that a label version is greater than
	// expected, this is rejected.
	state = &OwnerState{Starting: 87, VerAtStarting: -1, UpcomingVers: []uint64{97}}
	err = runTest(testVector{
		state:  state,
		verMap: map[uint64]uint32{97: 0, 99: 1},

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95, 97, 99},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatalf("unexpected error returned: %v", err)
	}
	verifyOwnerState(t, state, 87, -1, []uint64{97})

	// When a search ladder indicates that a label version is less than
	// expected, this is rejected.
	state = &OwnerState{Starting: 87, VerAtStarting: -1, UpcomingVers: []uint64{97, 97}}
	err = runTest(testVector{
		state:  state,
		verMap: map[uint64]uint32{97: 1, 99: 0},

		requests:      []uint64{63, 95, 99, 97},
		searchLadders: []uint64{95, 97, 99},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatalf("unexpected error returned: %v", err)
	}
	verifyOwnerState(t, state, 87, -1, []uint64{97, 97})
}
