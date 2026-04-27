package algorithms

import (
	"slices"
	"testing"
	"time"

	"github.com/Bren2010/katie/tree/transparency/test"
)

func TestUpdateView(t *testing.T) {
	config := test.Config(t)
	now := uint64(time.Now().UnixMilli())

	runTest := func(n uint64, m *uint64, requests, timestamps []uint64) error {
		tsMap := make(map[uint64]uint64)
		for i, pos := range requests {
			tsMap[pos] = timestamps[i]
		}
		handle := test.NewProofHandle(tsMap, nil)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(config.Public(), n, m, provider); err != nil {
			return err
		} else if err := handle.Verify(requests, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		return nil
	}

	// Previous tree size is greater than current tree size
	prev := uint64(100)
	err := runTest(99, &prev, nil, nil)
	if err.Error() != "new tree size is not greater than previous tree size" {
		t.Fatal("expected error but none returned")
	}

	// Current tree size is zero
	err = runTest(0, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Current tree size is greater than zero, previous tree size is nil
	err = runTest(100, nil, []uint64{63, 95, 99}, []uint64{0, 1, now})
	if err != nil {
		t.Fatal(err)
	}

	// Previous tree size is equal to current tree size
	err = runTest(100, &prev, []uint64{99}, []uint64{now})
	if err != nil {
		t.Fatal(err)
	}

	// Standard case
	err = runTest(200, &prev, []uint64{103, 111, 127, 191, 199}, []uint64{0, 1, 2, 3, now})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRightmostDistinguished(t *testing.T) {
	config := test.Config(t)

	rmw := config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())

	runTest := func(n uint64, requests, timestamps []uint64) *uint64 {
		public := config.Public()

		tsMap := make(map[uint64]uint64)
		for i, pos := range requests {
			tsMap[pos] = timestamps[i]
		}
		handle := test.NewProofHandle(tsMap, nil)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, n, nil, provider); err != nil {
			t.Fatal(err)
		}
		res, err := RightmostDistinguished(public, n, provider)
		if err != nil {
			t.Fatal(err)
		} else if err := handle.Verify(requests, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		return res
	}

	// Tree size = 0
	res := runTest(0, nil, nil)
	if res != nil {
		t.Fatal("unexpected response")
	}

	// Tree size = 1 and rightmost not distinguished
	config.ReasonableMonitoringWindow = now + 1
	res = runTest(1, []uint64{0}, []uint64{now})
	if res != nil {
		t.Fatal("unexpected response")
	}
	config.ReasonableMonitoringWindow = rmw

	// Tree size = 1 and rightmost is distinguished
	res = runTest(1, []uint64{0}, []uint64{now})
	if res == nil || *res != 0 {
		t.Fatal("unexpected response")
	}

	// Tree size = 100 and rightmost is not distinguished
	res = runTest(100, []uint64{63, 95, 99}, []uint64{now - 2*rmw, now - rmw + 1, now})
	if res == nil || *res != 95 {
		t.Fatal("unexpected response")
	}

	// Tree size = 100 and rightmost is distinguished
	res = runTest(100, []uint64{63, 95, 99}, []uint64{now - 2*rmw, now - rmw, now})
	if res == nil || *res != 99 {
		t.Fatal("unexpected response")
	}
}

func TestPreviousDistinguished(t *testing.T) {
	config := test.Config(t)

	rmw := config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())

	runTest := func(n uint64, requests, timestamps []uint64) *uint64 {
		public := config.Public()

		tsMap := make(map[uint64]uint64)
		for i, pos := range requests {
			tsMap[pos] = timestamps[i]
		}
		handle := test.NewProofHandle(tsMap, nil)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, n, nil, provider); err != nil {
			t.Fatal(err)
		}
		res, err := PreviousRightmost(public, n, provider)
		if err != nil {
			t.Fatal(err)
		} else if err := handle.Verify(requests, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		return res
	}

	// No distinguished log entry
	config.ReasonableMonitoringWindow = now + 1
	res := runTest(1, []uint64{0}, []uint64{now})
	if res != nil {
		t.Fatal("unexpected response")
	}
	config.ReasonableMonitoringWindow = rmw

	// Rightmost distinguished log entry is not rightmost log entry
	res = runTest(3, []uint64{1, 2}, []uint64{now - 1, now})
	if res == nil || *res != 1 {
		t.Fatal("unexpected response")
	}

	// Rightmost log entry is distinguished and has no left child.
	res = runTest(3, []uint64{1, 2}, []uint64{now - rmw, now})
	if res == nil || *res != 1 {
		t.Fatal("unexpected response")
	}

	// Rightmost log entry is distinguished and has distinguished left child.
	res = runTest(32, []uint64{31, 15, 23}, []uint64{now, now - rmw, now - 1})
	if res == nil || *res != 23 {
		t.Fatal("unexpected response", *res)
	}
}

func TestGreatestVersionSearch(t *testing.T) {
	config := test.Config(t)

	rmw := config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())

	type testVector struct {
		tsMap  map[uint64]uint64
		verMap map[uint64]uint32

		requests      []uint64
		searchLadders []uint64
	}
	runTest := func(vec testVector) (uint64, error) {
		public := config.Public()
		handle := test.NewProofHandle(vec.tsMap, vec.verMap)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, provider); err != nil {
			t.Fatal(err)
		}
		res, err := GreatestVersionSearch(public, 1, 100, provider)
		if err := handle.Verify(vec.requests, vec.searchLadders, nil, nil); err != nil {
			t.Fatal(err)
		}
		return res, err
	}

	// Search starts at root when there's no distinguished log entry.
	config.ReasonableMonitoringWindow = now + 1
	res, err := runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 2, 95: now - 1, 99: now},
		verMap: map[uint64]uint32{63: 0, 95: 0, 99: 1},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{63, 95, 99},
	})
	if res != 99 || err != nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}
	config.ReasonableMonitoringWindow = rmw

	// Search starts at rightmost distinguished log entry when there is one.
	res, err = runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 2*rmw, 95: now - rmw + 1, 99: now},
		verMap: map[uint64]uint32{95: 0, 99: 1},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{95, 99},
	})
	if res != 99 || err != nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// Search returns leftmost terminal log entry.
	res, err = runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 2*rmw, 95: now - rmw + 1, 99: now},
		verMap: map[uint64]uint32{95: 1, 99: 1},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{95, 99},
	})
	if res != 95 || err != nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// Search returns leftmost terminal log entry.
	res, err = runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 2*rmw, 95: now - rmw, 99: now},
		verMap: map[uint64]uint32{99: 1},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{99},
	})
	if res != 99 || err != nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// Returns an error when rightmost log entry indicates greater version.
	res, err = runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 2*rmw, 95: now - rmw + 1, 99: now},
		verMap: map[uint64]uint32{95: 1, 99: 2},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{95, 99},
	})
	if err.Error() != "log entry not consistent with claimed greatest version of label" {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// Returns an error when any log entry indicates greater version.
	res, err = runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 2*rmw, 95: now - rmw + 1, 99: now},
		verMap: map[uint64]uint32{95: 2, 99: 1},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{95},
	})
	if err.Error() != "log entry not consistent with claimed greatest version of label" {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// Returns an error when rightmost log entry indicates lesser version.
	res, err = runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 2*rmw, 95: now - rmw + 1, 99: now},
		verMap: map[uint64]uint32{95: 0, 99: 0},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{95, 99},
	})
	if err.Error() != "rightmost log entry not consistent with claimed greatest version of label" {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}
}

func TestFixedVersionSearch(t *testing.T) {
	config := test.Config(t)
	config.MaximumLifetime = 3 * config.ReasonableMonitoringWindow / 2

	ml, rmw := config.MaximumLifetime, config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())

	type testVector struct {
		tsMap  map[uint64]uint64
		verMap map[uint64]uint32

		requests        []uint64
		searchLadders   []uint64
		inclusionProofs []uint64
	}
	runTest := func(vec testVector) (uint64, error) {
		public := config.Public()
		handle := test.NewProofHandle(vec.tsMap, vec.verMap)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, 100, nil, provider); err != nil {
			t.Fatal(err)
		}
		res, err := FixedVersionSearch(public, 1, 100, provider)
		if err := handle.Verify(vec.requests, vec.searchLadders, nil, vec.inclusionProofs); err != nil {
			t.Fatal(err)
		}
		return res, err
	}

	// TEST BLOCK 1: no expired log entries touched.

	// No terminal log entry.
	res, err := runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 3, 95: now - 1, 99: now},
		verMap: map[uint64]uint32{63: 0, 95: 0, 99: 0},

		requests:      []uint64{63, 95, 99},
		searchLadders: []uint64{63, 95, 99},
	})
	if err.Error() != "requested version of label does not exist" {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// Search stops at first log entry where the target version is the greatest
	// version that exists.
	res, err = runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - 3, 79: now - 2, 95: now - 1, 99: now},
		verMap: map[uint64]uint32{63: 0, 79: 1, 95: 2},

		requests:      []uint64{63, 95, 99, 79},
		searchLadders: []uint64{63, 95, 79},
	})
	if res != 79 || err != nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// Search continues to leaf if necessary.
	res, err = runTest(testVector{
		tsMap: map[uint64]uint64{
			63: now - 7, 71: now - 6, 73: now - 5, 74: now - 4, 75: now - 3,
			79: now - 2, 95: now - 1, 99: now,
		},
		verMap: map[uint64]uint32{63: 0, 71: 0, 73: 0, 74: 0, 75: 2, 79: 2, 95: 2},

		requests:        []uint64{63, 95, 99, 79, 71, 75, 73, 74},
		searchLadders:   []uint64{63, 95, 79, 71, 75, 73, 74},
		inclusionProofs: []uint64{75},
	})
	if res != 75 || err != nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// TEST BLOCK 2: expired log entries touched and exact version match found.

	// The terminal log entry is distinguished.
	res, err = runTest(testVector{
		tsMap:  map[uint64]uint64{63: now - ml, 79: now - 2, 95: now - 1, 99: now},
		verMap: map[uint64]uint32{63: 0, 79: 1, 95: 2},

		requests:      []uint64{63, 95, 99, 79},
		searchLadders: []uint64{95, 79},
	})
	if res != 79 || err != nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// The terminal log entry is not distinguished or to the right of any
	// distinguished log entry.
	res, err = runTest(testVector{
		tsMap: map[uint64]uint64{
			63: now - ml,
			79: now - ml + rmw - 2,
			95: now - ml + rmw - 1,
			99: now,
		},
		verMap: map[uint64]uint32{63: 0, 79: 1, 95: 2},

		requests:      []uint64{63, 95, 99, 79},
		searchLadders: []uint64{95, 79},
	})
	if err.Error() != "requested version of label has expired" {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// TEST BLOCK 3: expired log entries touched and no exact match found.

	tsMap := map[uint64]uint64{
		63: now - ml - 1,       // bounds = [0, 99]  expired
		95: now - ml,           // bounds = [63, 99] expired
		96: now - ml + rmw - 2, // bounds = [95, 97] not distinguished
		97: now - ml + rmw - 1, // bounds = [95, 99] distinguished
		98: now - 1,            // bounds = [97, 99] not distinguished
		99: now,                // bounds = [95, 99] distinguished
	}

	// The terminal log entry is to the left of the leftmost unexpired
	// distinguished log entry.
	res, err = runTest(testVector{
		tsMap:  tsMap,
		verMap: map[uint64]uint32{63: 0, 95: 0, 96: 2, 97: 2, 99: 2},

		requests:      []uint64{63, 95, 99, 97, 96},
		searchLadders: []uint64{99, 97, 96},
	})
	if err.Error() != "requested version of label has expired" {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// The terminal log entry is the leftmost unexpired distinguished log entry.
	res, err = runTest(testVector{
		tsMap:  tsMap,
		verMap: map[uint64]uint32{63: 0, 95: 0, 96: 0, 97: 2, 99: 2},

		requests:      []uint64{63, 95, 99, 97, 96},
		searchLadders: []uint64{99, 97, 96},
	})
	if err.Error() != "requested version of label has expired" {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}

	// The terminal log entry is to the right of the leftmost unexpired
	// distinguished log entry.
	res, err = runTest(testVector{
		tsMap:  tsMap,
		verMap: map[uint64]uint32{63: 0, 95: 0, 97: 0, 98: 0, 99: 2},

		requests:        []uint64{63, 95, 99, 97, 98},
		searchLadders:   []uint64{99, 97, 98},
		inclusionProofs: []uint64{99},
	})
	if res != 99 || err != nil {
		t.Fatalf("unexpected result: res=%v err=%v", res, err)
	}
}

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
		t.Fatal(err)
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
		t.Fatal("unexpected error from owner initialization")
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
		err = monitor.OwnerInit(87, vec.vers)

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
	ok := state != nil && state.Starting == 87 &&
		state.VerAtStarting == 1 && len(state.UpcomingVers) == 0
	if !ok {
		t.Fatal("owner state not populated as expected")
	}

	// Search ladder returns version too great.
	_, err = runTest(testVector{
		verMap: map[uint64]uint32{87: 1},
		vers:   []uint32{0},

		requests:      []uint64{63, 95, 99, 79, 87},
		searchLadders: []uint64{87},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatal(err)
	}

	// Search ladder returns version too small.
	_, err = runTest(testVector{
		verMap: map[uint64]uint32{87: 31},
		vers:   []uint32{32},

		requests:      []uint64{63, 95, 99, 79, 87},
		searchLadders: []uint64{87},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatal(err)
	}

	// Search ladder returns version exists when it shouldn't.
	_, err = runTest(testVector{
		verMap: map[uint64]uint32{87: 0, 79: 0},
		vers:   []uint32{0},

		requests:      []uint64{63, 95, 99, 79, 87},
		searchLadders: []uint64{87, 79},
	})
	if err.Error() != "binary ladder inconsistent with expected greatest version of label" {
		t.Fatal(err)
	}
}
