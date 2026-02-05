package transparency

import (
	"slices"
	"testing"
	"time"

	"github.com/Bren2010/katie/tree/transparency/structs"
)

type testProofHandle struct {
	timestamps map[uint64]uint64
	versions   map[uint64]uint32

	requested         []uint64
	searchLadders     []uint64
	monitoringLadders []uint64
	inclusionProofs   []uint64
}

func newTestProofHandle(timestamps map[uint64]uint64, versions map[uint64]uint32) *testProofHandle {
	return &testProofHandle{timestamps: timestamps, versions: versions}
}

func (tph *testProofHandle) verify(requested, searchLadders, monitoringLadders, inclusionProofs []uint64) bool {
	return slices.Equal(tph.requested, requested) &&
		slices.Equal(tph.searchLadders, searchLadders) &&
		slices.Equal(tph.monitoringLadders, monitoringLadders) &&
		slices.Equal(tph.inclusionProofs, inclusionProofs)
}

func (tph *testProofHandle) GetTimestamp(x uint64) (uint64, error) {
	tph.requested = append(tph.requested, x)

	ts, ok := tph.timestamps[x]
	if !ok {
		panic("timestamp not known for position")
	}
	return ts, nil
}

func (tph *testProofHandle) GetSearchBinaryLadder(x uint64, ver uint32, omit bool) ([]byte, int, error) {
	tph.searchLadders = append(tph.searchLadders, x)

	posVer, ok := tph.versions[x]
	if !ok {
		panic("version not known for position")
	}

	if ver < posVer {
		return make([]byte, 32), -1, nil
	} else if ver == posVer {
		return make([]byte, 32), 0, nil
	} else {
		return make([]byte, 32), 1, nil
	}
}

func (tph *testProofHandle) GetMonitoringBinaryLadder(x uint64, ver uint32) ([]byte, error) {
	tph.monitoringLadders = append(tph.monitoringLadders, x)
	return make([]byte, 32), nil
}

func (tph *testProofHandle) GetInclusionProof(x uint64, ver uint32) ([]byte, error) {
	tph.inclusionProofs = append(tph.inclusionProofs, x)
	return make([]byte, 32), nil
}

func (tph *testProofHandle) AddVersion(ver uint32, vrfOutput, commitment []byte) error {
	panic("not implemented")
}
func (tph *testProofHandle) GetPrefixTrees(xs []uint64) ([][]byte, error) {
	panic("not implemented")
}
func (tph *testProofHandle) Finish() ([][]byte, error) {
	panic("not implemented")
}
func (tph *testProofHandle) Output(leaves []uint64, n uint64, nP, m *uint64) (*structs.CombinedTreeProof, error) {
	panic("not implemented")
}

func TestUpdateView(t *testing.T) {
	config := testConfig(t)
	now := uint64(time.Now().UnixMilli())

	runTest := func(n uint64, m *uint64, requests, timestamps []uint64) error {
		tsMap := make(map[uint64]uint64)
		for i, pos := range requests {
			tsMap[pos] = timestamps[i]
		}
		handle := newTestProofHandle(tsMap, nil)
		provider := newDataProvider(config.Suite, handle)

		if err := updateView(config.Public(), n, m, provider); err != nil {
			return err
		} else if !handle.verify(requests, nil, nil, nil) {
			t.Fatal("unexpected lookups made by algorithm")
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
	config := testConfig(t)

	rmw := config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())

	runTest := func(n uint64, requests, timestamps []uint64) *uint64 {
		public := config.Public()

		tsMap := make(map[uint64]uint64)
		for i, pos := range requests {
			tsMap[pos] = timestamps[i]
		}
		handle := newTestProofHandle(tsMap, nil)
		provider := newDataProvider(config.Suite, handle)

		if err := updateView(public, n, nil, provider); err != nil {
			t.Fatal(err)
		}
		res, err := rightmostDistinguished(public, n, provider)
		if err != nil {
			t.Fatal(err)
		} else if !handle.verify(requests, nil, nil, nil) {
			t.Fatal("unexpected lookups made by algorithm")
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

func TestGreatestVersionSearch(t *testing.T) {
	config := testConfig(t)

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
		handle := newTestProofHandle(vec.tsMap, vec.verMap)
		provider := newDataProvider(config.Suite, handle)

		if err := updateView(public, 100, nil, provider); err != nil {
			t.Fatal(err)
		}
		res, err := greatestVersionSearch(public, 1, 100, provider)
		if !handle.verify(vec.requests, vec.searchLadders, nil, nil) {
			t.Fatal("unexpected lookups made by algorithm")
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
	if err.Error() != "rightmost log entry not consistent with claimed greatest version of label" {
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
