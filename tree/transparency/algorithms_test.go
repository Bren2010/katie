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
		out, err := rightmostDistinguished(public, n, provider)
		if err != nil {
			t.Fatal(err)
		} else if !handle.verify(requests, nil, nil, nil) {
			t.Fatal("unexpected lookups made by algorithm")
		}
		return out
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

// func TestGreatestVersionSearch(t *testing.T) {
// 	config := testConfig(t)

// 	runTest := func(ver uint32, n uint64, requests, timestamps []uint64, versions []uint32) (uint64, error) {
// 		public := config.Public()

// 		tsMap, verMap := make(map[uint64]uint64), make(map[uint64]uint32)
// 		for i, pos := range requests {
// 			tsMap[pos] = timestamps[i]
// 			verMap[pos] = versions[i]
// 		}
// 		handle := newTestProofHandle(tsMap, verMap)
// 		provider := newDataProvider(config.Suite, handle)

// 		if err := updateView(public, n, nil, provider); err != nil {
// 			t.Fatal(err)
// 		}
// 		return greatestVersionSearch(public, ver, n, provider) // TODO: handle.verify
// 	}

// 	// Search starts at root when there's no distinguished log entry.

// 	// No rightmost distinguished log entry.
// 	// Rightmost distinguished log entry is not the rightmost log entry.
// 	// Terminal log entry is rightmost log entry
// 	// Terminal log entry is rightmost distinguished log entry
// 	// Terminal log entry is neither

// 	// Final ladder is consistent with lesser greatest version.
// 	// Final ladder is consistent with g
// }

// func TestFixedVersionSearch(t *testing.T) {
// 	// ns := []uint64{1000, 1000000, 10000000}
// 	// ks := []uint32{1, 10, 100, 1000}

// 	// for _, n := range ns {
// 	// 	for _, k := range ks {
// 	// 		for i := 0; i < 5; i++ {
// 	// 			ver := uint32(rand.Intn(int(k)))
// 	// 			res := runExperiment(t, n, k, ver)
// 	// 			fmt.Println(n, k, res)
// 	// 		}
// 	// 	}
// 	// }

// 	sum := 0
// 	for i := 0; i < 50; i++ {
// 		ver := uint32(rand.Intn(10))
// 		sum += runExperiment(t, 1000000, 10, ver)
// 	}
// 	fmt.Println(sum)
// }

// type testHandler struct {
// 	sum     int
// 	vers    []uint64
// 	tracker versionTracker
// }

// func (th *testHandler) AddVersion(_ uint32, _, _ []byte) error { panic("not implemented") }

// func (th *testHandler) GetTimestamp(x uint64) (uint64, error) { return x, nil }

// func (th *testHandler) GetSearchBinaryLadder(x uint64, ver uint32, omit bool) ([]byte, int, error) {
// 	greatest, found := slices.BinarySearch(th.vers, x)
// 	if !found {
// 		greatest--
// 	}

// 	leftInclusion, rightNonInclusion := th.tracker.SearchMaps(x, omit)
// 	ladder := math.SearchBinaryLadder(ver, uint32(greatest), leftInclusion, rightNonInclusion)
// 	th.sum += len(ladder)
// 	th.tracker.AddLadder(x, omit, greatest, ladder)

// 	res := 0
// 	if x < th.vers[ver] {
// 		res = -1
// 	} else if x > th.vers[ver] {
// 		res = 1
// 	}
// 	// fmt.Printf("x=%v (%v) res=%v ladder=%v\n", x, th.vers[ver], res, ladder)
// 	return make([]byte, 32), res, nil
// }

// func (th *testHandler) GetMonitoringBinaryLadder(_ uint64, _ uint32) ([]byte, error) {
// 	panic("not implemented")
// }
// func (th *testHandler) GetInclusionProof(_ uint64, _ uint32) ([]byte, error) {
// 	panic("not implemented")
// }
// func (th *testHandler) GetPrefixTrees(_ []uint64) ([][]byte, error) { panic("not implemented") }
// func (th *testHandler) Finish() ([][]byte, error)                   { panic("not implemented") }
// func (th *testHandler) Output(_ []uint64, _ uint64, _, _ *uint64) (*structs.CombinedTreeProof, error) {
// 	panic("not implemented")
// }

// func runExperiment(t *testing.T, n uint64, k, ver uint32) int {
// 	versMap := make(map[uint64]struct{})
// 	for len(versMap) < int(k) {
// 		x := uint64(rand.Intn(int(n)))
// 		versMap[x] = struct{}{}
// 	}
// 	vers := make([]uint64, 0, len(versMap))
// 	for x := range versMap {
// 		vers = append(vers, x)
// 	}
// 	slices.Sort(vers)

// 	// fmt.Println(vers)

// 	publicConfig := &structs.PublicConfig{}
// 	suite := suites.KTSha256P256{}
// 	th := &testHandler{vers: vers}
// 	provider := newDataProvider(suite, th)

// 	if _, err := fixedVersionSearch(publicConfig, ver, n, provider); err != nil {
// 		t.Fatal(err)
// 	}

// 	return th.sum
// }
