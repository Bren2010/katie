package transparency

import (
	"testing"
	"time"

	"github.com/Bren2010/katie/tree/transparency/structs"
)

func TestRightmostDistinguished(t *testing.T) {
	config := testConfig(t)

	rmw := config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())

	runTest := func(n uint64, timestamps []uint64) (*uint64, error) {
		handle := newReceivedProofHandle(config.Suite, structs.CombinedTreeProof{
			Timestamps: timestamps,
		})
		provider := newDataProvider(config.Suite, handle)

		public := config.Public()
		if err := updateView(public, n, nil, provider); err != nil {
			t.Fatal(err)
		}
		return rightmostDistinguished(public, n, provider)
	}

	// Tree size = 0
	if res, err := runTest(0, []uint64{}); err != nil {
		t.Fatal(err)
	} else if res != nil {
		t.Fatal("unexpected response")
	}

	// Tree size = 1 and rightmost not distinguished
	config.ReasonableMonitoringWindow = now + 1
	if res, err := runTest(1, []uint64{now}); err != nil {
		t.Fatal(err)
	} else if res != nil {
		t.Fatal("unexpected response")
	}
	config.ReasonableMonitoringWindow = rmw

	// Tree size = 1 and rightmost is distinguished
	if res, err := runTest(1, []uint64{now}); err != nil {
		t.Fatal(err)
	} else if res == nil || *res != 0 {
		t.Fatal("unexpected response")
	}

	// Tree size = 100 and rightmost is not distinguished
	if res, err := runTest(100, []uint64{now - 2*rmw, now - rmw + 1, now}); err != nil {
		t.Fatal(err)
	} else if res == nil || *res != 95 {
		t.Fatal("unexpected response")
	}

	// Tree size = 100 and rightmost is distinguished
	if res, err := runTest(100, []uint64{now - 2*rmw, now - rmw, now}); err != nil {
		t.Fatal(err)
	} else if res == nil || *res != 99 {
		t.Fatal("unexpected response")
	}
}

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
