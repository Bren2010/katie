package algorithms

import (
	"slices"
	"testing"
	"time"

	"github.com/Bren2010/katie/tree/transparency/test"
)

func TestWalkDistinguished(t *testing.T) {
	config := test.Config(t)
	rmw := config.ReasonableMonitoringWindow
	now := uint64(time.Now().UnixMilli())

	// A tree of 15 log entries where every log entry is distinguished.
	allDistinguished := make(map[uint64]uint64)
	for x := range uint64(15) {
		allDistinguished[x] = now - (14-x)*rmw
	}
	frontier := []uint64{7, 11, 13, 14}

	runTest := func(
		n uint64,
		stop *uint64,
		recent RecentFunc,
		tsMap map[uint64]uint64,
		requests []uint64,
	) ([]uint64, error) {
		t.Helper()
		public := config.Public()

		handle := test.NewProofHandle(tsMap, nil)
		provider := NewDataProvider(config.Suite, handle)

		if err := UpdateView(public, n, nil, provider); err != nil {
			t.Fatal(err)
		}
		res, err := WalkDistinguished(public, stop, recent, n, provider)

		if err := handle.Verify(requests, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		return res, err
	}
	check := func(res []uint64, err error, expected []uint64) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		} else if !slices.Equal(res, expected) {
			t.Fatalf("unexpected result: %v", res)
		}
	}

	// Empty tree.
	res, err := runTest(0, nil, RecentCount(10), nil, nil)
	check(res, err, nil)

	// Stopping position is not in tree.
	stop := uint64(15)
	_, err = runTest(15, &stop, RecentCount(10), allDistinguished, frontier)
	if err == nil || err.Error() != "stopping position is not in tree" {
		t.Fatalf("unexpected error returned: %v", err)
	}

	// Single log entry.
	res, err = runTest(1, nil, RecentCount(10), map[uint64]uint64{0: now}, []uint64{0})
	check(res, err, []uint64{0})

	// Recent defined as the n rightmost distinguished log entries.
	res, err = runTest(15, nil, RecentCount(3), allDistinguished, append(frontier, 12))
	check(res, err, []uint64{12, 13, 14})

	// Recent defined by a threshold on timestamps.
	res, err = runTest(15, nil, RecentWithin(5*rmw), allDistinguished, append(frontier, 12, 9, 10))
	check(res, err, []uint64{10, 11, 12, 13, 14})

	// Stopping position is provided.
	stop = 12
	res, err = runTest(15, &stop, RecentCount(10), allDistinguished, append(frontier, 12))
	check(res, err, []uint64{13, 14})

	// Expired log entries are not recent.
	config.MaximumLifetime = 2 * rmw
	res, err = runTest(15, nil, RecentCount(10), allDistinguished, append(frontier, 12))
	check(res, err, []uint64{13, 14})
	config.MaximumLifetime = 0

	// Non-distinguished subtrees are not walked.
	res, err = runTest(15, nil, RecentCount(2), map[uint64]uint64{
		3: now - 7*rmw, 5: now - 5*rmw, 6: now - 4*rmw,
		7: now - rmw/2, 11: now - rmw/4, 13: now - rmw/8, 14: now,
	}, append(frontier, 3, 5, 6))
	check(res, err, []uint64{6, 7})
}

func TestCompareRoots(t *testing.T) {
	roots := func(vals ...byte) [][]byte {
		out := make([][]byte, len(vals))
		for i, val := range vals {
			out[i] = []byte{val}
		}
		return out
	}

	testCases := []struct {
		a, b [][]byte
		err  string
	}{
		{roots(1, 2, 3), roots(1, 2, 3), ""},
		{roots(1, 2, 3), roots(2, 3, 4), ""},
		{roots(2, 3, 4), roots(1, 2, 3), ""},
		{roots(1, 2, 3), roots(3, 4, 5), ""},
		{roots(3, 4, 5), roots(1, 2, 3), ""},
		{roots(1, 2, 3), roots(4, 5, 6), "no valid overlap found"},
		{roots(1, 2, 3), roots(1, 9, 3), "no valid overlap found"},
		{roots(1, 2, 3), roots(2, 4, 5), "no valid overlap found"},
		{roots(1, 2, 3), roots(1, 2, 4), "no valid overlap found"},
		{roots(), roots(), "no valid overlap found"},
		{roots(1, 2, 3), roots(1, 2), "lists must be the same size"},
	}
	for i, tc := range testCases {
		err := CompareRoots(tc.a, tc.b)
		if tc.err == "" && err != nil {
			t.Fatalf("test case %d: unexpected error: %v", i, err)
		} else if tc.err != "" && (err == nil || err.Error() != tc.err) {
			t.Fatalf("test case %d: unexpected error returned: %v", i, err)
		}
	}
}
