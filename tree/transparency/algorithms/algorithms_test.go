package algorithms

import (
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
		t.Fatalf("unexpected error returned: %v", err)
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
