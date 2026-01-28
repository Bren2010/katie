package transparency

import (
	"bytes"
	"slices"
	"testing"

	"github.com/Bren2010/katie/db/memory"
	"github.com/Bren2010/katie/tree/transparency/math"
)

func TestIndexEncoding(t *testing.T) {
	tree, err := NewTree(testConfig(t), memory.NewTransparencyStore())
	if err != nil {
		t.Fatal(err)
	}
	input := []uint64{1000, 2000, 2500, 2500, 2500, 2500, 3000, 7000}
	if err := tree.putIndex([]byte("label"), input); err != nil {
		t.Fatal(err)
	}
	output, err := tree.batchGetIndex([][]byte{[]byte("label")})
	if err != nil {
		t.Fatal(err)
	} else if len(output) != 1 {
		t.Fatal("unexpected number of indices output")
	} else if !slices.Equal(input, output[0]) {
		t.Fatal("input and output indices do not match")
	}
}

func TestPutIndexRejectsNonMonotonic(t *testing.T) {
	tree, err := NewTree(testConfig(t), memory.NewTransparencyStore())
	if err != nil {
		t.Fatal(err)
	}
	input := []uint64{1000, 999, 2000}
	if err := tree.putIndex([]byte("label"), input); err == nil {
		t.Fatal("expected error but none returned")
	}
}

func TestComputeVrfOutput(t *testing.T) {
	tree, err := NewTree(testConfig(t), memory.NewTransparencyStore())
	if err != nil {
		t.Fatal(err)
	}
	output0, _, err := tree.computeVrfOutput([]byte("label"), 0)
	if err != nil {
		t.Fatal(err)
	}
	output1, _, err := tree.computeVrfOutput([]byte("label"), 1)
	if err != nil {
		t.Fatal(err)
	} else if bytes.Equal(output0, output1) {
		t.Fatal("vrf outputs for different versions must be different")
	}
}

func TestSearchMaps(t *testing.T) {
	var (
		tracker versionTracker

		target       uint32 = 5 // Target version of label
		greatest1000 uint32 = 3 // Greatest version present at log entry 1000
		greatest2000 uint32 = 6 // Greatest version present at log entry 2000
	)

	left, right := tracker.SearchMaps(1000, true)
	if len(left) != 0 || len(right) != 0 {
		t.Fatal("expected left and right maps")
	}
	ladder := math.SearchBinaryLadder(target, greatest1000, left, right)
	t.Logf("pos=1000 greatest=%v ladder=%v", greatest1000, ladder)
	tracker.AddLadder(1000, true, int(greatest1000), ladder)

	left, right = tracker.SearchMaps(2000, true)
	if len(left) != 3 || len(right) != 0 {
		t.Fatal("unexpected left and right maps")
	}
	ladder = math.SearchBinaryLadder(target, greatest2000, left, right)
	t.Logf("pos=2000 greatest=%v ladder=%v", greatest2000, ladder)
	tracker.AddLadder(2000, true, int(greatest2000), ladder)

	left, right = tracker.SearchMaps(1500, true)
	if len(left) != 3 || len(right) != 1 {
		t.Fatal("unexpected left and right maps")
	}
}
