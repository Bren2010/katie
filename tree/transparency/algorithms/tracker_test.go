package algorithms

import (
	"testing"

	"github.com/Bren2010/katie/tree/transparency/math"
)

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
