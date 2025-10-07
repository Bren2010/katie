package math

import (
	"fmt"
	"testing"
)

func TestSearchBinaryLadder(t *testing.T) {
	// Ends after first inclusion proof for a version greater than target.
	ladder := fmt.Sprint(SearchBinaryLadder(5, 10, nil, nil))
	if ladder != "[0 1 3 7]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(SearchBinaryLadder(8, 10, nil, nil))
	if ladder != "[0 1 3 7 15 11 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}

	// Ends after the first non-inclusion proof for a version less than or equal
	// to target.
	ladder = fmt.Sprint(SearchBinaryLadder(10, 6, nil, nil))
	if ladder != "[0 1 3 7]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(SearchBinaryLadder(10, 8, nil, nil))
	if ladder != "[0 1 3 7 15 11 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(SearchBinaryLadder(7, 6, nil, nil))
	if ladder != "[0 1 3 7]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
}

func TestMonitoringBinaryLadder(t *testing.T) {
	ladder := fmt.Sprint(MonitoringBinaryLadder(9, nil))
	if ladder != "[0 1 3 7 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
}
