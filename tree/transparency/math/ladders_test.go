package math

import (
	"fmt"
	"testing"
)

func TestFixedVersionBinaryLadder(t *testing.T) {
	// Ends after first inclusion proof for a version greater than target.
	ladder := fmt.Sprint(FixedVersionBinaryLadder(5, 10, nil, nil))
	if ladder != "[0 1 3 7]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(FixedVersionBinaryLadder(8, 10, nil, nil))
	if ladder != "[0 1 3 7 15 11 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}

	// Ends after the first non-inclusion proof for a version less than target.
	ladder = fmt.Sprint(FixedVersionBinaryLadder(10, 6, nil, nil))
	if ladder != "[0 1 3 7]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(FixedVersionBinaryLadder(10, 8, nil, nil))
	if ladder != "[0 1 3 7 15 11 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
}

func TestMonitorBinaryLadder(t *testing.T) {
	ladder := fmt.Sprint(MonitorBinaryLadder(9, nil))
	if ladder != "[0 1 3 7 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
}

func TestGreatestVersionBinaryLadder(t *testing.T) {
	ladder := fmt.Sprint(GreatestVersionBinaryLadder(7, 7, false, nil, nil, nil))
	if ladder != "[0 1 3 7 15 11 9 8]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(GreatestVersionBinaryLadder(9, 8, false, nil, nil, nil))
	if ladder != "[0 1 3 7 15 11 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(GreatestVersionBinaryLadder(
		9, 8, false, map[uint64]struct{}{0: {}}, nil, nil,
	))
	if ladder != "[1 3 7 15 11 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(GreatestVersionBinaryLadder(
		9, 8, true, nil, nil, map[uint64]struct{}{0: {}},
	))
	if ladder != "[1 3 7 15 11 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
}
