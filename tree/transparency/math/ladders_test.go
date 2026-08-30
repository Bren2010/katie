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

	// Correctly handles versions where the ladder might exceed 2^32-1.
	ladder = fmt.Sprint(SearchBinaryLadder(uint32((1<<32)-1), uint32((1<<32)-1), nil, nil))
	if ladder != "[0 1 3 7 15 31 63 127 255 511 1023 2047 4095 8191 16383 32767 65535 131071 262143 524287 1048575 2097151 4194303 8388607 16777215 33554431 67108863 134217727 268435455 536870911 1073741823 2147483647 4294967295]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
	ladder = fmt.Sprint(SearchBinaryLadder(uint32((1<<32)-2), uint32((1<<32)-2), nil, nil))
	if ladder != "[0 1 3 7 15 31 63 127 255 511 1023 2047 4095 8191 16383 32767 65535 131071 262143 524287 1048575 2097151 4194303 8388607 16777215 33554431 67108863 134217727 268435455 536870911 1073741823 2147483647 4294967295 3221225471 3758096383 4026531839 4160749567 4227858431 4261412863 4278190079 4286578687 4290772991 4292870143 4293918719 4294443007 4294705151 4294836223 4294901759 4294934527 4294950911 4294959103 4294963199 4294965247 4294966271 4294966783 4294967039 4294967167 4294967231 4294967263 4294967279 4294967287 4294967291 4294967293 4294967294]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
}

func TestMonitoringBinaryLadder(t *testing.T) {
	ladder := fmt.Sprint(MonitoringBinaryLadder(9))
	if ladder != "[0 1 3 7 9]" {
		t.Fatalf("unexpected output: %v", ladder)
	}
}
