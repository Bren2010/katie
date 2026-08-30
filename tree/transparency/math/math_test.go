package math

import (
	"fmt"
	"testing"
)

func TestUpdateView(t *testing.T) {
	m := uint64(70)
	entries := fmt.Sprint(UpdateView(60, &m))
	if entries != "[]" {
		t.Fatalf("unexpected output: %v", entries)
	}
	entries = fmt.Sprint(UpdateView(70, &m))
	if entries != "[]" {
		t.Fatalf("unexpected output: %v", entries)
	}

	entries = fmt.Sprint(UpdateView(70, nil))
	if entries != "[63 67 69]" {
		t.Fatalf("unexpected output: %v", entries)
	}
	m = 0
	entries = fmt.Sprint(UpdateView(70, &m))
	if entries != "[63 67 69]" {
		t.Fatalf("unexpected output: %v", entries)
	}

	m = 70
	entries = fmt.Sprint(UpdateView(100, &m))
	if entries != "[71 79 95 99]" {
		t.Fatalf("unexpected output: %v", entries)
	}
	m = 96
	entries = fmt.Sprint(UpdateView(100, &m))
	if entries != "[99]" {
		t.Fatalf("unexpected output: %v", entries)
	}
}
