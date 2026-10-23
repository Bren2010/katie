package transparency

import (
	"bytes"
	"slices"
	"testing"

	"github.com/Bren2010/katie/tree/transparency/test"
)

func TestIndexEncoding(t *testing.T) {
	tree, err := NewTree(test.Config(t), test.MemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	input := []uint64{1000, 2000, 2500, 2500, 2500, 2500, 3000, 7000}
	if err := tree.putIndex([]byte("label"), input); err != nil {
		t.Fatal(err)
	}
	output, err := tree.getIndex([]byte("label"))
	if err != nil {
		t.Fatal(err)
	} else if !slices.Equal(input, output) {
		t.Fatal("input and output indices do not match")
	}
}

func TestPutIndexRejectsNonMonotonic(t *testing.T) {
	tree, err := NewTree(test.Config(t), test.MemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	input := []uint64{1000, 999, 2000}
	if err := tree.putIndex([]byte("label"), input); err == nil {
		t.Fatal("expected error but none returned")
	}
}

func TestComputeVrfOutput(t *testing.T) {
	tree, err := NewTree(test.Config(t), test.MemStore(), nil)
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
