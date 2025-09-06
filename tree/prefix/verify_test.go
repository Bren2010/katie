package prefix

import (
	"bytes"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
)

func TestVerifyRoot(t *testing.T) {
	cs := suites.KTSha256P256{}

	root := leafNode{vrfOutput: makeBytes(0x00), commitment: makeBytes(0x00)}
	want := root.Hash(cs)

	entries := []Entry{{makeBytes(0x00), makeBytes(0x00)}}
	proof := &PrefixProof{
		Results:  []PrefixSearchResult{inclusionProof{depth: 0}},
		Elements: nil,
	}
	got, err := Evaluate(cs, entries, proof)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(got, want) {
		t.Fatalf("unexpected root hash: got=%x want=%x", got, want)
	}
}

func TestVerifyNoCopath(t *testing.T) {
	cs := suites.KTSha256P256{}

	root := &parentNode{
		left:  leafNode{vrfOutput: makeBytes(0x00), commitment: makeBytes(0x00)},
		right: leafNode{vrfOutput: makeBytes(0x80), commitment: makeBytes(0x80)},
	}
	want := root.Hash(cs)

	entries := []Entry{
		{makeBytes(0x00), makeBytes(0x00)},
		{makeBytes(0x80), makeBytes(0x80)},
	}
	proof := &PrefixProof{
		Results: []PrefixSearchResult{
			inclusionProof{depth: 1},
			inclusionProof{depth: 1},
		},
		Elements: nil,
	}
	got, err := Evaluate(cs, entries, proof)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(got, want) {
		t.Fatalf("unexpected root hash: got=%x want=%x", got, want)
	}
}

func TestVerifyOneDeep(t *testing.T) {
	cs := suites.KTSha256P256{}

	root := &parentNode{
		left: &parentNode{
			left: &parentNode{
				left:  externalNode{hash: makeBytes(1)},
				right: leafNode{vrfOutput: makeBytes(0x20), commitment: makeBytes(0xFF)},
			},
			right: externalNode{hash: makeBytes(2)},
		},
		right: externalNode{hash: makeBytes(3)},
	}
	want := root.Hash(cs)

	entries := []Entry{{makeBytes(0x20), makeBytes(0xFF)}}
	proof := &PrefixProof{
		Results:  []PrefixSearchResult{inclusionProof{depth: 3}},
		Elements: [][]byte{makeBytes(1), makeBytes(2), makeBytes(3)},
	}
	got, err := Evaluate(cs, entries, proof)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(got, want) {
		t.Fatalf("unexpected root hash: got=%x want=%x", got, want)
	}
}

func TestVerifyTwoDeep(t *testing.T) {
	cs := suites.KTSha256P256{}

	root := &parentNode{
		left: &parentNode{
			left: &parentNode{
				left:  externalNode{hash: makeBytes(1)},
				right: leafNode{vrfOutput: makeBytes(0x20), commitment: makeBytes(0xFF)},
			},
			right: externalNode{hash: makeBytes(2)},
		},
		right: &parentNode{
			left: &parentNode{
				left:  externalNode{hash: makeBytes(3)},
				right: leafNode{vrfOutput: makeBytes(0xA0), commitment: makeBytes(0xBB)},
			},
			right: externalNode{hash: makeBytes(4)},
		},
	}
	want := root.Hash(cs)

	entries := []Entry{
		{makeBytes(0x20), makeBytes(0xFF)},
		{makeBytes(0xA0), makeBytes(0xBB)},
	}
	proof := &PrefixProof{
		Results: []PrefixSearchResult{
			inclusionProof{depth: 3},
			inclusionProof{depth: 3},
		},
		Elements: [][]byte{makeBytes(1), makeBytes(2), makeBytes(3), makeBytes(4)},
	}
	got, err := Evaluate(cs, entries, proof)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(got, want) {
		t.Fatalf("unexpected root hash: got=%x want=%x", got, want)
	}
}

func TestVerifyTooShortCopathFails(t *testing.T) {
	cs := suites.KTSha256P256{}

	entries := []Entry{{makeBytes(0x00), makeBytes(0x00)}}
	proof := &PrefixProof{
		Results:  []PrefixSearchResult{inclusionProof{depth: 3}},
		Elements: [][]byte{makeBytes(1), makeBytes(2)},
	}
	_, err := Evaluate(cs, entries, proof)
	if err == nil {
		t.Fatal("too few entries provided but evaluate did not return an error")
	}
}

func TestVerifyTooLongCopathFails(t *testing.T) {
	cs := suites.KTSha256P256{}

	entries := []Entry{{makeBytes(0x00), makeBytes(0x00)}}
	proof := &PrefixProof{
		Results:  []PrefixSearchResult{inclusionProof{depth: 3}},
		Elements: [][]byte{makeBytes(1), makeBytes(2), makeBytes(3), makeBytes(4)},
	}
	_, err := Evaluate(cs, entries, proof)
	if err == nil {
		t.Fatal("too few entries provided but evaluate did not return an error")
	}
}
