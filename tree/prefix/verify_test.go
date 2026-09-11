package prefix

import (
	"bytes"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
)

func TestVerifyRoot(t *testing.T) {
	cs := suites.KTSha256P256{}

	root := leafNode{makeBytes(0x00), makeBytes(0x00)}
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
		left:  leafNode{makeBytes(0x00), makeBytes(0x00)},
		right: leafNode{makeBytes(0x80), makeBytes(0x80)},
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
				right: leafNode{makeBytes(0x20), makeBytes(0xFF)},
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
				right: leafNode{makeBytes(0x20), makeBytes(0xFF)},
			},
			right: externalNode{hash: makeBytes(2)},
		},
		right: &parentNode{
			left: &parentNode{
				left:  externalNode{hash: makeBytes(3)},
				right: leafNode{makeBytes(0xA0), makeBytes(0xBB)},
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

// TestVerifyNonInclusionOfIncludedEntryFails checks that a non-inclusion proof
// can not present the leaf that was searched for as the different leaf that the
// search terminated on. Such a proof evaluates to the correct root hash while
// claiming that an entry which is in the tree is absent.
func TestVerifyNonInclusionOfIncludedEntryFails(t *testing.T) {
	cs := suites.KTSha256P256{}

	searched := leafNode{makeBytes(0x00), makeBytes(0x11)}
	other := leafNode{makeBytes(0x80), makeBytes(0x22)}
	root := &parentNode{left: searched, right: other}

	proof := &PrefixProof{
		Results:  []PrefixSearchResult{nonInclusionLeafProof{leaf: searched, depth: 1}},
		Elements: [][]byte{other.Hash(cs)},
	}
	entries := []Entry{{VrfOutput: searched.vrfOutput}}

	if err := Verify(cs, entries, proof, root.Hash(cs)); err == nil {
		t.Fatal("verify accepted non-inclusion proof for an entry that is in the tree")
	}
}

// TestVerifyWrongCommitmentFails checks that an inclusion proof can not present
// a commitment other than the one that's in the tree. The leaf is put in the
// skeleton by the non-inclusion proof for an entry that terminates on it, so
// the root hash is computed over the real commitment either way.
func TestVerifyWrongCommitmentFails(t *testing.T) {
	cs := suites.KTSha256P256{}

	included := leafNode{makeBytes(0x80), makeBytes(0x22)}
	root := &parentNode{left: leafNode{makeBytes(0x00), makeBytes(0x11)}, right: included}

	entries := []Entry{
		{VrfOutput: makeBytes(0xc0)},
		{VrfOutput: included.vrfOutput, Commitment: makeBytes(0x33)},
	}
	proof := &PrefixProof{
		Results: []PrefixSearchResult{
			nonInclusionLeafProof{leaf: included, depth: 1},
			inclusionProof{depth: 1},
		},
		Elements: [][]byte{root.left.Hash(cs)},
	}

	if err := Verify(cs, entries, proof, root.Hash(cs)); err == nil {
		t.Fatal("verify accepted inclusion proof with a commitment that is not in the tree")
	}
}

// TestVerifyInconsistentResultsFail checks that two search results can not
// disagree about which node is at a given position in the tree.
func TestVerifyInconsistentResultsFail(t *testing.T) {
	cs := suites.KTSha256P256{}

	entries := []Entry{{VrfOutput: makeBytes(0xc0)}, {VrfOutput: makeBytes(0xa0)}}
	proof := &PrefixProof{
		Results: []PrefixSearchResult{
			nonInclusionLeafProof{leaf: leafNode{makeBytes(0x80), makeBytes(0x22)}, depth: 1},
			nonInclusionParentProof{depth: 1},
		},
		Elements: [][]byte{make([]byte, cs.HashSize())},
	}

	if _, err := Evaluate(cs, entries, proof); err == nil {
		t.Fatal("evaluate accepted results that disagree about the same node")
	}
}

// TestEvaluateBeforeAfterRejectsIncludedAdd checks that an entry can not be
// added when the proof says it's already in the tree. Applying such a mutation
// looks for a free position for the new leaf below one that has the same vrf
// output, and runs off the end of the vrf output looking for it.
func TestEvaluateBeforeAfterRejectsIncludedAdd(t *testing.T) {
	cs := suites.KTSha256P256{}

	add := []Entry{{makeBytes(0x00), makeBytes(0x11)}}
	proof := &PrefixProof{Results: []PrefixSearchResult{inclusionProof{depth: 0}}}

	if _, _, err := EvaluateBeforeAfter(cs, add, nil, proof); err == nil {
		t.Fatal("accepted an addition of an entry that is already in the tree")
	}
}

// TestEvaluateBeforeAfterRejectsAbsentRemove checks that an entry can not be
// removed when the proof says it's not in the tree.
func TestEvaluateBeforeAfterRejectsAbsentRemove(t *testing.T) {
	cs := suites.KTSha256P256{}

	remove := []Entry{{makeBytes(0x00), makeBytes(0x11)}}
	proof := &PrefixProof{Results: []PrefixSearchResult{nonInclusionParentProof{depth: 0}}}

	if _, _, err := EvaluateBeforeAfter(cs, nil, remove, proof); err == nil {
		t.Fatal("accepted a removal of an entry that is not in the tree")
	}
}
