package prefix

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db/memory"
)

func randomBytes() [32]byte {
	out := [32]byte{}
	rand.Read(out[:])
	return out
}

func TestTree(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	roots := [][]byte{make([]byte, cs.HashSize())}
	data := make(map[[32]byte][32]byte)

	for ver := range uint64(10) {
		// Insert some random data into the tree.
		entries := make([]Entry, 0)
		for range 10 {
			vrfOutput, commitment := randomBytes(), randomBytes()

			entries = append(entries, Entry{vrfOutput[:], commitment[:]})
			data[vrfOutput] = commitment
		}
		root, proof, commitments, err := tree.Mutate(ver, entries, nil)
		if err != nil {
			t.Fatal(err)
		} else if len(commitments) > 0 {
			t.Fatal("unexpected number of commitments provided")
		}
		roots = append(roots, root)

		// Verify prior-version lookup proof.
		if err := Verify(cs, entries, proof, roots[ver]); err != nil {
			t.Fatal(err)
		}

		// Look up every VRF output and check that it matches what was
		// originally inserted.
		for vrfOutput, commitment := range data {
			res, err := tree.Search([]PrefixSearch{{ver + 1, [][]byte{vrfOutput[:]}}})
			if err != nil {
				t.Fatal(err)
			} else if len(res) != 1 {
				t.Fatal("unexpected number of versions returned")
			}
			verRes := res[0]
			if len(verRes.Proof.Results) != 1 || !verRes.Proof.Results[0].Inclusion() {
				t.Fatal("unexpected search result returned")
			} else if len(verRes.Commitments) != 1 {
				t.Fatal("unexpected number of commitments returned")
			} else if !bytes.Equal(verRes.Commitments[0], commitment[:]) {
				t.Fatal("unexpected commitment value returned")
			}
			err = Verify(cs, []Entry{{vrfOutput[:], commitment[:]}}, &verRes.Proof, root)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestUnableToInsertSameTwice(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	_, _, _, err := tree.Mutate(0, []Entry{{makeBytes(0), makeBytes(0)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = tree.Mutate(1, []Entry{{makeBytes(1), makeBytes(1)}, {makeBytes(1), makeBytes(1)}}, nil)
	if err == nil {
		t.Fatal("mutate did not return error when it should have")
	}
	_, _, _, err = tree.Mutate(1, []Entry{{makeBytes(0), makeBytes(0)}}, nil)
	if err == nil {
		t.Fatal("mutate did not return error when it should have")
	}
}

func TestUnableToAddAndRemoveSame(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	_, _, _, err := tree.Mutate(
		0,
		[]Entry{{makeBytes(0), makeBytes(0)}, {makeBytes(1), makeBytes(1)}},
		[][]byte{makeBytes(1)},
	)
	if err == nil {
		t.Fatal("mutate did not return error when it should have")
	}
}

func TestRemove(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	_, _, commitments, err := tree.Mutate(0, []Entry{
		{makeBytes(0), makeBytes(0)},
		{makeBytes(1), makeBytes(1)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) > 0 {
		t.Fatal("unexpected number of commitments returned")
	}
	_, _, commitments, err = tree.Mutate(1, nil, [][]byte{makeBytes(0)})
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) != 1 || !bytes.Equal(commitments[0], makeBytes(0)) {
		t.Fatal("unexpected commitment returned")
	}

	res, err := tree.Search([]PrefixSearch{{2, [][]byte{makeBytes(0), makeBytes(1)}}})
	if err != nil {
		t.Fatal(err)
	} else if len(res) != 1 {
		t.Fatal("unexpected number of results returned")
	}
	verRes := res[0]
	if len(verRes.Commitments) != 2 || len(verRes.Proof.Results) != 2 {
		t.Fatal("unexpected number of results provided")
	} else if verRes.Commitments[0] != nil || !bytes.Equal(verRes.Commitments[1], makeBytes(1)) {
		t.Fatal("unexpected commitments returned")
	} else if verRes.Proof.Results[0].Inclusion() || !verRes.Proof.Results[1].Inclusion() {
		t.Fatal("unexpected search result")
	} else if len(verRes.Proof.Elements) != 0 {
		t.Fatal("tree not properly reduced after removal")
	}
}

func TestReplace(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	_, _, commitments, err := tree.Mutate(0, []Entry{
		{makeBytes(0), makeBytes(0)},
		{makeBytes(1), makeBytes(1)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) > 0 {
		t.Fatal("unexpected number of commitments returned")
	}
	_, _, commitments, err = tree.Mutate(1, []Entry{
		{makeBytes(0), makeBytes(2)},
	}, [][]byte{makeBytes(0)})
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) != 1 || !bytes.Equal(commitments[0], makeBytes(0)) {
		t.Fatal("unexpected commitment returned")
	}

	res, err := tree.Search([]PrefixSearch{{2, [][]byte{makeBytes(0), makeBytes(1)}}})
	if err != nil {
		t.Fatal(err)
	} else if len(res) != 1 {
		t.Fatal("unexpected number of results returned")
	}
	verRes := res[0]
	if len(verRes.Commitments) != 2 || len(verRes.Proof.Results) != 2 {
		t.Fatal("unexpected number of results provided")
	} else if !bytes.Equal(verRes.Commitments[0], makeBytes(2)) || !bytes.Equal(verRes.Commitments[1], makeBytes(1)) {
		t.Fatal("unexpected commitments returned")
	} else if !verRes.Proof.Results[0].Inclusion() || !verRes.Proof.Results[1].Inclusion() {
		t.Fatal("unexpected search result")
	}
}

func buildRandomTree(t *testing.T, cs suites.CipherSuite) (*Tree, [][]byte, [][]Entry) {
	store := memory.NewPrefixStore()

	tree := NewTree(cs, store)
	roots := make([][]byte, 0)
	allEntries := make([][]Entry, 0)

	for ver := range uint64(10) {
		entries := make([]Entry, 0)
		for range 10 {
			vrfOutput, commitment := randomBytes(), randomBytes()
			entries = append(entries, Entry{vrfOutput[:], commitment[:]})
		}
		root, _, commitments, err := tree.Mutate(ver, entries, nil)
		if err != nil {
			t.Fatal(err)
		} else if len(commitments) > 0 {
			t.Fatal("unexpected number of commitments returned")
		}
		roots = append(roots, root)
		allEntries = append(allEntries, entries)
	}

	return tree, roots, allEntries
}

func TestSearchOneVersion(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree, roots, allEntries := buildRandomTree(t, cs)
	ver := uint64(len(roots))

	// Select a random entry from each version of the tree to search for.
	search := PrefixSearch{Version: ver}
	selected := make([]Entry, 0)
	for _, entries := range allEntries {
		entry := entries[mrand.Intn(len(entries))]
		search.VrfOutputs = append(search.VrfOutputs, entry.VrfOutput)
		selected = append(selected, entry)
	}

	// Execute search.
	res, err := tree.Search([]PrefixSearch{search})
	if err != nil {
		t.Fatal(err)
	} else if len(res) != 1 {
		t.Fatal("wrong number of results returned")
	}
	verRes := res[0]

	// Verify search results.
	if err := Verify(cs, selected, &verRes.Proof, roots[ver-1]); err != nil {
		t.Fatal(err)
	}
	for i, commitment := range verRes.Commitments {
		if !bytes.Equal(commitment, selected[i].Commitment) {
			t.Fatal("unexpected commitment returned")
		}
	}
}

func TestSearchMultipleVersion(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree, roots, allEntries := buildRandomTree(t, cs)

	// For each version of the tree: select a number of random entries from that
	// version or prior versions.
	searches := make([]PrefixSearch, 0)
	entries := make([][]Entry, 0)
	for i := range len(allEntries) {
		vrfOutputs := make([][]byte, 0)
		verEntries := make([]Entry, 0)

		for _, entries := range allEntries[:i+1] {
			entry := entries[mrand.Intn(len(entries))]
			vrfOutputs = append(vrfOutputs, entry.VrfOutput)
			verEntries = append(verEntries, entry)
		}

		ver := uint64(i + 1)
		searches = append(searches, PrefixSearch{ver, vrfOutputs})
		entries = append(entries, verEntries)
	}

	// Execute search.
	res, err := tree.Search(searches)
	if err != nil {
		t.Fatal(err)
	} else if len(res) != len(searches) {
		t.Fatal("wrong number of results returned")
	}

	// Verify search results.
	for i, search := range searches {
		verRes, verEntries := res[i], entries[i]
		if err := Verify(cs, verEntries, &verRes.Proof, roots[search.Version-1]); err != nil {
			t.Fatal(err)
		}
		for i, commitment := range verRes.Commitments {
			if !bytes.Equal(commitment, verEntries[i].Commitment) {
				t.Fatal("unexpected commitment returned")
			}
		}
	}
}
