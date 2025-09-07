package prefix

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"slices"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
)

func randomBytes() [32]byte {
	out := [32]byte{}
	rand.Read(out[:])
	return out
}

func TestTree(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := newMemoryPrefixStore()

	tree := NewTree(cs, store)
	roots := make([][]byte, 0)
	data := make(map[[32]byte][32]byte)

	for ver := range uint64(10) {
		// Insert some random data into the tree.
		entries := make([]Entry, 0)
		for range 10 {
			vrfOutput, commitment := randomBytes(), randomBytes()

			entries = append(entries, Entry{vrfOutput[:], commitment[:]})
			data[vrfOutput] = commitment
		}
		root, proof, err := tree.Insert(ver, entries)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)

		// Verify prior-version lookup proof.
		if ver == 0 {
			if proof != nil {
				t.Fatal("proof unexpectedly produced")
			}
		} else {
			if err := Verify(cs, entries, proof, roots[ver-1]); err != nil {
				t.Fatal(err)
			}
		}

		// Look up every VRF output and check that it matches what was
		// originally inserted.
		for vrfOutput, commitment := range data {
			res, err := tree.Search(map[uint64][][]byte{ver + 1: {vrfOutput[:]}})
			if err != nil {
				t.Fatal(err)
			} else if len(res) != 1 {
				t.Fatal("unexpected number of versions returned")
			}
			verRes := res[ver+1]
			if len(verRes.Commitments) != 1 {
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
	store := newMemoryPrefixStore()

	tree := NewTree(cs, store)
	_, _, err := tree.Insert(0, []Entry{{makeBytes(0), makeBytes(0)}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = tree.Insert(1, []Entry{{makeBytes(1), makeBytes(1)}, {makeBytes(1), makeBytes(1)}})
	if err == nil {
		t.Fatal("insert did not return error when it should have")
	}
	_, _, err = tree.Insert(1, []Entry{{makeBytes(0), makeBytes(0)}})
	if err == nil {
		t.Fatal("insert did not return error when it should have")
	}
}

func buildRandomTree(t *testing.T, cs suites.CipherSuite) (*Tree, [][]byte, [][]Entry) {
	store := newMemoryPrefixStore()

	tree := NewTree(cs, store)
	roots := make([][]byte, 0)
	allEntries := make([][]Entry, 0)

	for ver := range uint64(10) {
		entries := make([]Entry, 0)
		for range 10 {
			vrfOutput, commitment := randomBytes(), randomBytes()
			entries = append(entries, Entry{vrfOutput[:], commitment[:]})
		}
		root, _, err := tree.Insert(ver, entries)
		if err != nil {
			t.Fatal(err)
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
	selected := make([]Entry, 0)
	for _, entries := range allEntries {
		entry := entries[mrand.Intn(len(entries))]
		selected = append(selected, entry)
	}
	slices.SortFunc(selected, func(a, b Entry) int {
		return bytes.Compare(a.VrfOutput, b.VrfOutput)
	})

	// Execute search.
	searches := make(map[uint64][][]byte)
	for _, entry := range selected {
		searches[ver] = append(searches[ver], entry.VrfOutput)
	}
	res, err := tree.Search(searches)
	if err != nil {
		t.Fatal(err)
	} else if len(res) != 1 {
		t.Fatal("wrong number of results returned")
	}
	verRes := res[ver]

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
	selected := make(map[uint64][]Entry, 0)
	for i := range len(allEntries) {
		verSelected := make([]Entry, 0)

		for _, entries := range allEntries[:i+1] {
			entry := entries[mrand.Intn(len(entries))]
			verSelected = append(verSelected, entry)
		}
		slices.SortFunc(verSelected, func(a, b Entry) int {
			return bytes.Compare(a.VrfOutput, b.VrfOutput)
		})

		selected[uint64(i+1)] = verSelected
	}

	// Execute search.
	searches := make(map[uint64][][]byte)
	for ver, entries := range selected {
		for _, entry := range entries {
			searches[ver] = append(searches[ver], entry.VrfOutput)
		}
	}
	res, err := tree.Search(searches)
	if err != nil {
		t.Fatal(err)
	} else if len(res) != len(selected) {
		t.Fatal("wrong number of results returned")
	}

	// Verify search results.
	for ver, entries := range selected {
		verRes, ok := res[ver]
		if !ok {
			t.Fatal("expected result not present")
		} else if err := Verify(cs, entries, &verRes.Proof, roots[ver-1]); err != nil {
			t.Fatal(err)
		}
		for i, commitment := range verRes.Commitments {
			if !bytes.Equal(commitment, entries[i].Commitment) {
				t.Fatal("unexpected commitment returned")
			}
		}
	}
}
