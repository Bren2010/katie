package prefix

import (
	"bytes"
	"context"
	"crypto/rand"
	mrand "math/rand"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
)

// memPrefixStore returns a PrefixStore backed by an in-memory key-value store.
func memPrefixStore() db.PrefixStore {
	kv := db.NewMemoryKeyValueStore()
	return db.NewTransparencyStore(context.Background(), kv, false).PrefixStore()
}

func randomBytes() [32]byte {
	out := [32]byte{}
	rand.Read(out[:])
	return out
}

func TestTree(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memPrefixStore()

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
	store := memPrefixStore()

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
	store := memPrefixStore()

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
	store := memPrefixStore()

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
	root, _, commitments, err := tree.Mutate(1, nil, [][]byte{makeBytes(0)})
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
	}
	entries := []Entry{{VrfOutput: makeBytes(0)}, {makeBytes(1), makeBytes(1)}}
	if err := Verify(cs, entries, &verRes.Proof, root); err != nil {
		t.Fatal(err)
	}
}

func TestReplace(t *testing.T) {
	cs := suites.KTSha256P256{}
	store := memPrefixStore()

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
	store := memPrefixStore()

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

// TestEmptyMutateFails checks that a mutation must add or remove something.
func TestEmptyMutateFails(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, memPrefixStore())

	if _, _, _, err := tree.Mutate(0, []Entry{{makeBytes(0x00), makeBytes(0x11)}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := tree.Mutate(1, nil, nil); err == nil {
		t.Fatal("mutate did not return error when it should have")
	}
}

// TestEmptySearchFails checks that a search must look for at least one vrf
// output.
func TestEmptySearchFails(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, memPrefixStore())

	if _, _, _, err := tree.Mutate(0, []Entry{{makeBytes(0x00), makeBytes(0x11)}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.Search([]PrefixSearch{{1, nil}}); err == nil {
		t.Fatal("search did not return error when it should have")
	}
}

// TestEvaluateBeforeAfterMatchesMutation checks that the proof returned by
// Mutate evaluates to the root hash of the tree both before and after the
// mutation is applied.
func TestEvaluateBeforeAfterMatchesMutation(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, memPrefixStore())

	root0, _, _, err := tree.Mutate(0, []Entry{
		{makeBytes(0x00), makeBytes(0x11)},
		{makeBytes(0x80), makeBytes(0x22)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	add := []Entry{{makeBytes(0xc0), makeBytes(0x33)}}
	root1, proof, commitments, err := tree.Mutate(1, add, [][]byte{makeBytes(0x00)})
	if err != nil {
		t.Fatal(err)
	} else if len(commitments) != 1 {
		t.Fatal("unexpected number of commitments returned")
	}
	removed := []Entry{{makeBytes(0x00), commitments[0]}}

	before, after, err := EvaluateBeforeAfter(cs, add, removed, proof)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(before, root0) {
		t.Fatal("unexpected root hash computed for the tree before the mutation")
	} else if !bytes.Equal(after, root1) {
		t.Fatal("unexpected root hash computed for the tree after the mutation")
	}
}

// checkMutationProof checks that EvaluateBeforeAfter computes the same root
// hashes for a mutation as the server did.
func checkMutationProof(
	t *testing.T,
	cs suites.CipherSuite,
	prev, next []byte,
	add []Entry,
	remove [][]byte,
	proof *PrefixProof,
	commitments [][]byte,
) {
	t.Helper()

	removed := make([]Entry, len(remove))
	for i, vrfOutput := range remove {
		removed[i] = Entry{vrfOutput, commitments[i]}
	}
	before, after, err := EvaluateBeforeAfter(cs, add, removed, proof)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(before, prev) {
		t.Fatal("unexpected root hash computed for the tree before the mutation")
	} else if !bytes.Equal(after, next) {
		t.Fatal("unexpected root hash computed for the tree after the mutation")
	}
}

// TestRemoveUntouchedLeaf checks that when a leaf is removed, a sibling leaf
// that the mutation doesn't otherwise touch stays where it is. A verifier only
// knows the sibling's hash, so it can't move the sibling up either.
func TestRemoveUntouchedLeaf(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, memPrefixStore())

	sibling := leafNode{makeBytes(0x80), makeBytes(0x22)}
	root0, _, _, err := tree.Mutate(0, []Entry{
		{makeBytes(0x00), makeBytes(0x11)},
		{sibling.vrfOutput, sibling.commitment},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	remove := [][]byte{makeBytes(0x00)}
	root1, proof, commitments, err := tree.Mutate(1, nil, remove)
	if err != nil {
		t.Fatal(err)
	}
	want := (&parentNode{left: emptyNode{}, right: sibling}).Hash(cs)
	if !bytes.Equal(root1, want) {
		t.Fatal("untouched sibling leaf was moved")
	}
	checkMutationProof(t, cs, root0, root1, nil, remove, proof, commitments)
}

// TestRemoveTouchedLeaf checks that the tree is still simplified when the leaf
// that would move up is on a search path, since a verifier can move it too.
func TestRemoveTouchedLeaf(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, memPrefixStore())

	// These share their first bit, so they're stored two levels deep.
	root0, _, _, err := tree.Mutate(0, []Entry{
		{makeBytes(0x00), makeBytes(0x11)},
		{makeBytes(0x40), makeBytes(0x22)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Replacing both with a new entry leaves a single leaf, which should move
	// all the way up to the root.
	added := leafNode{makeBytes(0x20), makeBytes(0x33)}
	add := []Entry{{added.vrfOutput, added.commitment}}
	remove := [][]byte{makeBytes(0x00), makeBytes(0x40)}
	root1, proof, commitments, err := tree.Mutate(1, add, remove)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(root1, added.Hash(cs)) {
		t.Fatal("tree not properly reduced after removal")
	}
	checkMutationProof(t, cs, root0, root1, add, remove, proof, commitments)
}

// TestEvaluateBeforeAfterRandom checks that EvaluateBeforeAfter computes the
// same root hashes as the server over a series of random mutations.
func TestEvaluateBeforeAfterRandom(t *testing.T) {
	cs := suites.KTSha256P256{}
	tree := NewTree(cs, memPrefixStore())

	roots := [][]byte{make([]byte, cs.HashSize())}
	live := make(map[string]struct{})

	for ver := range uint64(30) {
		// Remove a random subset of the entries in the tree.
		remove := make([][]byte, 0)
		for vrfOutput := range live {
			if mrand.Intn(4) == 0 {
				remove = append(remove, []byte(vrfOutput))
			}
		}

		// Add some new entries. Some share a long prefix, so that the tree has
		// deeper chains of parent nodes.
		add := make([]Entry, 0)
		for range 1 + mrand.Intn(20) {
			vrfOutput, commitment := randomBytes(), randomBytes()
			if mrand.Intn(3) == 0 {
				vrfOutput[0], vrfOutput[1] = 0x5a, 0xa5
			}
			add = append(add, Entry{vrfOutput[:], commitment[:]})
		}

		root, proof, commitments, err := tree.Mutate(ver, add, remove)
		if err != nil {
			t.Fatal(err)
		}
		checkMutationProof(t, cs, roots[ver], root, add, remove, proof, commitments)
		roots = append(roots, root)

		for _, vrfOutput := range remove {
			delete(live, string(vrfOutput))
		}
		for _, entry := range add {
			live[string(entry.VrfOutput)] = struct{}{}
		}
	}
}
