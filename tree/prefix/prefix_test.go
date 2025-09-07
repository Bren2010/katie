package prefix

import (
	"bytes"
	"crypto/rand"
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
