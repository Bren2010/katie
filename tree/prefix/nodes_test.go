package prefix

import (
	"bytes"
	"testing"

	"github.com/Bren2010/katie/crypto/suites"
)

func makeBytes(b byte) []byte {
	out := make([]byte, 32)
	for i := range len(out) {
		out[i] = b
	}
	return out
}

func TestMarshalUnmarshal1(t *testing.T) {
	cs := suites.KTSha256P256{}
	n1 := &parentNode{
		left: &parentNode{
			left:  leafNode{makeBytes(1), makeBytes(2)},
			right: leafNode{makeBytes(3), makeBytes(4)},
		},
		right: leafNode{makeBytes(5), makeBytes(6)},
	}

	buf := &bytes.Buffer{}
	if err := n1.Marshal(cs, 0, buf); err != nil {
		t.Fatal(err)
	}
	n2, err := unmarshalNode(cs, nil, 0, bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := n2.String(), n1.String(); got != want {
		t.Fatal("unmarshalled value incorrectly")
	}
}

func TestMarshalUnmarshal2(t *testing.T) {
	cs := suites.KTSha256P256{}
	n1 := &parentNode{
		left: leafNode{makeBytes(1), makeBytes(2)},
		right: &parentNode{
			left:  leafNode{makeBytes(3), makeBytes(4)},
			right: leafNode{makeBytes(5), makeBytes(6)},
		},
	}

	buf := &bytes.Buffer{}
	if err := n1.Marshal(cs, 0, buf); err != nil {
		t.Fatal(err)
	}
	n2, err := unmarshalNode(cs, nil, 0, bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := n2.String(), n1.String(); got != want {
		t.Fatal("unmarshalled value incorrectly")
	}
}

func createLargeTree(depth int) node {
	if depth == 8 {
		return leafNode{vrfOutput: makeBytes(1), commitment: makeBytes(2)}
	}
	return &parentNode{
		left:  createLargeTree(depth + 1),
		right: createLargeTree(depth + 1),
	}
}

func encodedSize(cs suites.CipherSuite, depth int, nd node) int {
	buf := &bytes.Buffer{}
	if err := nd.Marshal(cs, depth, buf); err != nil {
		panic(err)
	}
	return buf.Len()
}

func extractExternalNodes(t *testing.T, nd node, externals map[tileId][]byte) {
	switch nd := nd.(type) {
	case *parentNode:
		nd.hash = nil
		extractExternalNodes(t, nd.left, externals)
		extractExternalNodes(t, nd.right, externals)

	case externalNode:
		if existing, ok := externals[nd.id]; ok {
			if !bytes.Equal(nd.hash, existing) {
				t.Fatalf("same external node has different hashes")
			}
		}
		externals[nd.id] = nd.hash
	}
}

func TestSplitIntoTiles(t *testing.T) {
	cs := suites.KTSha256P256{}
	root := createLargeTree(0)
	want := root.Hash(cs)

	// Split large root into tiles.
	tiles := splitIntoTiles(cs, 1, root)

	// Extract the root hash of each tile and
	hashes := make(map[tileId][]byte)
	externals := make(map[tileId][]byte)
	for _, tile := range tiles {
		if got := encodedSize(cs, tile.depth, tile.root); got > TargetTileWeight {
			t.Fatalf("encoded tile is too large: %v", got)
		}
		extractExternalNodes(t, tile.root, externals)
		hashes[tile.id] = tile.root.Hash(cs)
	}

	// Check computed hashes match stored hashes.
	if !bytes.Equal(want, hashes[tileId{ver: 1, ctr: 0}]) {
		t.Fatal("root hash changed")
	}
	delete(hashes, tileId{ver: 1, ctr: 0})

	if len(hashes) != len(externals) {
		t.Fatal("unexpected number of tiles vs external nodes")
	}
	for id, want := range hashes {
		if got := externals[id]; !bytes.Equal(want, got) {
			t.Fatal("external node has unexpected hash")
		}
	}
}
