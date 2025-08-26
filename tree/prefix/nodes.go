package prefix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Bren2010/katie/crypto/suites"
)

const (
	IntermediateSuppression = 4
	MaxTileWeight           = 1000
)

func shouldStoreIntermediate(depth int) bool {
	return (depth % IntermediateSuppression) == (IntermediateSuppression - 1)
}

const (
	emptyNodeType uint8 = iota
	leafNodeType
	parentNodeType
	externalNodeType
)

func encodeUvarint(x uint64) []byte {
	encoded := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(encoded, x)
	return encoded[:n]
}

type node interface {
	String() string
	Weight(cs suites.CipherSuite) int
	Hash(cs suites.CipherSuite) []byte
	Marshal(cs suites.CipherSuite, depth int, buf *bytes.Buffer) error
}

// parentNode represents a parent node within a given tile.
type parentNode struct {
	left, right node
	hash        []byte
	id          *tileId
}

func (pn *parentNode) String() string {
	return fmt.Sprintf("(%v, %v)", pn.left.String(), pn.right.String())
}

// Returns the same weight as an externalNode so that the breadth-first search
// for building tiles can incrementally include more nodes, rather than starting
// with a tile that's too large and trying to figure out how to trim it down.
func (pn *parentNode) Weight(cs suites.CipherSuite) int {
	return 1 + cs.HashSize() + (2 * binary.MaxVarintLen64)
}

func (pn *parentNode) Hash(cs suites.CipherSuite) []byte {
	if pn.hash != nil {
		return pn.hash
	}

	h := cs.Hash()
	h.Write([]byte{0x02})
	h.Write(pn.left.Hash(cs))
	h.Write(pn.right.Hash(cs))
	out := h.Sum(nil)

	pn.hash = out
	return out
}

func (pn *parentNode) Marshal(cs suites.CipherSuite, depth int, buf *bytes.Buffer) error {
	if err := buf.WriteByte(parentNodeType); err != nil {
		return err
	}
	if shouldStoreIntermediate(depth) {
		if _, err := buf.Write(pn.Hash(cs)); err != nil {
			return err
		}
	}
	if err := pn.left.Marshal(cs, depth+1, buf); err != nil {
		return err
	} else if err := pn.right.Marshal(cs, depth+1, buf); err != nil {
		return err
	}
	return nil
}

// emptyNode represents a non-existent child of a parent node.
type emptyNode struct{}

func (en emptyNode) String() string { return "empty" }

func (en emptyNode) Weight(cs suites.CipherSuite) int { return 1 }

func (en emptyNode) Hash(cs suites.CipherSuite) []byte {
	return make([]byte, cs.HashSize())
}

func (en emptyNode) Marshal(cs suites.CipherSuite, depth int, buf *bytes.Buffer) error {
	return buf.WriteByte(emptyNodeType)
}

// leafNode contains the VRF output and commitment stored in a leaf node.
type leafNode struct {
	vrfOutput, commitment []byte
}

func newLeafNode(cs suites.CipherSuite, buf *bytes.Buffer) (node, error) {
	vrfOutput := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, vrfOutput); err != nil {
		return nil, err
	}
	commitment := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, commitment); err != nil {
		return nil, err
	}
	return leafNode{vrfOutput, commitment}, nil
}

func (ln leafNode) String() string {
	return fmt.Sprintf("[%x;%x]", ln.vrfOutput, ln.commitment)
}

func (ln leafNode) Weight(cs suites.CipherSuite) int {
	return 1 + (2 * cs.HashSize())
}

func (ln leafNode) Hash(cs suites.CipherSuite) []byte {
	h := cs.Hash()
	h.Write([]byte{0x01})
	h.Write(ln.vrfOutput)
	h.Write(ln.commitment)
	return h.Sum(nil)
}

func (ln leafNode) Marshal(cs suites.CipherSuite, depth int, buf *bytes.Buffer) error {
	if err := buf.WriteByte(leafNodeType); err != nil {
		return err
	} else if _, err := buf.Write(ln.vrfOutput); err != nil {
		return err
	} else if _, err := buf.Write(ln.commitment); err != nil {
		return err
	}
	return nil
}

// externalNode represents a parent node that's stored in another tile.
type externalNode struct {
	hash []byte // The hash of this subtree.
	id   tileId // The id of the tile where the subtree is stored.
}

func newExternalNode(cs suites.CipherSuite, buf *bytes.Buffer) (node, error) {
	hash := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, hash); err != nil {
		return nil, err
	}
	ver, err := binary.ReadUvarint(buf)
	if err != nil {
		return nil, err
	}
	ctr, err := binary.ReadUvarint(buf)
	if err != nil {
		return nil, err
	}
	return externalNode{hash, tileId{ver, ctr}}, nil
}

func (en externalNode) String() string {
	return fmt.Sprintf("<%v;%v>", en.id.ver, en.id.ctr)
}

func (en externalNode) Weight(cs suites.CipherSuite) int {
	return 1 + cs.HashSize() + (2 * binary.MaxVarintLen64)
}

func (en externalNode) Hash(cs suites.CipherSuite) []byte { return en.hash }

func (en externalNode) Marshal(cs suites.CipherSuite, depth int, buf *bytes.Buffer) error {
	if err := buf.WriteByte(externalNodeType); err != nil {
		return err
	} else if _, err := buf.Write(en.hash); err != nil {
		return err
	} else if _, err := buf.Write(encodeUvarint(en.id.ver)); err != nil {
		return err
	} else if _, err := buf.Write(encodeUvarint(en.id.ctr)); err != nil {
		return err
	}
	return nil
}

func unmarshalNode(cs suites.CipherSuite, id *tileId, depth int, buf *bytes.Buffer) (node, error) {
	b, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	switch b {
	case parentNodeType:
		var hash []byte
		if shouldStoreIntermediate(depth) {
			hash = make([]byte, cs.HashSize())
			if _, err := io.ReadFull(buf, hash); err != nil {
				return nil, err
			}
		}
		left, err := unmarshalNode(cs, id, depth+1, buf)
		if err != nil {
			return nil, err
		}
		right, err := unmarshalNode(cs, id, depth+1, buf)
		if err != nil {
			return nil, err
		}
		return &parentNode{left: left, right: right, hash: hash, id: id}, nil

	case emptyNodeType:
		return emptyNode{}, nil

	case leafNodeType:
		return newLeafNode(cs, buf)

	case externalNodeType:
		return newExternalNode(cs, buf)

	default:
		return nil, errors.New("read unexpected byte")
	}
}

type tileId struct {
	ver uint64
	ctr uint64
}

func (tid tileId) String() string {
	return fmt.Sprintf("%x:%x", tid.ver, tid.ctr)
}

type tile struct {
	id    tileId
	depth int
	root  node
}

func (t *tile) Marshal(cs suites.CipherSuite) ([]byte, error) {
	buf := &bytes.Buffer{}

	if t.depth > 255 {
		return nil, errors.New("depth is too large to marshal")
	} else if err := buf.WriteByte(byte(t.depth)); err != nil {
		return nil, err
	} else if err := t.root.Marshal(cs, t.depth, buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func unmarshalTile(cs suites.CipherSuite, id tileId, raw []byte) (tile, error) {
	buf := bytes.NewBuffer(raw)

	d, err := buf.ReadByte()
	if err != nil {
		return tile{}, err
	}
	depth := int(d)

	root, err := unmarshalNode(cs, &id, depth, buf)
	if err != nil {
		return tile{}, err
	}

	return tile{id, depth, root}, nil
}

type pointerAndDepth struct {
	ptr   *node
	depth int
}

type nodeAndDepth struct {
	nd    node
	depth int
}

// makeTile performs a breadth-first search to produce the largest tile possible
// without exceeing MaxTileWeight. The tile is stored in root and ejected nodes
// are returned.
func makeTile(cs suites.CipherSuite, ver, ctrOffset uint64, root *node, depth int) []nodeAndDepth {
	// Queue for the breadth-first search through the tree.
	queue := []pointerAndDepth{{ptr: root, depth: depth}}

	// Weight (approx. size in bytes) of the current tile.
	weight := (*root).Weight(cs)

	// Nodes that were ejected from this tile because they don't fit.
	ejected := make([]nodeAndDepth, 0)

	for len(queue) > 0 {
		elem := queue[0]
		queue = queue[1:]

		p, ok := (*elem.ptr).(*parentNode)
		if !ok {
			// If n is any type other than parentNode, then it is necessarily
			// included in the current tile.
			continue
		}

		newWeight := weight - p.Weight(cs) + 1 + p.left.Weight(cs) + p.right.Weight(cs)
		if shouldStoreIntermediate(elem.depth) {
			newWeight += cs.HashSize()
		}

		if newWeight <= MaxTileWeight {
			queue = append(queue,
				pointerAndDepth{ptr: &p.left, depth: elem.depth + 1},
				pointerAndDepth{ptr: &p.right, depth: elem.depth + 1})
			weight = newWeight
		} else {
			ejected = append(ejected, nodeAndDepth{nd: p, depth: elem.depth})
			*elem.ptr = externalNode{
				hash: p.Hash(cs),
				id:   tileId{ver: ver, ctr: ctrOffset + uint64(len(ejected))},
			}
		}
	}

	return ejected
}

// splitIntoTiles converts the tree in `root` into a series of "tiles" that
// conform to a maximum size limit when serialized.
func splitIntoTiles(cs suites.CipherSuite, ver uint64, root node) []tile {
	queue := []nodeAndDepth{{nd: root, depth: 0}}
	out := make([]tile, 0)

	for len(queue) > 0 {
		elem := queue[0]
		queue = queue[1:]

		ctrOffset := uint64(len(out) + len(queue))
		ejected := makeTile(cs, ver, ctrOffset, &elem.nd, elem.depth)
		queue = append(queue, ejected...)
		out = append(out, tile{
			id:    tileId{ver: ver, ctr: uint64(len(out))},
			depth: elem.depth,
			root:  elem.nd,
		})
	}

	return out
}
