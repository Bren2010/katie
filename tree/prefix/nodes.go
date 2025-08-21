package prefix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Bren2010/katie/crypto/suites"
)

const TargetTileWeight = 2000

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
	Marshal(buf *bytes.Buffer) error
}

// parentNode represents a parent node within a given tile.
type parentNode struct {
	left, right node
	hash        []byte
}

func (pn parentNode) String() string {
	return fmt.Sprintf("(%v, %v)", pn.left.String(), pn.right.String())
}

// Returns the same weight as an externalNode so that the breadth-first search
// for building tiles can incrementally include more nodes, rather than starting
// with a tile that's too large and trying to figure out how to trim it down.
func (pn parentNode) Weight(cs suites.CipherSuite) int {
	return 1 + cs.HashSize() + (2 * binary.MaxVarintLen64)
}

func (pn parentNode) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(parentNodeType); err != nil {
		return err
	} else if err := pn.left.Marshal(buf); err != nil {
		return err
	} else if err := pn.right.Marshal(buf); err != nil {
		return err
	}
	return nil
}

func hashContent(cs suites.CipherSuite, n node) []byte {
	switch n := n.(type) {
	case emptyNode:
		return make([]byte, 1+cs.HashSize())
	case leafNode:
		return append([]byte{0x01}, n.Hash(cs)...)
	case parentNode:
		return append([]byte{0x02}, n.Hash(cs)...)
	case externalNode:
		return append([]byte{0x02}, n.hash...)
	default:
		panic("unexpected node type")
	}
}

func (pn *parentNode) Hash(cs suites.CipherSuite) []byte {
	if pn.hash != nil {
		return pn.hash
	}

	h := cs.Hash()
	h.Write(hashContent(cs, pn.left))
	h.Write(hashContent(cs, pn.right))
	out := h.Sum(nil)

	pn.hash = out
	return out
}

// emptyNode represents a non-existent child of a parent node.
type emptyNode struct{}

func (en emptyNode) String() string { return "empty" }

func (en emptyNode) Weight(cs suites.CipherSuite) int { return 1 }

func (en emptyNode) Marshal(buf *bytes.Buffer) error {
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

func (ln leafNode) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(leafNodeType); err != nil {
		return err
	} else if _, err := buf.Write(ln.vrfOutput); err != nil {
		return err
	} else if _, err := buf.Write(ln.commitment); err != nil {
		return err
	}
	return nil
}

func (ln leafNode) Hash(cs suites.CipherSuite) []byte {
	h := cs.Hash()
	h.Write(ln.vrfOutput)
	h.Write(ln.commitment)
	return h.Sum(nil)
}

// externalNode represents a parent node that's stored in another tile.
type externalNode struct {
	hash []byte // The hash of this subtree.
	ver  uint64 // The prefix tree version where the parent was created.
	ctr  uint64 // The tile counter where the parent node is stored.
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
	return externalNode{hash, ver, ctr}, nil
}

func (en externalNode) String() string {
	return fmt.Sprintf("<%v;%v>", en.ver, en.ctr)
}

func (en externalNode) Weight(cs suites.CipherSuite) int {
	return 1 + cs.HashSize() + (2 * binary.MaxVarintLen64)
}

func (en externalNode) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(externalNodeType); err != nil {
		return err
	} else if _, err := buf.Write(en.hash); err != nil {
		return err
	} else if _, err := buf.Write(encodeUvarint(en.ver)); err != nil {
		return err
	} else if _, err := buf.Write(encodeUvarint(en.ctr)); err != nil {
		return err
	}
	return nil
}

func unmarshalNode(cs suites.CipherSuite, buf *bytes.Buffer) (node, error) {
	b, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	switch b {
	case parentNodeType:
		left, err := unmarshalNode(cs, buf)
		if err != nil {
			return nil, err
		}
		right, err := unmarshalNode(cs, buf)
		if err != nil {
			return nil, err
		}
		return parentNode{left: left, right: right}, nil

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

// makeOneTile performs a breadth-first search to produce the largest tile
// possible without exceeing TargetTileWeight. The tile is stored in root and
// ejected nodes are returned.
func makeOneTile(cs suites.CipherSuite, ver, ctrOffset uint64, root *node) []node {
	// Queue for the breadth-first search through the tree.
	queue := make([]*node, 1)
	queue[0] = root

	// Weight (approx. size in bytes) of the current tile.
	weight := (*root).Weight(cs)

	// Nodes that were ejected from this tile because they don't fit.
	ejected := make([]node, 0)

	for len(queue) > 0 {
		ptr := queue[0]
		queue = queue[1:]

		pn, ok := (*ptr).(parentNode)
		if !ok {
			// If n is any type other than parentNode, then it is necessarily
			// included in the current tile.
			continue
		}

		newWeight := weight - pn.Weight(cs) + pn.left.Weight(cs) + pn.right.Weight(cs)
		if newWeight <= TargetTileWeight {
			queue = append(queue, &pn.left, &pn.right)
			weight = newWeight
		} else {
			ejected = append(ejected, pn)
			*ptr = externalNode{
				hash: pn.Hash(cs),
				ver:  ver,
				ctr:  ctrOffset + uint64(len(ejected)),
			}
		}
	}

	return ejected
}

// tiles converts a (possibly abridged) prefix tree in `root` into a series of
// tiles / subtrees that obey a maximum size limit.
func tiles(cs suites.CipherSuite, ver uint64, root node) []node {
	queue := make([]node, 0)
	queue[0] = root

	out := make([]node, 0)

	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]

		ejected := makeOneTile(cs, ver, uint64(len(out)), &n)
		queue = append(queue, ejected...)
		out = append(out, n)
	}

	return out
}
