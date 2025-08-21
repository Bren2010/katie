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
	Weight() int
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
func (pn parentNode) Weight() int { return 1 + 32 + (8 * 2) }

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
		return append([]byte{0x02}, n.hash[:]...)
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

func (en emptyNode) Weight() int { return 1 }

func (en emptyNode) Marshal(buf *bytes.Buffer) error {
	return buf.WriteByte(emptyNodeType)
}

// leafNode contains the VRF output and commitment stored in a leaf node.
type leafNode struct {
	vrfOutput  [32]byte
	commitment [32]byte
}

func newLeafNode(buf *bytes.Buffer) (node, error) {
	var vrfOutput [32]byte
	if _, err := io.ReadFull(buf, vrfOutput[:]); err != nil {
		return nil, err
	}
	var commitment [32]byte
	if _, err := io.ReadFull(buf, commitment[:]); err != nil {
		return nil, err
	}
	return leafNode{vrfOutput, commitment}, nil
}

func (ln leafNode) String() string {
	return fmt.Sprintf("[%x;%x]", ln.vrfOutput, ln.commitment)
}

func (ln leafNode) Weight() int { return 1 + (32 * 2) }

func (ln leafNode) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(leafNodeType); err != nil {
		return err
	} else if _, err := buf.Write(ln.vrfOutput[:]); err != nil {
		return err
	} else if _, err := buf.Write(ln.commitment[:]); err != nil {
		return err
	}
	return nil
}

func (ln leafNode) Hash(cs suites.CipherSuite) []byte {
	h := cs.Hash()
	h.Write(ln.vrfOutput[:])
	h.Write(ln.commitment[:])
	return h.Sum(nil)
}

// externalNode represents a parent node that's stored in another tile.
type externalNode struct {
	hash [32]byte // The hash of this subtree.
	ver  uint64   // The prefix tree version where the parent was created.
	ctr  uint64   // The tile counter where the parent node is stored.
}

func newExternalNode(buf *bytes.Buffer) (node, error) {
	var hash [32]byte
	if _, err := io.ReadFull(buf, hash[:]); err != nil {
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

func (en externalNode) Weight() int {
	return 1 + 32 + (binary.MaxVarintLen64 * 2)
}

func (en externalNode) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(externalNodeType); err != nil {
		return err
	} else if _, err := buf.Write(en.hash[:]); err != nil {
		return err
	} else if _, err := buf.Write(encodeUvarint(en.ver)); err != nil {
		return err
	} else if _, err := buf.Write(encodeUvarint(en.ctr)); err != nil {
		return err
	}
	return nil
}

func unmarshalNode(buf *bytes.Buffer) (node, error) {
	b, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	switch b {
	case parentNodeType:
		left, err := unmarshalNode(buf)
		if err != nil {
			return nil, err
		}
		right, err := unmarshalNode(buf)
		if err != nil {
			return nil, err
		}
		return parentNode{left: left, right: right}, nil

	case emptyNodeType:
		return emptyNode{}, nil

	case leafNodeType:
		return newLeafNode(buf)

	case externalNodeType:
		return newExternalNode(buf)

	default:
		return nil, errors.New("read unexpected byte")
	}
}
