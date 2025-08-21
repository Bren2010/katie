package prefix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	parentNodeType uint8 = iota
	emptyNodeType
	leafNodeType
	externalNodeType
)

func encodeUvarint(x uint64) []byte {
	encoded := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(encoded, x)
	return encoded[:n]
}

type node interface {
	Marshal(buf *bytes.Buffer) error
	Count() int
}

// parentNode represents a parent node within a given tile.
type parentNode struct {
	left, right node
}

func (pn *parentNode) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(parentNodeType); err != nil {
		return err
	} else if err := pn.left.Marshal(buf); err != nil {
		return err
	} else if err := pn.right.Marshal(buf); err != nil {
		return err
	}
	return nil
}

func (pn *parentNode) Count() int { return pn.left.Count() + pn.right.Count() }

// emptyNode represents a non-existent child of a parent node.
type emptyNode struct{}

func (en *emptyNode) Marshal(buf *bytes.Buffer) error {
	return buf.WriteByte(emptyNodeType)
}

func (en *emptyNode) Count() int { return 1 }

// leafNode contains the VRF output and commitment stored in a leaf node.
type leafNode struct {
	vrfOutput  [32]byte
	commitment [32]byte
}

func newLeafNode(buf *bytes.Buffer) (*leafNode, error) {
	var vrfOutput [32]byte
	if _, err := io.ReadFull(buf, vrfOutput[:]); err != nil {
		return nil, err
	}
	var commitment [32]byte
	if _, err := io.ReadFull(buf, commitment[:]); err != nil {
		return nil, err
	}
	return &leafNode{vrfOutput, commitment}, nil
}

func (ln *leafNode) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(leafNodeType); err != nil {
		return err
	} else if _, err := buf.Write(ln.vrfOutput[:]); err != nil {
		return err
	} else if _, err := buf.Write(ln.commitment[:]); err != nil {
		return err
	}
	return nil
}

func (ln *leafNode) Count() int { return 1 }

// externalNode represents a parent node that's stored in another tile.
type externalNode struct {
	hash [32]byte // The hash of this subtree.
	ver  uint64   // The prefix tree version where the parent was created.
	ctr  uint64   // The tile counter where the parent node is stored.
}

func newExternalNode(buf *bytes.Buffer) (*externalNode, error) {
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
	return &externalNode{hash, ver, ctr}, nil
}

func (en *externalNode) Marshal(buf *bytes.Buffer) error {
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

func (en *externalNode) Count() int { return 1 }

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
		return &parentNode{left, right}, nil

	case emptyNodeType:
		return &emptyNode{}, nil

	case leafNodeType:
		return newLeafNode(buf)

	case externalNodeType:
		return newExternalNode(buf)

	default:
		return nil, errors.New("read unexpected byte")
	}
}
