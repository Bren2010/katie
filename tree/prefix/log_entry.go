package prefix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

type leafNode struct {
	key [32]byte // The full key that was inserted.
	ctr uint32   // Counter, incremented each time the key is inserted.
}

func newLeafNode(buf *bytes.Buffer) (*leafNode, error) {
	if buf.Len() < 36 {
		return nil, errors.New("buffer is too short to decode leaf node")
	}

	var key [32]byte
	if _, err := io.ReadFull(buf, key[:]); err != nil {
		return nil, err
	}
	var ctr uint32
	if err := binary.Read(buf, binary.BigEndian, &ctr); err != nil {
		return nil, err
	}

	return &leafNode{key, ctr}, nil
}

func (ln *leafNode) Marshal(buf *bytes.Buffer) error {
	if _, err := buf.Write(ln.key[:]); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, ln.ctr); err != nil {
		return err
	}
	return nil
}

type parentNode struct {
	hash   [32]byte // The hash of this subtree.
	ptr    uint64   // The id of the log entry where this subtree is stored.
	offset uint8    // The offset in the indicated log entry.
}

func newParentNode(buf *bytes.Buffer) (*parentNode, error) {
	if buf.Len() < 41 {
		return nil, errors.New("buffer is too short to decode parent node")
	}

	var hash [32]byte
	if _, err := io.ReadFull(buf, hash[:]); err != nil {
		return nil, err
	}
	var ptr uint64
	if err := binary.Read(buf, binary.BigEndian, &ptr); err != nil {
		return nil, err
	}
	var offset uint8
	if err := binary.Read(buf, binary.BigEndian, &offset); err != nil {
		return nil, err
	}

	return &parentNode{hash, ptr, offset}, nil
}

func (pn *parentNode) Marshal(buf *bytes.Buffer) error {
	if _, err := buf.Write(pn.hash[:]); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, &pn.ptr); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, &pn.offset); err != nil {
		return err
	}
	return nil
}

type emptyNode struct{}

// logEntry is the data structure that's serialized and stored in the database.
// It represents the addition of one new entry to an existing prefix tree,
// storing the new leaf and the insertion path.
type logEntry struct {
	leaf *leafNode
	path []interface{} // Path to the leaf; entries are one of: leafNode, parentNode, or emptyNode.
}

func newLogEntry(data []byte) (*logEntry, error) {
	buf := bytes.NewBuffer(data)

	leaf, err := newLeafNode(buf)
	if err != nil {
		return nil, err
	}
	path := make([]interface{}, 0)
	for {
		t, err := buf.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		} else if t == 0 {
			leaf, err := newLeafNode(buf)
			if err != nil {
				return nil, err
			}
			path = append(path, *leaf)
		} else if t == 1 {
			parent, err := newParentNode(buf)
			if err != nil {
				return nil, err
			}
			path = append(path, *parent)
		} else if t == 2 {
			path = append(path, emptyNode{})
		} else {
			return nil, errors.New("log entry is malformed")
		}
	}

	return &logEntry{leaf, path}, nil
}

func (le *logEntry) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := le.leaf.Marshal(buf); err != nil {
		return nil, err
	}
	for _, nd := range le.path {
		switch nd := nd.(type) {
		case leafNode:
			if err := buf.WriteByte(0); err != nil {
				return nil, err
			} else if err := nd.Marshal(buf); err != nil {
				return nil, err
			}
		case parentNode:
			if err := buf.WriteByte(1); err != nil {
				return nil, err
			} else if err := nd.Marshal(buf); err != nil {
				return nil, err
			}
		case emptyNode:
			if err := buf.WriteByte(2); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unexpected log entry found")
		}
	}

	return buf.Bytes(), nil
}

func (le *logEntry) proof() [][]byte {
	out := make([][]byte, len(le.path))

	for i, nd := range le.path {
		switch nd := nd.(type) {
		case leafNode:
			h := leafHash(&nd)
			out[i] = h[:]
		case parentNode:
			out[i] = nd.hash[:]
		case emptyNode:
			out[i] = make([]byte, 32)
		default:
			panic("unexpected log entry found")
		}
	}

	return out
}

func (le *logEntry) rollup(ptr uint64, offset uint8) interface{} {
	if len(le.path) <= int(offset) {
		return *le.leaf
	}

	acc := leafHash(le.leaf)
	for i := len(le.path) - 1; i >= int(offset); i-- {
		var h [32]byte

		switch nd := le.path[i].(type) {
		case leafNode:
			h = leafHash(&nd)
		case parentNode:
			h = nd.hash
		case emptyNode:
		default:
			panic("unexpected log entry found")
		}

		if getBit(le.leaf.key, i) {
			acc = parentHash(h, acc)
		} else {
			acc = parentHash(acc, h)
		}
	}

	return parentNode{acc, ptr, offset}
}

func (le *logEntry) root() [32]byte {
	switch nd := le.rollup(0, 0).(type) {
	case leafNode:
		return leafHash(&nd)
	case parentNode:
		return nd.hash
	default:
		panic("unexpected value returned by rollup")
	}
}
