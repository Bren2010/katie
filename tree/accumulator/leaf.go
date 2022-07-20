package accumulator

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// leafData is the wrapper struct for a single leaf node of an accumulator log.
type leafData struct {
	value []byte
	left  uint64
	right uint64
}

func parseLeaf(raw []byte) (*leafData, error) {
	if len(raw) < 32 {
		return nil, fmt.Errorf("leaf has unexpected length: %v", len(raw))
	}
	value := raw[:32]
	buf := bytes.NewBuffer(raw[32:])

	left, n := binary.ReadUvarint(buf)
	if err != nil {
		return nil, err
	}
	right, err := binary.ReadUvarint(buf)
	if err != nil {
		return nil, err
	}

	if buf.Len() != 0 {
		return nil, fmt.Errorf("unable to parse leaf")
	}
	return &leafData{value: value, left: left, right: right}, nil
}

func (ld *leafData) marshal() []byte {
	buf := make([]byte, 32+8+8)
	copy(buf, ld.value)

	n := binary.PutUvarint(buf[32:], ld.left)
	m := binary.PutUvarint(buf[32+n:], ld.right)

	return buf[:32+n+m]
}
