// Package structs implements the encoding and decoding of structures needed for
// a Transparency Tree.
package structs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const maxUint16 int = 65535

func readU16Bytes(buf *bytes.Buffer) ([]byte, error) {
	var size uint16
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(buf, out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeU16Bytes(buf *bytes.Buffer, out []byte, name string) error {
	if len(out) > maxUint16 {
		return errors.New(name + " is too long to marshal")
	} else if err := binary.Write(buf, binary.BigEndian, uint16(len(out))); err != nil {
		return err
	} else if _, err := buf.Write(out); err != nil {
		return err
	}
	return nil
}

type LogLeaf struct {
	Timestamp  uint64
	PrefixTree []byte
}

type UpdatePrefix struct {
	Signature []byte
}

type UpdateValue struct {
	UpdatePrefix
	Value []byte
}

type UpdateTBS struct {
	Label   []byte
	Version uint32
	Value   []byte
}

type CommitmentValue struct {
	Opening []byte
	Label   []byte
	Update  UpdateValue
}
