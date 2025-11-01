// Package structs implements the encoding and decoding of structures needed for
// a Transparency Tree.
package structs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	maxUint8  int = 255
	maxUint16 int = 65535
	maxUint32 int = 4294967295
)

func readU8Bytes(buf *bytes.Buffer) ([]byte, error) {
	size, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(buf, out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeU8Bytes(buf *bytes.Buffer, out []byte, name string) error {
	if len(out) > maxUint8 {
		return errors.New(name + " is too long to marshal")
	} else if err := buf.WriteByte(byte(len(out))); err != nil {
		return err
	} else if _, err := buf.Write(out); err != nil {
		return err
	}
	return nil
}

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

func readU32Bytes(buf *bytes.Buffer) ([]byte, error) {
	var size uint32
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(buf, out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeU32Bytes(buf *bytes.Buffer, out []byte, name string) error {
	if len(out) > maxUint32 {
		return errors.New(name + " is too long to marshal")
	} else if err := binary.Write(buf, binary.BigEndian, uint32(len(out))); err != nil {
		return err
	} else if _, err := buf.Write(out); err != nil {
		return err
	}
	return nil
}

func readOptional(buf *bytes.Buffer) (bool, error) {
	present, err := buf.ReadByte()
	if err != nil {
		return false, err
	} else if present != 0 && present != 1 {
		return false, errors.New("read unexpected value in optional")
	}
	return present == 1, nil
}

func writeOptional(buf *bytes.Buffer, present bool) error {
	if present {
		return buf.WriteByte(1)
	}
	return buf.WriteByte(0)
}

type Marshaller interface {
	Marshal(buf *bytes.Buffer) error
}

// Marshal takes a structure as input and returns the marshalled struct as a
// byte slice.
func Marshal(x Marshaller) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := x.Marshal(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
