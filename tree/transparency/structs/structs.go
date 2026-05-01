// Package structs implements the encoding and decoding of structures needed for
// a Transparency Tree.
package structs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

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

type numeric interface {
	uint8 | uint16 | uint32 | uint64
}

func readNumeric[T numeric](buf *bytes.Buffer) (T, error) {
	var val T
	if err := binary.Read(buf, binary.BigEndian, &val); err != nil {
		return 0, err
	}
	return val, nil
}

func writeNumeric[T numeric](buf *bytes.Buffer, val T) {
	binary.Write(buf, binary.BigEndian, val)
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

func writeOptional(buf *bytes.Buffer, present bool) bool {
	if present {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	return present
}

func readOptionalNumeric[T numeric](buf *bytes.Buffer) (*T, error) {
	var val *T

	if present, err := readOptional(buf); err != nil {
		return nil, err
	} else if present {
		actual, err := readNumeric[T](buf)
		if err != nil {
			return nil, err
		}
		val = &actual
	}

	return val, nil
}

func writeOptionalNumeric[T numeric](buf *bytes.Buffer, val *T) {
	if writeOptional(buf, val != nil) {
		writeNumeric(buf, *val)
	}
}

type sizeParam interface {
	uint8 | uint16 | uint32
}

func max[S sizeParam]() int { return int(^S(0)) }

func readBytes[S sizeParam](buf *bytes.Buffer) ([]byte, error) {
	size, err := readNumeric[S](buf)
	if err != nil {
		return nil, err
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(buf, out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeBytes[S sizeParam](buf *bytes.Buffer, out []byte, name string) error {
	if len(out) > max[S]() {
		return errors.New(name + " is too long to marshal")
	}
	writeNumeric(buf, S(len(out)))
	buf.Write(out)
	return nil
}

func readByteSlice[S sizeParam](buf *bytes.Buffer, n int) ([][]byte, error) {
	size, err := readNumeric[S](buf)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, size)
	for i := range int(size) {
		elem := make([]byte, n)
		if _, err := io.ReadFull(buf, elem); err != nil {
			return nil, err
		}
		out[i] = elem
	}
	return out, nil
}

func writeByteSlice[S sizeParam](buf *bytes.Buffer, out [][]byte, name string) error {
	if len(out) > max[S]() {
		return errors.New(name + " list is too long to marshal")
	}
	writeNumeric(buf, S(len(out)))
	for _, elem := range out {
		buf.Write(elem)
	}
	return nil
}

func readNumericSlice[S sizeParam, T numeric](buf *bytes.Buffer) ([]T, error) {
	size, err := readNumeric[S](buf)
	if err != nil {
		return nil, err
	}
	out := make([]T, size)
	for i := range int(size) {
		val, err := readNumeric[T](buf)
		if err != nil {
			return nil, err
		}
		out[i] = val
	}
	return out, nil
}

func writeNumericSlice[S sizeParam, T numeric](
	buf *bytes.Buffer,
	out []T,
	name string,
) error {
	if len(out) > max[S]() {
		return errors.New(name + " list is too long to marshal")
	}
	writeNumeric(buf, S(len(out)))
	for _, elem := range out {
		writeNumeric(buf, elem)
	}
	return nil
}

func readFuncSlice[S sizeParam, T any](
	buf *bytes.Buffer,
	newF func(*bytes.Buffer) (*T, error),
) ([]T, error) {
	size, err := readNumeric[S](buf)
	if err != nil {
		return nil, err
	}
	out := make([]T, size)
	for i := range int(size) {
		elem, err := newF(buf)
		if err != nil {
			return nil, err
		}
		out[i] = *elem
	}
	return out, nil
}

func writeFuncSlice[S sizeParam, T any](
	buf *bytes.Buffer,
	out []T,
	name string,
	marshalF func(*T, *bytes.Buffer) error,
) error {
	if len(out) > max[S]() {
		return errors.New(name + " list is too long to marshal")
	}
	writeNumeric(buf, S(len(out)))
	for _, elem := range out {
		if err := marshalF(&elem, buf); err != nil {
			return err
		}
	}
	return nil
}

func writeMarshalSlice[S sizeParam, T any, PT interface {
	*T
	Marshaller
}](buf *bytes.Buffer, out []T, name string) error {
	if len(out) > max[S]() {
		return errors.New(name + " list is too long to marshal")
	}
	writeNumeric(buf, S(len(out)))
	for _, elem := range out {
		if err := PT(&elem).Marshal(buf); err != nil {
			return err
		}
	}
	return nil
}
