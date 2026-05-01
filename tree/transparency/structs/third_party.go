package structs

import (
	"bytes"
	"io"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/prefix"
)

func newPrefixEntry(cs suites.CipherSuite, buf *bytes.Buffer) (*prefix.Entry, error) {
	vrfOutput := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, vrfOutput); err != nil {
		return nil, err
	}
	commitment := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, commitment); err != nil {
		return nil, err
	}
	return &prefix.Entry{VrfOutput: vrfOutput, Commitment: commitment}, nil
}

func marshalPrefixEntry(entry *prefix.Entry, buf *bytes.Buffer) error {
	buf.Write(entry.VrfOutput)
	buf.Write(entry.Commitment)
	return nil
}

type AuditorUpdate struct {
	Timestamp      uint64
	Added, Removed []prefix.Entry
	Proof          prefix.PrefixProof
}

func NewAuditorUpdate(cs suites.CipherSuite, buf *bytes.Buffer) (*AuditorUpdate, error) {
	timestamp, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}

	newF := func(buf *bytes.Buffer) (*prefix.Entry, error) { return newPrefixEntry(cs, buf) }
	added, err := readFuncSlice[uint16](buf, newF)
	if err != nil {
		return nil, err
	}
	removed, err := readFuncSlice[uint16](buf, newF)
	if err != nil {
		return nil, err
	}

	proof, err := prefix.NewPrefixProof(cs, buf)
	if err != nil {
		return nil, err
	}

	return &AuditorUpdate{
		Timestamp: timestamp,
		Added:     added,
		Removed:   removed,
		Proof:     *proof,
	}, nil
}

func (au *AuditorUpdate) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, au.Timestamp)

	if err := writeFuncSlice[uint16](buf, au.Added, "added prefix entry", marshalPrefixEntry); err != nil {
		return err
	}
	if err := writeFuncSlice[uint16](buf, au.Removed, "removed prefix entry", marshalPrefixEntry); err != nil {
		return err
	}

	return au.Proof.Marshal(buf)
}
