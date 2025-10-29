package structs

import (
	"bytes"
	"encoding/binary"
	"errors"
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

func marshalPrefixEntry(entry prefix.Entry, buf *bytes.Buffer) error {
	if _, err := buf.Write(entry.VrfOutput); err != nil {
		return err
	} else if _, err := buf.Write(entry.Commitment); err != nil {
		return err
	}
	return nil
}

type AuditorUpdate struct {
	Timestamp      uint64
	Added, Removed []prefix.Entry
	Proof          prefix.PrefixProof
}

func NewAuditorUpdate(cs suites.CipherSuite, buf *bytes.Buffer) (*AuditorUpdate, error) {
	var timestamp uint64
	if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, err
	}

	var numAdded uint16
	if err := binary.Read(buf, binary.BigEndian, &numAdded); err != nil {
		return nil, err
	}
	added := make([]prefix.Entry, numAdded)
	for i := range numAdded {
		entry, err := newPrefixEntry(cs, buf)
		if err != nil {
			return nil, err
		}
		added[i] = *entry
	}

	var numRemoved uint16
	if err := binary.Read(buf, binary.BigEndian, &numRemoved); err != nil {
		return nil, err
	}
	removed := make([]prefix.Entry, numRemoved)
	for i := range numRemoved {
		entry, err := newPrefixEntry(cs, buf)
		if err != nil {
			return nil, err
		}
		removed[i] = *entry
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
	if err := binary.Write(buf, binary.BigEndian, au.Timestamp); err != nil {
		return err
	}

	if len(au.Added) > maxUint16 {
		return errors.New("added prefix entries are too large to marshal")
	} else if err := binary.Write(buf, binary.BigEndian, uint16(len(au.Added))); err != nil {
		return err
	}
	for _, entry := range au.Added {
		if err := marshalPrefixEntry(entry, buf); err != nil {
			return err
		}
	}

	if len(au.Removed) > maxUint16 {
		return errors.New("removed prefix entries are too large to marshal")
	} else if err := binary.Write(buf, binary.BigEndian, uint16(len(au.Removed))); err != nil {
		return err
	}
	for _, entry := range au.Removed {
		if err := marshalPrefixEntry(entry, buf); err != nil {
			return err
		}
	}

	if err := au.Proof.Marshal(buf); err != nil {
		return err
	}
	return nil
}
