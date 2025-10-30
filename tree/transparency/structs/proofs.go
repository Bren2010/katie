package structs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/prefix"
)

type InclusionProof struct {
	Elements [][]byte
}

func NewInclusionProof(cs suites.CipherSuite, buf *bytes.Buffer) (*InclusionProof, error) {
	var numElements uint16
	if err := binary.Read(buf, binary.BigEndian, &numElements); err != nil {
		return nil, err
	}
	elements := make([][]byte, numElements)
	for i := range int(numElements) {
		elem := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, elem); err != nil {
			return nil, err
		}
		elements[i] = elem
	}
	return &InclusionProof{elements}, nil
}

func (ip *InclusionProof) Marshal(buf *bytes.Buffer) error {
	if len(ip.Elements) > maxUint16 {
		return errors.New("inclusion proof is too long to marshal")
	}
	err := binary.Write(buf, binary.BigEndian, uint16(len(ip.Elements)))
	if err != nil {
		return err
	}
	for _, element := range ip.Elements {
		if _, err := buf.Write(element); err != nil {
			return err
		}
	}
	return nil
}

type CombinedTreeProof struct {
	Timestamps   []uint64
	PrefixProofs []prefix.PrefixProof
	PrefixRoots  [][]byte

	Inclusion InclusionProof
}

func NewCombinedTreeProof(cs suites.CipherSuite, buf *bytes.Buffer) (*CombinedTreeProof, error) {
	numTimestamps, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	timestamps := make([]uint64, numTimestamps)
	for i := range int(numTimestamps) {
		var timestamp uint64
		if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
			return nil, err
		}
		timestamps[i] = timestamp
	}

	numProofs, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	proofs := make([]prefix.PrefixProof, numProofs)
	for i := range int(numProofs) {
		proof, err := prefix.NewPrefixProof(cs, buf)
		if err != nil {
			return nil, err
		}
		proofs[i] = *proof
	}

	numRoots, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	roots := make([][]byte, numRoots)
	for i := range int(numRoots) {
		root := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, root); err != nil {
			return nil, err
		}
		roots[i] = root
	}

	inclusion, err := NewInclusionProof(cs, buf)
	if err != nil {
		return nil, err
	}

	return &CombinedTreeProof{timestamps, proofs, roots, *inclusion}, nil
}

func (ctp *CombinedTreeProof) Marshal(buf *bytes.Buffer) error {
	if len(ctp.Timestamps) > maxUint8 {
		return errors.New("timestamps are too long to marshal")
	} else if err := buf.WriteByte(byte(len(ctp.Timestamps))); err != nil {
		return err
	}
	for _, timestamp := range ctp.Timestamps {
		if err := binary.Write(buf, binary.BigEndian, timestamp); err != nil {
			return err
		}
	}

	if len(ctp.PrefixProofs) > maxUint8 {
		return errors.New("prefix proofs are too long to marshal")
	} else if err := buf.WriteByte(byte(len(ctp.PrefixProofs))); err != nil {
		return err
	}
	for _, proof := range ctp.PrefixProofs {
		if err := proof.Marshal(buf); err != nil {
			return err
		}
	}

	if len(ctp.PrefixRoots) > maxUint8 {
		return errors.New("prefix roots are too long to marshal")
	} else if err := buf.WriteByte(byte(len(ctp.PrefixRoots))); err != nil {
		return err
	}
	for _, root := range ctp.PrefixRoots {
		if _, err := buf.Write(root); err != nil {
			return err
		}
	}

	if err := ctp.Inclusion.Marshal(buf); err != nil {
		return err
	}

	return nil
}
