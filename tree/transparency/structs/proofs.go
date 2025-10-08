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
	elements := make([][]byte, 0, numElements)
	for range int(numElements) {
		elem := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, elem); err != nil {
			return nil, err
		}
		elements = append(elements, elem)
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
	var numTimestamps uint8
	if err := binary.Read(buf, binary.BigEndian, &numTimestamps); err != nil {
		return nil, err
	}
	timestamps := make([]uint64, 0, numTimestamps)
	for range int(numTimestamps) {
		var timestamp uint64
		if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
			return nil, err
		}
		timestamps = append(timestamps, timestamp)
	}

	var numProofs uint8
	if err := binary.Read(buf, binary.BigEndian, &numProofs); err != nil {
		return nil, err
	}
	proofs := make([]prefix.PrefixProof, 0, numProofs)
	for range int(numProofs) {
		proof, err := prefix.NewPrefixProof(cs, buf)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, *proof)
	}

	var numRoots uint8
	if err := binary.Read(buf, binary.BigEndian, &numRoots); err != nil {
		return nil, err
	}
	roots := make([][]byte, 0, numRoots)
	for range int(numRoots) {
		root := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, root); err != nil {
			return nil, err
		}
		roots = append(roots, root)
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
	}
	err := binary.Write(buf, binary.BigEndian, uint8(len(ctp.Timestamps)))
	if err != nil {
		return err
	}
	for _, timestamp := range ctp.Timestamps {
		if err := binary.Write(buf, binary.BigEndian, timestamp); err != nil {
			return err
		}
	}

	if len(ctp.PrefixProofs) > maxUint8 {
		return errors.New("prefix proofs are too long to marshal")
	}
	err = binary.Write(buf, binary.BigEndian, uint8(len(ctp.PrefixProofs)))
	if err != nil {
		return err
	}
	for _, proof := range ctp.PrefixProofs {
		if err := proof.Marshal(buf); err != nil {
			return err
		}
	}

	if len(ctp.PrefixRoots) > maxUint8 {
		return errors.New("prefix roots are too long to marshal")
	}
	err = binary.Write(buf, binary.BigEndian, uint8(len(ctp.PrefixRoots)))
	if err != nil {
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
