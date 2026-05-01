package structs

import (
	"bytes"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/prefix"
)

type InclusionProof struct {
	Elements [][]byte
}

func NewInclusionProof(cs suites.CipherSuite, buf *bytes.Buffer) (*InclusionProof, error) {
	elements, err := readByteSlice[uint16](buf, cs.HashSize())
	if err != nil {
		return nil, err
	}
	return &InclusionProof{elements}, nil
}

func (ip *InclusionProof) Marshal(buf *bytes.Buffer) error {
	return writeByteSlice[uint16](buf, ip.Elements, "inclusion proof")
}

type CombinedTreeProof struct {
	Timestamps   []uint64
	PrefixProofs []prefix.PrefixProof
	PrefixRoots  [][]byte

	Inclusion InclusionProof
}

func NewCombinedTreeProof(cs suites.CipherSuite, buf *bytes.Buffer) (*CombinedTreeProof, error) {
	timestamps, err := readNumericSlice[uint8, uint64](buf)
	if err != nil {
		return nil, err
	}
	proofs, err := readFuncSlice[uint8](buf, func(buf *bytes.Buffer) (*prefix.PrefixProof, error) {
		return prefix.NewPrefixProof(cs, buf)
	})
	if err != nil {
		return nil, err
	}
	roots, err := readByteSlice[uint8](buf, cs.HashSize())
	if err != nil {
		return nil, err
	}
	inclusion, err := NewInclusionProof(cs, buf)
	if err != nil {
		return nil, err
	}
	return &CombinedTreeProof{timestamps, proofs, roots, *inclusion}, nil
}

func (ctp *CombinedTreeProof) Marshal(buf *bytes.Buffer) error {
	if err := writeNumericSlice[uint8](buf, ctp.Timestamps, "timestamp"); err != nil {
		return err
	} else if err := writeMarshalSlice[uint8](buf, ctp.PrefixProofs, "prefix proof"); err != nil {
		return err
	} else if err := writeByteSlice[uint8](buf, ctp.PrefixRoots, "prefix root"); err != nil {
		return err
	}
	return ctp.Inclusion.Marshal(buf)
}
