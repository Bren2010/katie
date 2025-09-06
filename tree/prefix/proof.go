package prefix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Bren2010/katie/crypto/suites"
)

const (
	inclusionResultType uint8 = iota + 1
	nonInclusionLeafResultType
	nonInclusionParentResultType
)

// PrefixProof is the output of executing a batch search in the tree.
type PrefixProof struct {
	Results  []PrefixSearchResult
	Elements [][]byte
}

func NewPrefixProof(cs suites.CipherSuite, buf *bytes.Buffer) (*PrefixProof, error) {
	numResults, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	var results []PrefixSearchResult
	for range int(numResults) {
		result, err := unmarshalSearchResult(cs, buf)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	var numElements uint16
	if err := binary.Read(buf, binary.BigEndian, &numElements); err != nil {
		return nil, err
	}
	var elements [][]byte
	for range int(numElements) {
		elem := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, elem); err != nil {
			return nil, err
		}
		elements = append(elements, elem)
	}

	return &PrefixProof{results, elements}, nil
}

func (pp *PrefixProof) Marshal(buf *bytes.Buffer) error {
	if len(pp.Results) > 255 {
		return errors.New("results too long to marshal")
	} else if err := buf.WriteByte(byte(len(pp.Results))); err != nil {
		return err
	}
	for _, res := range pp.Results {
		if err := res.Marshal(buf); err != nil {
			return err
		}
	}

	if len(pp.Elements) > 65535 {
		return errors.New("elements too long to marshal")
	}
	err := binary.Write(buf, binary.BigEndian, uint16(len(pp.Elements)))
	if err != nil {
		return err
	}
	for _, elem := range pp.Elements {
		if _, err := buf.Write(elem); err != nil {
			return err
		}
	}

	return nil
}

// PrefixSearchResult is the result of a single search.
type PrefixSearchResult interface {
	Inclusion() bool
	Depth() int
	Marshal(buf *bytes.Buffer) error
}

type inclusionProof struct {
	commitment []byte
	depth      int
}

func (p inclusionProof) Inclusion() bool { return true }
func (p inclusionProof) Depth() int      { return p.depth }

func (p inclusionProof) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(inclusionResultType); err != nil {
		return err
	} else if err := buf.WriteByte(byte(p.depth)); err != nil {
		return err
	}
	return nil
}

type nonInclusionLeafProof struct {
	leaf  leafNode
	depth int
}

func (p nonInclusionLeafProof) Inclusion() bool { return false }
func (p nonInclusionLeafProof) Depth() int      { return p.depth }

func (p nonInclusionLeafProof) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(nonInclusionLeafResultType); err != nil {
		return err
	} else if _, err := buf.Write(p.leaf.vrfOutput); err != nil {
		return err
	} else if _, err := buf.Write(p.leaf.commitment); err != nil {
		return err
	} else if err := buf.WriteByte(byte(p.depth)); err != nil {
		return err
	}
	return nil
}

type nonInclusionParentProof struct {
	depth int
}

func (p nonInclusionParentProof) Inclusion() bool { return false }
func (p nonInclusionParentProof) Depth() int      { return p.depth }

func (p nonInclusionParentProof) Marshal(buf *bytes.Buffer) error {
	if err := buf.WriteByte(nonInclusionParentResultType); err != nil {
		return err
	} else if err := buf.WriteByte(byte(p.depth)); err != nil {
		return err
	}
	return nil
}

func unmarshalSearchResult(cs suites.CipherSuite, buf *bytes.Buffer) (PrefixSearchResult, error) {
	resultType, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	switch resultType {
	case inclusionResultType:
		depth, err := buf.ReadByte()
		if err != nil {
			return nil, err
		}
		return inclusionProof{nil, int(depth)}, nil

	case nonInclusionLeafResultType:
		vrfOutput := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, vrfOutput); err != nil {
			return nil, err
		}
		commitment := make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, commitment); err != nil {
			return nil, err
		}
		depth, err := buf.ReadByte()
		if err != nil {
			return nil, err
		}
		return nonInclusionLeafProof{
			leaf:  leafNode{vrfOutput, commitment},
			depth: int(depth),
		}, nil

	case nonInclusionParentResultType:
		depth, err := buf.ReadByte()
		if err != nil {
			return nil, err
		}
		return nonInclusionParentProof{int(depth)}, nil

	default:
		return nil, errors.New("invalid prefix search result type read")
	}
}
