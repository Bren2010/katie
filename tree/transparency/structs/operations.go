package structs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

type SearchRequest struct {
	Last *uint64

	Label   []byte
	Version *uint32
}

func NewSearchRequest(buf *bytes.Buffer) (*SearchRequest, error) {
	var last *uint64
	if present, err := readOptional(buf); err != nil {
		return nil, err
	} else if present {
		var lastActual uint64
		if err := binary.Read(buf, binary.BigEndian, &lastActual); err != nil {
			return nil, err
		}
		last = &lastActual
	}

	label, err := readU8Bytes(buf)
	if err != nil {
		return nil, err
	}

	var version *uint32
	if present, err := readOptional(buf); err != nil {
		return nil, err
	} else if present {
		var versionActual uint32
		if err := binary.Read(buf, binary.BigEndian, &versionActual); err != nil {
			return nil, err
		}
		version = &versionActual
	}

	return &SearchRequest{last, label, version}, nil
}

func (sr *SearchRequest) Marshal(buf *bytes.Buffer) error {
	if err := writeOptional(buf, sr.Last != nil); err != nil {
		return err
	} else if sr.Last != nil {
		if err := binary.Write(buf, binary.BigEndian, *sr.Last); err != nil {
			return err
		}
	}

	if err := writeU8Bytes(buf, sr.Label, "label"); err != nil {
		return err
	}

	if err := writeOptional(buf, sr.Version != nil); err != nil {
		return err
	} else if sr.Version != nil {
		if err := binary.Write(buf, binary.BigEndian, *sr.Version); err != nil {
			return err
		}
	}

	return nil
}

type SearchResponse struct {
	FullTreeHead FullTreeHead

	Version *uint32
	Opening []byte
	Value   UpdateValue

	BinaryLadder []BinaryLadderStep
	Search       CombinedTreeProof
}

func NewSearchResponse(
	config *PublicConfig,
	req *SearchRequest,
	buf *bytes.Buffer,
) (*SearchResponse, error) {
	fth, err := NewFullTreeHead(config, buf)
	if err != nil {
		return nil, err
	}

	var version *uint32
	if req.Version == nil {
		var versionActual uint32
		if err := binary.Read(buf, binary.BigEndian, &versionActual); err != nil {
			return nil, err
		}
		version = &versionActual
	}

	opening := make([]byte, config.Suite.CommitmentOpeningSize())
	if _, err := io.ReadFull(buf, opening); err != nil {
		return nil, err
	}

	value, err := NewUpdateValue(config, buf)
	if err != nil {
		return nil, err
	}

	numSteps, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	steps := make([]BinaryLadderStep, numSteps)
	for i := range steps {
		step, err := NewBinaryLadderStep(config.Suite, buf)
		if err != nil {
			return nil, err
		}
		steps[i] = *step
	}

	search, err := NewCombinedTreeProof(config.Suite, buf)
	if err != nil {
		return nil, err
	}

	return &SearchResponse{*fth, version, opening, *value, steps, *search}, nil
}

func (sr *SearchResponse) Marshal(buf *bytes.Buffer) error {
	if err := sr.FullTreeHead.Marshal(buf); err != nil {
		return err
	}

	if sr.Version != nil {
		if err := binary.Write(buf, binary.BigEndian, *sr.Version); err != nil {
			return err
		}
	}
	if _, err := buf.Write(sr.Opening); err != nil {
		return err
	} else if err := sr.Value.Marshal(buf); err != nil {
		return err
	}

	if len(sr.BinaryLadder) > maxUint8 {
		return errors.New("binary ladder is too long to marshal")
	} else if err := buf.WriteByte(byte(len(sr.BinaryLadder))); err != nil {
		return err
	}
	for _, step := range sr.BinaryLadder {
		if err := step.Marshal(buf); err != nil {
			return err
		}
	}
	if err := sr.Search.Marshal(buf); err != nil {
		return err
	}

	return nil
}
