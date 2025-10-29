package structs

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/Bren2010/katie/crypto/suites"
)

type UpdatePrefix struct {
	Signature []byte
}

func NewUpdatePrefix(config *PublicConfig, buf *bytes.Buffer) (*UpdatePrefix, error) {
	if config.Mode != ThirdPartyManagement {
		return &UpdatePrefix{}, nil
	}
	signature, err := readU16Bytes(buf)
	if err != nil {
		return nil, err
	}
	return &UpdatePrefix{signature}, nil
}

func (up *UpdatePrefix) Marshal(buf *bytes.Buffer) error {
	if up.Signature == nil {
		return nil
	} else if err := writeU16Bytes(buf, up.Signature, "service operator signature"); err != nil {
		return err
	}
	return nil
}

type UpdateValue struct {
	UpdatePrefix
	Value []byte
}

func NewUpdateValue(config *PublicConfig, buf *bytes.Buffer) (*UpdateValue, error) {
	prefix, err := NewUpdatePrefix(config, buf)
	if err != nil {
		return nil, err
	}
	value, err := readU32Bytes(buf)
	if err != nil {
		return nil, err
	}
	return &UpdateValue{*prefix, value}, nil
}

func (uv *UpdateValue) Marshal(buf *bytes.Buffer) error {
	if err := uv.UpdatePrefix.Marshal(buf); err != nil {
		return err
	} else if err := writeU32Bytes(buf, uv.Value, "label value"); err != nil {
		return err
	}
	return nil
}

type UpdateTBS struct {
	Label   []byte
	Version uint32
	Value   []byte
}

func (tbs *UpdateTBS) Marshal(buf *bytes.Buffer) error {
	if err := writeU8Bytes(buf, tbs.Label, "label"); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, tbs.Version); err != nil {
		return err
	} else if err := writeU32Bytes(buf, tbs.Value, "label value"); err != nil {
		return err
	}
	return nil
}

type CommitmentValue struct {
	Label  []byte
	Update UpdateValue
}

func (cv *CommitmentValue) Marshal(buf *bytes.Buffer) error {
	if err := writeU8Bytes(buf, cv.Label, "label"); err != nil {
		return err
	} else if err := cv.Update.Marshal(buf); err != nil {
		return err
	}
	return nil
}

type VrfInput struct {
	Label   []byte
	Version uint32
}

func (vi *VrfInput) Marshal(buf *bytes.Buffer) error {
	if err := writeU8Bytes(buf, vi.Label, "label"); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, vi.Version); err != nil {
		return err
	}
	return nil
}

type LogEntry struct {
	Timestamp  uint64
	PrefixTree []byte
}

func NewLogEntry(cs suites.CipherSuite, buf *bytes.Buffer) (*LogEntry, error) {
	var timestamp uint64
	if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, err
	}
	prefixTree := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, prefixTree); err != nil {
		return nil, err
	}
	return &LogEntry{timestamp, prefixTree}, nil
}

func (le *LogEntry) Marshal(buf *bytes.Buffer) error {
	if err := binary.Write(buf, binary.BigEndian, le.Timestamp); err != nil {
		return err
	} else if _, err := buf.Write(le.PrefixTree); err != nil {
		return err
	}
	return nil
}

type BinaryLadderStep struct {
	Proof      []byte
	Commitment []byte
}

func NewBinaryLadderStep(cs suites.CipherSuite, buf *bytes.Buffer) (*BinaryLadderStep, error) {
	proof := make([]byte, cs.VrfProofSize())
	if _, err := io.ReadFull(buf, proof); err != nil {
		return nil, err
	}

	var commitment []byte
	if present, err := readOptional(buf); err != nil {
		return nil, err
	} else if present {
		commitment = make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, commitment); err != nil {
			return nil, err
		}
	}

	return &BinaryLadderStep{proof, commitment}, nil
}

func (bls *BinaryLadderStep) Marshal(buf *bytes.Buffer) error {
	if _, err := buf.Write(bls.Proof); err != nil {
		return err
	}

	if err := writeOptional(buf, bls.Commitment != nil); err != nil {
		return err
	} else if bls.Commitment != nil {
		if _, err := buf.Write(bls.Commitment); err != nil {
			return err
		}
	}

	return nil
}

type LabelValue struct {
	Opening []byte
	Value   UpdateValue
}

func NewLabelValue(config *PublicConfig, buf *bytes.Buffer) (*LabelValue, error) {
	opening := make([]byte, config.Suite.CommitmentOpeningSize())
	if _, err := io.ReadFull(buf, opening); err != nil {
		return nil, err
	}
	value, err := NewUpdateValue(config, buf)
	if err != nil {
		return nil, err
	}
	return &LabelValue{Opening: opening, Value: *value}, nil
}

func (lv *LabelValue) Marshal(buf *bytes.Buffer) error {
	if _, err := buf.Write(lv.Opening); err != nil {
		return err
	} else if err := lv.Value.Marshal(buf); err != nil {
		return err
	}
	return nil
}
