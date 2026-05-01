package structs

import (
	"bytes"
	"io"

	"github.com/Bren2010/katie/crypto/suites"
)

type UpdateSuffix struct {
	Signature []byte
}

func NewUpdateSuffix(config *PublicConfig, buf *bytes.Buffer) (*UpdateSuffix, error) {
	if config.Mode != ThirdPartyManagement {
		return &UpdateSuffix{}, nil
	}
	signature, err := readBytes[uint16](buf)
	if err != nil {
		return nil, err
	}
	return &UpdateSuffix{signature}, nil
}

func (us *UpdateSuffix) Marshal(buf *bytes.Buffer) error {
	if us.Signature == nil {
		return nil
	}
	return writeBytes[uint16](buf, us.Signature, "service operator signature")
}

type UpdateValue struct {
	Value []byte
	UpdateSuffix
}

func NewUpdateValue(config *PublicConfig, buf *bytes.Buffer) (*UpdateValue, error) {
	value, err := readBytes[uint32](buf)
	if err != nil {
		return nil, err
	}
	suffix, err := NewUpdateSuffix(config, buf)
	if err != nil {
		return nil, err
	}
	return &UpdateValue{value, *suffix}, nil
}

func (uv *UpdateValue) Marshal(buf *bytes.Buffer) error {
	if err := writeBytes[uint32](buf, uv.Value, "label value"); err != nil {
		return err
	}
	return uv.UpdateSuffix.Marshal(buf)
}

type UpdateTBS struct {
	Config  *PublicConfig
	Label   []byte
	Version uint32
	Value   []byte
}

func (tbs *UpdateTBS) Marshal(buf *bytes.Buffer) error {
	if err := tbs.Config.Marshal(buf); err != nil {
		return err
	} else if err := writeBytes[uint8](buf, tbs.Label, "label"); err != nil {
		return err
	}
	writeNumeric(buf, tbs.Version)
	return writeBytes[uint32](buf, tbs.Value, "label value")
}

type CommitmentValue struct {
	Label   []byte
	Version uint32
	Update  UpdateValue
}

func (cv *CommitmentValue) Marshal(buf *bytes.Buffer) error {
	if err := writeBytes[uint8](buf, cv.Label, "label"); err != nil {
		return err
	}
	writeNumeric(buf, cv.Version)
	return cv.Update.Marshal(buf)
}

type VrfInput struct {
	Label   []byte
	Version uint32
}

func (vi *VrfInput) Marshal(buf *bytes.Buffer) error {
	if err := writeBytes[uint8](buf, vi.Label, "label"); err != nil {
		return err
	}
	writeNumeric(buf, vi.Version)
	return nil
}

type LogEntry struct {
	Timestamp  uint64
	PrefixTree []byte
}

func NewLogEntry(cs suites.CipherSuite, buf *bytes.Buffer) (*LogEntry, error) {
	timestamp, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	prefixTree := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, prefixTree); err != nil {
		return nil, err
	}
	return &LogEntry{timestamp, prefixTree}, nil
}

func (le *LogEntry) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, le.Timestamp)
	buf.Write(le.PrefixTree)
	return nil
}

func (le *LogEntry) Hash(cs suites.CipherSuite) ([]byte, error) {
	raw, err := Marshal(le)
	if err != nil {
		return nil, err
	}
	hasher := cs.Hash()
	hasher.Write(raw)
	return hasher.Sum(nil), nil
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
	buf.Write(bls.Proof)
	if writeOptional(buf, bls.Commitment != nil) {
		buf.Write(bls.Commitment)
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
	buf.Write(lv.Opening)
	return lv.Value.Marshal(buf)
}
