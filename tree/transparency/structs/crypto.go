package structs

import (
	"bytes"
	"encoding/binary"
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
	Opening []byte
	Label   []byte
	Update  UpdateValue
}

func (cv *CommitmentValue) Marshal(buf *bytes.Buffer) error {
	if _, err := buf.Write(cv.Opening); err != nil {
		return err
	} else if err := writeU8Bytes(buf, cv.Label, "label"); err != nil {
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

type LogLeaf struct {
	Timestamp  uint64
	PrefixTree []byte
}

func (ll *LogLeaf) Marshal(buf *bytes.Buffer) error {
	if err := binary.Write(buf, binary.BigEndian, ll.Timestamp); err != nil {
		return err
	} else if _, err := buf.Write(ll.PrefixTree); err != nil {
		return err
	}
	return nil
}
