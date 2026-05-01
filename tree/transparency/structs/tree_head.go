package structs

import (
	"bytes"
	"errors"
)

type TreeHead struct {
	TreeSize  uint64
	Signature []byte
}

func NewTreeHead(buf *bytes.Buffer) (*TreeHead, error) {
	treeSize, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	signature, err := readBytes[uint16](buf)
	if err != nil {
		return nil, err
	}
	return &TreeHead{treeSize, signature}, nil
}

func (th *TreeHead) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, th.TreeSize)
	return writeBytes[uint16](buf, th.Signature, "signature")
}

type TreeHeadTBS struct {
	Config   *PublicConfig
	TreeSize uint64
	Root     []byte
}

func (tbs *TreeHeadTBS) Marshal(buf *bytes.Buffer) error {
	if err := tbs.Config.Marshal(buf); err != nil {
		return err
	}
	writeNumeric(buf, tbs.TreeSize)
	buf.Write(tbs.Root)
	return nil
}

type AuditorTreeHead struct {
	Timestamp uint64
	TreeSize  uint64
	Signature []byte
}

func NewAuditorTreeHead(buf *bytes.Buffer) (*AuditorTreeHead, error) {
	timestamp, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	treeSize, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	signature, err := readBytes[uint16](buf)
	if err != nil {
		return nil, err
	}
	return &AuditorTreeHead{timestamp, treeSize, signature}, nil
}

func (ath *AuditorTreeHead) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, ath.Timestamp)
	writeNumeric(buf, ath.TreeSize)
	return writeBytes[uint16](buf, ath.Signature, "auditor signature")
}

type AuditorTreeHeadTBS struct {
	Config    *PublicConfig
	Timestamp uint64
	TreeSize  uint64
	Root      []byte
}

func (tbs *AuditorTreeHeadTBS) Marshal(buf *bytes.Buffer) error {
	if err := tbs.Config.Marshal(buf); err != nil {
		return err
	}
	writeNumeric(buf, tbs.Timestamp)
	writeNumeric(buf, tbs.TreeSize)
	buf.Write(tbs.Root)
	return nil
}

type FullTreeHeadType byte

const (
	SameHead FullTreeHeadType = iota + 1
	UpdatedHead
)

type FullTreeHead struct {
	TreeHead        *TreeHead
	AuditorTreeHead *AuditorTreeHead
}

func NewFullTreeHead(config *PublicConfig, buf *bytes.Buffer) (*FullTreeHead, error) {
	b, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	headType := FullTreeHeadType(b)
	if headType != SameHead && headType != UpdatedHead {
		return nil, errors.New("unexpected head type read")
	}

	var (
		treeHead        *TreeHead
		auditorTreeHead *AuditorTreeHead
	)
	if headType == UpdatedHead {
		treeHead, err = NewTreeHead(buf)
		if err != nil {
			return nil, err
		}
		if config.Mode == ThirdPartyAuditing {
			auditorTreeHead, err = NewAuditorTreeHead(buf)
			if err != nil {
				return nil, err
			}
		}
	}

	return &FullTreeHead{treeHead, auditorTreeHead}, nil
}

func (fth *FullTreeHead) Marshal(buf *bytes.Buffer) error {
	if fth.TreeHead == nil {
		buf.WriteByte(byte(SameHead))
		return nil
	}

	buf.WriteByte(byte(UpdatedHead))
	if err := fth.TreeHead.Marshal(buf); err != nil {
		return err
	}
	if fth.AuditorTreeHead != nil {
		if err := fth.AuditorTreeHead.Marshal(buf); err != nil {
			return err
		}
	}
	return nil
}
