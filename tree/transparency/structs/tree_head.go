package structs

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type TreeHead struct {
	TreeSize  uint64
	Signature []byte
}

func NewTreeHead(buf *bytes.Buffer) (*TreeHead, error) {
	var treeSize uint64
	if err := binary.Read(buf, binary.BigEndian, &treeSize); err != nil {
		return nil, err
	}
	signature, err := readU16Bytes(buf)
	if err != nil {
		return nil, err
	}
	return &TreeHead{treeSize, signature}, nil
}

func (th *TreeHead) Marshal(buf *bytes.Buffer) error {
	if err := binary.Write(buf, binary.BigEndian, th.TreeSize); err != nil {
		return err
	} else if err := writeU16Bytes(buf, th.Signature, "signature"); err != nil {
		return err
	}
	return nil
}

type TreeHeadTBS struct {
	Config   PublicConfig
	TreeSize uint64
	Root     []byte
}

func (tbs *TreeHeadTBS) Marshal(buf *bytes.Buffer) error {
	if err := tbs.Config.Marshal(buf); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, tbs.TreeSize); err != nil {
		return err
	} else if _, err := buf.Write(tbs.Root); err != nil {
		return err
	}
	return nil
}

type AuditorTreeHead struct {
	Timestamp uint64
	TreeSize  uint64
	Signature []byte
}

func NewAuditorTreeHead(buf *bytes.Buffer) (*AuditorTreeHead, error) {
	var timestamp uint64
	if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, err
	}
	var treeSize uint64
	if err := binary.Read(buf, binary.BigEndian, &treeSize); err != nil {
		return nil, err
	}
	signature, err := readU16Bytes(buf)
	if err != nil {
		return nil, err
	}
	return &AuditorTreeHead{timestamp, treeSize, signature}, nil
}

func (ath *AuditorTreeHead) Marshal(buf *bytes.Buffer) error {
	if err := binary.Write(buf, binary.BigEndian, ath.Timestamp); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, ath.TreeSize); err != nil {
		return err
	} else if err := writeU16Bytes(buf, ath.Signature, "auditor signature"); err != nil {
		return err
	}
	return nil
}

type AuditorTreeHeadTBS struct {
	Config    PublicConfig
	Timestamp uint64
	TreeSize  uint64
	Root      []byte
}

func (tbs *AuditorTreeHeadTBS) Marshal(buf *bytes.Buffer) error {
	if err := tbs.Config.Marshal(buf); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, tbs.Timestamp); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, tbs.TreeSize); err != nil {
		return err
	} else if _, err := buf.Write(tbs.Root); err != nil {
		return err
	}
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
		return buf.WriteByte(byte(SameHead))
	}

	if err := buf.WriteByte(byte(UpdatedHead)); err != nil {
		return err
	} else if err := fth.TreeHead.Marshal(buf); err != nil {
		return err
	} else if fth.AuditorTreeHead != nil {
		if err := fth.AuditorTreeHead.Marshal(buf); err != nil {
			return err
		}
	}
	return nil
}
