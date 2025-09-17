package structs

import (
	"bytes"
	"encoding/binary"
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
	return &TreeHead{TreeSize: treeSize, Signature: signature}, nil
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
	return &AuditorTreeHead{Timestamp: timestamp, TreeSize: treeSize, Signature: signature}, nil
}

func (ath *AuditorTreeHead) Marshal(buf *bytes.Buffer) error {
	if err := binary.Write(buf, binary.BigEndian, ath.Timestamp); err != nil {
		return err
	} else if err := binary.Write(buf, binary.BigEndian, ath.TreeSize); err != nil {
		return err
	} else if err := writeU16Bytes(buf, ath.Signature, "auditor tree head signature"); err != nil {
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
