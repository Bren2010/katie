package structs

import (
	"bytes"
	"errors"
	"io"

	"github.com/Bren2010/katie/crypto/suites"
)

type IndexedLogEntry struct {
	Position uint64
	LogEntry
}

func NewIndexedLogEntry(cs suites.CipherSuite, buf *bytes.Buffer) (*IndexedLogEntry, error) {
	pos, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	entry, err := NewLogEntry(cs, buf)
	if err != nil {
		return nil, err
	}
	return &IndexedLogEntry{Position: pos, LogEntry: *entry}, nil
}

func (ile *IndexedLogEntry) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, ile.Position)
	return ile.LogEntry.Marshal(buf)
}

type ClientState struct {
	TreeHead        TreeHead
	AuditorTreeHead *AuditorTreeHead
	FullSubtrees    [][]byte
	LogEntries      map[uint64]LogEntry
}

func NewClientState(config *PublicConfig, buf *bytes.Buffer) (*ClientState, error) {
	treeHead, err := NewTreeHead(buf)
	if err != nil {
		return nil, err
	}
	var auditorTreeHead *AuditorTreeHead
	if config.Mode == ThirdPartyAuditing {
		auditorTreeHead, err = NewAuditorTreeHead(buf)
		if err != nil {
			return nil, err
		}
	}
	fullSubtrees, err := readByteSlice[uint8](buf, config.Suite.HashSize())
	if err != nil {
		return nil, err
	}

	entrySlice, err := readFuncSlice[uint8](buf, func(buf *bytes.Buffer) (*IndexedLogEntry, error) {
		return NewIndexedLogEntry(config.Suite, buf)
	})
	if err != nil {
		return nil, err
	}
	logEntries := make(map[uint64]LogEntry)
	for _, entry := range entrySlice {
		if _, ok := logEntries[entry.Position]; ok {
			return nil, errors.New("same log entry present multiple times")
		}
		logEntries[entry.Position] = entry.LogEntry
	}

	return &ClientState{
		TreeHead:        *treeHead,
		AuditorTreeHead: auditorTreeHead,
		FullSubtrees:    fullSubtrees,
		LogEntries:      logEntries,
	}, nil
}

func (cs *ClientState) Marshal(buf *bytes.Buffer) error {
	if err := cs.TreeHead.Marshal(buf); err != nil {
		return err
	}
	if cs.AuditorTreeHead != nil {
		if err := cs.AuditorTreeHead.Marshal(buf); err != nil {
			return err
		}
	}
	if err := writeByteSlice[uint8](buf, cs.FullSubtrees, "full subtrees"); err != nil {
		return err
	}

	entrySlice := make([]IndexedLogEntry, 0, len(cs.LogEntries))
	for pos, entry := range cs.LogEntries {
		entrySlice = append(entrySlice, IndexedLogEntry{Position: pos, LogEntry: entry})
	}
	return writeMarshalSlice[uint8](buf, entrySlice, "log entry")
}

type LabelOwnerState struct {
	Starting      uint64
	VerAtStarting int
	UpcomingVers  []uint64
}

func NewLabelOwnerState(buf *bytes.Buffer) (*LabelOwnerState, error) {
	starting, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	verAtStarting, err := readNumeric[int](buf)
	if err != nil {
		return nil, err
	}
	upcomingVers, err := readNumericSlice[uint32, uint64](buf)
	if err != nil {
		return nil, err
	}
	return &LabelOwnerState{
		Starting:      starting,
		VerAtStarting: verAtStarting,
		UpcomingVers:  upcomingVers,
	}, nil
}

func (los *LabelOwnerState) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, los.Starting)
	writeNumeric(buf, los.VerAtStarting)
	return writeNumericSlice[uint32](buf, los.UpcomingVers, "upcoming versions")
}

type RetainedVersion struct {
	Version    uint32
	VrfOutput  []byte
	Commitment []byte
}

func NewRetainedVersion(cs suites.CipherSuite, buf *bytes.Buffer) (*RetainedVersion, error) {
	version, err := readNumeric[uint32](buf)
	if err != nil {
		return nil, err
	}

	vrfOutput := make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, vrfOutput); err != nil {
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
	return &RetainedVersion{
		Version:    version,
		VrfOutput:  vrfOutput,
		Commitment: commitment,
	}, nil
}

func (rv *RetainedVersion) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, rv.Version)
	buf.Write(rv.VrfOutput)
	if writeOptional(buf, rv.Commitment != nil) {
		buf.Write(rv.Commitment)
	}
	return nil
}

type ClientLabelState struct {
	Contact  []MonitorMapEntry
	Owner    *LabelOwnerState
	Versions []RetainedVersion
}

func NewClientLabelState(cs suites.CipherSuite, buf *bytes.Buffer) (*ClientLabelState, error) {
	contact, err := readFuncSlice[uint32](buf, NewMonitorMapEntry)
	if err != nil {
		return nil, err
	}

	var owner *LabelOwnerState
	if present, err := readOptional(buf); err != nil {
		return nil, err
	} else if present {
		owner, err = NewLabelOwnerState(buf)
		if err != nil {
			return nil, err
		}
	}

	versions, err := readFuncSlice[uint32](buf, func(buf *bytes.Buffer) (*RetainedVersion, error) {
		return NewRetainedVersion(cs, buf)
	})

	return &ClientLabelState{Contact: contact, Owner: owner, Versions: versions}, nil
}

func (cls *ClientLabelState) Marshal(buf *bytes.Buffer) error {
	if err := writeMarshalSlice[uint32](buf, cls.Contact, "contact state"); err != nil {
		return err
	}
	if writeOptional(buf, cls.Owner != nil) {
		return cls.Owner.Marshal(buf)
	}
	return writeMarshalSlice[uint32](buf, cls.Versions, "retained versions")
}
