package structs

import (
	"bytes"
	"errors"

	"github.com/Bren2010/katie/crypto/suites"
)

type IndexedLogEntry struct {
	Pos uint64
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
	return &IndexedLogEntry{Pos: pos, LogEntry: *entry}, nil
}

func (ile *IndexedLogEntry) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, ile.Pos)
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
		if _, ok := logEntries[entry.Pos]; ok {
			return nil, errors.New("same log entry present multiple times")
		}
		logEntries[entry.Pos] = entry.LogEntry
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
		entrySlice = append(entrySlice, IndexedLogEntry{Pos: pos, LogEntry: entry})
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

type ClientLabelState struct {
	Contact []MonitorMapEntry
	Owner   *LabelOwnerState
}

func NewClientLabelState(buf *bytes.Buffer) (*ClientLabelState, error) {
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

	return &ClientLabelState{Contact: contact, Owner: owner}, nil
}

func (cls *ClientLabelState) Marshal(buf *bytes.Buffer) error {
	if err := writeMarshalSlice[uint32](buf, cls.Contact, "contact state"); err != nil {
		return err
	}
	if writeOptional(buf, cls.Owner != nil) {
		return cls.Owner.Marshal(buf)
	}
	return nil
}
