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

type LabelContactState struct {
	Pos uint64
	Ver uint32
}

func NewLabelContactState(buf *bytes.Buffer) (*LabelContactState, error) {
	pos, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	ver, err := readNumeric[uint32](buf)
	if err != nil {
		return nil, err
	}
	return &LabelContactState{Pos: pos, Ver: ver}, nil
}

func (lcs *LabelContactState) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, lcs.Pos)
	writeNumeric(buf, lcs.Ver)
	return nil
}

type ClientLabelState struct {
	Contact map[uint64]uint32
	Owner   *LabelOwnerState
}

func NewClientLabelState(buf *bytes.Buffer) (*ClientLabelState, error) {
	ptrSlice, err := readFuncSlice[uint32](buf, NewLabelContactState)
	if err != nil {
		return nil, err
	}
	contact := make(map[uint64]uint32)
	for _, pair := range ptrSlice {
		if _, ok := contact[pair.Pos]; ok {
			return nil, errors.New("same log entry present multiple times")
		}
		contact[pair.Pos] = pair.Ver
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
	ptrSlice := make([]LabelContactState, 0, len(cls.Contact))
	for pos, ver := range cls.Contact {
		ptrSlice = append(ptrSlice, LabelContactState{Pos: pos, Ver: ver})
	}
	if err := writeMarshalSlice[uint32](buf, ptrSlice, "contact state"); err != nil {
		return err
	}

	if writeOptional(buf, cls.Owner != nil) {
		return cls.Owner.Marshal(buf)
	}
	return nil
}
