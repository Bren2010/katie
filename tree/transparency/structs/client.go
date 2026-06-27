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

func NewClientState(cs suites.CipherSuite, buf *bytes.Buffer) (*ClientState, error) {
	treeHead, err := NewTreeHead(buf)
	if err != nil {
		return nil, err
	}
	fullSubtrees, err := readByteSlice[uint8](buf, cs.HashSize())
	if err != nil {
		return nil, err
	}

	entrySlice, err := readFuncSlice[uint8](buf, func(buf *bytes.Buffer) (*IndexedLogEntry, error) {
		return NewIndexedLogEntry(cs, buf)
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
		TreeHead:     *treeHead,
		FullSubtrees: fullSubtrees,
		LogEntries:   logEntries,
	}, nil
}

func (cs *ClientState) Marshal(buf *bytes.Buffer) error {
	if err := cs.TreeHead.Marshal(buf); err != nil {
		return err
	} else if err := writeByteSlice[uint8](buf, cs.FullSubtrees, "full subtrees"); err != nil {
		return err
	}

	entrySlice := make([]IndexedLogEntry, 0, len(cs.LogEntries))
	for pos, entry := range cs.LogEntries {
		entrySlice = append(entrySlice, IndexedLogEntry{Pos: pos, LogEntry: entry})
	}
	return writeMarshalSlice[uint8](buf, entrySlice, "log entry")
}
