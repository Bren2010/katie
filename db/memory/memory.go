// Package memory provides in-memory implementations of the database interfaces.
package memory

import (
	"errors"
	"fmt"

	"github.com/Bren2010/katie/db"
)

func dup(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

type TransparencyStore struct {
	TreeHead, Auditor []byte
	Indices           map[string][]byte
	Versions          map[string][]byte
	LogEntries        map[uint64][]byte

	logStore    *LogStore
	prefixStore *PrefixStore

	ReadOnly bool
}

func NewTransparencyStore() *TransparencyStore {
	return &TransparencyStore{
		Indices:    make(map[string][]byte),
		Versions:   make(map[string][]byte),
		LogEntries: make(map[uint64][]byte),

		logStore:    NewLogStore(),
		prefixStore: NewPrefixStore(),

		ReadOnly: false,
	}
}

func (ts *TransparencyStore) Clone() db.TransparencyStore {
	return &TransparencyStore{
		TreeHead:   ts.TreeHead,
		Auditor:    ts.Auditor,
		Indices:    ts.Indices,
		Versions:   ts.Versions,
		LogEntries: ts.LogEntries,

		logStore:    ts.logStore,
		prefixStore: ts.prefixStore,

		ReadOnly: false,
	}
}

func (ts *TransparencyStore) GetTreeHead() ([]byte, []byte, error) {
	return dup(ts.TreeHead), dup(ts.Auditor), nil
}

func (ts *TransparencyStore) PutTreeHead(raw []byte) error {
	ts.TreeHead = dup(raw)
	return nil
}

func (ts *TransparencyStore) PutAuditorTreeHead(raw []byte) error {
	ts.Auditor = dup(raw)
	return nil
}

func (ts *TransparencyStore) BatchGetIndex(labels [][]byte) ([][]byte, error) {
	out := make([][]byte, len(labels))
	for i, label := range labels {
		out[i] = dup(ts.Indices[fmt.Sprintf("%x", label)])
	}
	return out, nil
}

func (ts *TransparencyStore) PutIndex(label []byte, data []byte) error {
	if data == nil {
		return errors.New("unable to store nil index")
	}
	ts.Indices[fmt.Sprintf("%x", label)] = dup(data)
	return nil
}

func (ts *TransparencyStore) DeleteIndex(label []byte) error {
	delete(ts.Indices, fmt.Sprintf("%x", label))
	return nil
}

func (ts *TransparencyStore) GetVersion(label []byte, ver uint32) ([]byte, error) {
	return dup(ts.Versions[fmt.Sprintf("%x:%v", label, ver)]), nil
}

func (ts *TransparencyStore) PutVersion(label []byte, ver uint32, data []byte) error {
	if data == nil {
		return errors.New("unable to store nil version")
	}
	ts.Versions[fmt.Sprintf("%x:%v", label, ver)] = dup(data)
	return nil
}

func (ts *TransparencyStore) DeleteVersion(label []byte, ver uint32) error {
	delete(ts.Versions, fmt.Sprintf("%x:%v", label, ver))
	return nil
}

func (ts *TransparencyStore) BatchGet(keys []uint64) (map[uint64][]byte, error) {
	out := make(map[uint64][]byte)
	for _, key := range keys {
		if val, ok := ts.LogEntries[key]; ok {
			out[key] = dup(val)
		}
	}
	return out, nil
}

func (ts *TransparencyStore) Put(key uint64, data []byte) error {
	if data == nil {
		return errors.New("unable to store nil log entry")
	}
	ts.LogEntries[key] = dup(data)
	return nil
}

func (ts *TransparencyStore) Delete(key uint64) error {
	delete(ts.LogEntries, key)
	return nil
}

func (ts *TransparencyStore) LogStore() db.LogStore       { return ts.logStore }
func (ts *TransparencyStore) PrefixStore() db.PrefixStore { return ts.prefixStore }
func (ts *TransparencyStore) Commit() error               { return nil }

type LogStore struct {
	Data map[uint64][]byte
}

func NewLogStore() *LogStore {
	return &LogStore{Data: make(map[uint64][]byte)}
}

func (ls *LogStore) BatchGet(keys []uint64) (map[uint64][]byte, error) {
	out := make(map[uint64][]byte)

	for _, key := range keys {
		if d, ok := ls.Data[key]; ok {
			out[key] = dup(d)
		}
	}

	return out, nil
}

func (ls *LogStore) Put(key uint64, value []byte) error {
	if value == nil {
		return errors.New("unable to store nil value")
	}
	ls.Data[key] = dup(value)
	return nil
}

func (ls *LogStore) Delete(key uint64) error {
	delete(ls.Data, key)
	return nil
}

type PrefixStore struct {
	Data    map[string][]byte
	Lookups [][]string
}

func NewPrefixStore() *PrefixStore {
	return &PrefixStore{Data: make(map[string][]byte)}
}

func (ps *PrefixStore) BatchGet(keys []string) (map[string][]byte, error) {
	ps.Lookups = append(ps.Lookups, keys)

	out := make(map[string][]byte)
	for _, key := range keys {
		if val, ok := ps.Data[key]; ok {
			out[key] = dup(val)
		}
	}

	return out, nil
}

func (ps *PrefixStore) Put(key string, value []byte) error {
	if value == nil {
		return errors.New("unable to store nil value")
	}
	ps.Data[key] = dup(value)
	return nil
}

func (ps *PrefixStore) Delete(key string) error {
	delete(ps.Data, key)
	return nil
}
