package db

import (
	"context"
	"errors"
	"fmt"
)

const (
	treeHeadKey        = "tree-head"
	auditorTreeHeadKey = "auditor-tree-head"

	indexPrefix        = "i"
	versionPrefix      = "v"
	transparencyPrefix = "t"
	logTreePrefix      = "l"
	prefixTreePrefix   = "p"
)

// TransparencyStore is used by a Transparency Tree to communicate with its
// database. It handles batching and transactional-ish writes.
type TransparencyStore struct {
	ctx   context.Context
	kv    KeyValueStore
	batch map[string][]byte
}

// NewTransparencyStore returns a new TransparencyStore. `ctx` is the parent
// context for all database operations, `kv` is the underlying KeyValueStore,
// and `readOnly` indicates whether the TransparencyStore should reject writes
// or not.
func NewTransparencyStore(ctx context.Context, kv KeyValueStore, readOnly bool) TransparencyStore {
	var batch map[string][]byte
	if !readOnly {
		batch = make(map[string][]byte)
	}
	return TransparencyStore{ctx, kv, batch}
}

func (ts TransparencyStore) batchGet[K any](keys []K, convert func(key K) string) ([][]byte, error) {
	out := make([][]byte, len(keys))

	indices := make([]int, 0, len(keys))
	converted := make([]string, 0, len(keys))
	for i, key := range keys {
		conv := convert(key)
		if value, ok := ts.batch[conv]; ok { // Provide value directly from batch.
			if value != nil {
				out[i] = dup(value)
			} // Value is deleted; leave out of results slice.
		} else { // Queue up key to be fetched from the database.
			indices = append(indices, i)
			converted = append(converted, conv)
		}
	}

	results, err := ts.kv.BatchGet(ts.ctx, converted)
	if err != nil {
		return nil, err
	}
	for i, value := range results {
		out[indices[i]] = value
	}

	return out, nil
}

func (ts TransparencyStore) put(key string, value []byte) {
	if ts.batch == nil {
		panic("connection is read-only")
	} else if value == nil {
		panic("unable to store nil value")
	}
	ts.batch[key] = dup(value)
}

func (ts TransparencyStore) delete(key string) {
	if ts.batch == nil {
		panic("connection is read-only")
	}
	ts.batch[key] = nil
}

func noop(key string) string { return key }

func (ts TransparencyStore) GetTreeHead() ([]byte, []byte, error) {
	results, err := ts.batchGet([]string{treeHeadKey, auditorTreeHeadKey}, noop)
	if err != nil {
		return nil, nil, err
	}
	return results[0], results[1], nil
}
func (ts TransparencyStore) PutTreeHead(raw []byte) {
	ts.put(treeHeadKey, raw)
}
func (ts TransparencyStore) PutAuditorTreeHead(raw []byte) {
	ts.put(auditorTreeHeadKey, raw)
}

func indexK(key []byte) string { return indexPrefix + fmt.Sprintf("%x", key) }

func (ts TransparencyStore) BatchGetIndex(labels [][]byte) ([][]byte, error) {
	return ts.batchGet(labels, indexK)
}
func (ts TransparencyStore) PutIndex(label, index []byte) {
	ts.put(indexK(label), index)
}
func (ts TransparencyStore) DeleteIndex(label []byte) {
	ts.delete(indexK(label))
}

func versionK(label []byte, ver uint32) string {
	return versionPrefix + fmt.Sprintf("%x:%v", label, ver)
}

func (ts TransparencyStore) GetVersion(label []byte, ver uint32) ([]byte, error) {
	res, err := ts.batchGet([]string{versionK(label, ver)}, noop)
	if err != nil {
		return nil, err
	}
	return res[0], nil
}
func (ts TransparencyStore) PutVersion(label []byte, ver uint32, data []byte) {
	ts.put(versionK(label, ver), data)
}
func (ts TransparencyStore) DeleteVersion(label []byte, ver uint32) {
	ts.delete(versionK(label, ver))
}

func transparencyK(key uint64) string { return transparencyPrefix + fmt.Sprint(key) }

func (ts TransparencyStore) BatchGet(keys []uint64) ([][]byte, error) {
	return ts.batchGet(keys, transparencyK)
}
func (ts TransparencyStore) Put(key uint64, data []byte) {
	ts.put(transparencyK(key), data)
}
func (ts TransparencyStore) Delete(key uint64) {
	ts.delete(transparencyK(key))
}

func (ts TransparencyStore) LogStore() LogStore       { return LogStore{store: ts} }
func (ts TransparencyStore) PrefixStore() PrefixStore { return PrefixStore{store: ts} }

func (ts TransparencyStore) Commit() error {
	if ts.batch == nil {
		panic("connection is read-only")
	}

	var treeHead []byte
	batch := make(map[string][]byte)
	for key, value := range ts.batch {
		if key == treeHeadKey {
			treeHead = value
		} else {
			batch[key] = value
		}
	}

	if treeHead == nil {
		temp, _, err := ts.GetTreeHead()
		if err != nil {
			return err
		} else if temp == nil {
			return errors.New("no tree head currently or previously written")
		}
		treeHead = temp
	}

	return ts.kv.Commit(ts.ctx, batch, treeHead)
}

// LogStore is used by a Log Tree to communicate with its database.
type LogStore struct {
	store TransparencyStore
}

func logK(key uint64) string { return logTreePrefix + fmt.Sprint(key) }

func (ls LogStore) BatchGet(keys []uint64) ([][]byte, error) {
	return ls.store.batchGet(keys, logK)
}
func (ls LogStore) Put(key uint64, value []byte) {
	ls.store.put(logK(key), value)
}
func (ls LogStore) Delete(key uint64) {
	ls.store.delete(logK(key))
}

// PrefixStore is used by a Prefix Tree to communicate with its database.
type PrefixStore struct {
	store TransparencyStore
}

func prefixK(key string) string { return prefixTreePrefix + key }

func (ps PrefixStore) BatchGet(keys []string) ([][]byte, error) {
	return ps.store.batchGet(keys, prefixK)
}
func (ps PrefixStore) Put(key string, value []byte) {
	ps.store.put(prefixK(key), value)
}
func (ps PrefixStore) Delete(key string) {
	ps.store.delete(prefixK(key))
}
