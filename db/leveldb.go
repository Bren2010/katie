package db

import (
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
)

const leveldbTreeHeadKey = "tree-head"

func dup(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// ldbConn is a wrapper around a base LevelDB database that handles batching
// writes between commits transparently.
type ldbConn struct {
	conn     *leveldb.DB
	readonly bool
	batch    map[string][]byte
}

func newLDBConn(conn *leveldb.DB, readonly bool) *ldbConn {
	return &ldbConn{conn, readonly, make(map[string][]byte)}
}

func (c *ldbConn) Get(key string) ([]byte, error) {
	if value, ok := c.batch[key]; ok {
		if value == nil {
			return nil, leveldb.ErrNotFound
		}
		return dup(value), nil
	}
	return c.conn.Get([]byte(key), nil)
}

func (c *ldbConn) Put(key string, value []byte) {
	if c.readonly {
		panic("connection is readonly")
	}
	c.batch[key] = dup(value)
}

func (c *ldbConn) Commit() error {
	if c.readonly {
		panic("connection is readonly")
	}

	b := new(leveldb.Batch)
	for key, value := range c.batch {
		if key == leveldbTreeHeadKey {
			continue
		} else if value == nil {
			b.Delete([]byte(key))
		} else {
			b.Put([]byte(key), value)
		}
	}
	if err := c.conn.Write(b, nil); err != nil {
		return err
	}
	if value, ok := c.batch[leveldbTreeHeadKey]; ok {
		if err := c.conn.Put([]byte(leveldbTreeHeadKey), value, nil); err != nil {
			return err
		}
	}

	c.batch = make(map[string][]byte)
	return nil
}

// ldbTransparencyStore implements the TransparencyStore interface over a
// LevelDB database.
type ldbTransparencyStore struct {
	conn *ldbConn
}

func NewLDBTransparencyStore(file string) (TransparencyStore, error) {
	conn, err := leveldb.OpenFile(file, nil)
	if errors.IsCorrupted(err) {
		conn, err = leveldb.RecoverFile(file, nil)
	}
	if err != nil {
		return nil, err
	}
	return &ldbTransparencyStore{newLDBConn(conn, false)}, nil
}

func (ldb *ldbTransparencyStore) Clone() TransparencyStore {
	return &ldbTransparencyStore{newLDBConn(ldb.conn.conn, true)}
}

func (ldb *ldbTransparencyStore) GetTreeHead() ([]byte, []byte, error) {
	treeHead, err := ldb.conn.Get(leveldbTreeHeadKey)
	if err == leveldb.ErrNotFound {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}
	auditor, err := ldb.conn.Get("auditor-tree-head")
	if err != leveldb.ErrNotFound && err != nil {
		return nil, nil, err
	}
	return treeHead, auditor, nil
}

func (ldb *ldbTransparencyStore) PutTreeHead(raw []byte) error {
	ldb.conn.Put(leveldbTreeHeadKey, raw)
	return nil
}

func (ldb *ldbTransparencyStore) PutAuditorTreeHead(raw []byte) error {
	ldb.conn.Put("auditor-tree-head", raw)
	return nil
}

func (ldb *ldbTransparencyStore) BatchGetIndex(labels [][]byte) ([][]byte, error) {
	out := make([][]byte, len(labels))

	for i, label := range labels {
		raw, err := ldb.conn.Get("i" + fmt.Sprintf("%x", label))
		if err == leveldb.ErrNotFound {
			continue
		} else if err != nil {
			return nil, err
		}
		out[i] = raw
	}

	return out, nil
}

func (ldb *ldbTransparencyStore) PutIndex(label, index []byte) error {
	if index == nil {
		return errors.New("leveldb: can not store nil value")
	}
	ldb.conn.Put("i"+fmt.Sprintf("%x", label), index)
	return nil
}

func (ldb *ldbTransparencyStore) DeleteIndex(label []byte) error {
	ldb.conn.Put("i"+fmt.Sprintf("%x", label), nil)
	return nil
}

func (ldb *ldbTransparencyStore) GetVersion(label []byte, ver uint32) ([]byte, error) {
	raw, err := ldb.conn.Get("v" + fmt.Sprintf("%x:%x", label, ver))
	if err == leveldb.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return raw, nil
}

func (ldb *ldbTransparencyStore) PutVersion(label []byte, ver uint32, data []byte) error {
	if data == nil {
		return errors.New("leveldb: can not store nil value")
	}
	ldb.conn.Put("v"+fmt.Sprintf("%x:%x", label, ver), data)
	return nil
}

func (ldb *ldbTransparencyStore) DeleteVersion(label []byte, ver uint32) error {
	ldb.conn.Put("v"+fmt.Sprintf("%x:%x", label, ver), nil)
	return nil
}

func (ldb *ldbTransparencyStore) BatchGet(keys []uint64) (map[uint64][]byte, error) {
	out := make(map[uint64][]byte)

	for _, key := range keys {
		value, err := ldb.conn.Get("t" + fmt.Sprint(key))
		if err == leveldb.ErrNotFound {
			continue
		} else if err != nil {
			return nil, err
		}
		out[key] = value
	}

	return out, nil
}

func (ldb *ldbTransparencyStore) Put(key uint64, data []byte) error {
	if data == nil {
		return errors.New("leveldb: can not store nil value")
	}
	ldb.conn.Put("t"+fmt.Sprint(key), data)
	return nil
}

func (ldb *ldbTransparencyStore) Delete(key uint64) error {
	ldb.conn.Put("t"+fmt.Sprint(key), nil)
	return nil
}

func (ldb *ldbTransparencyStore) LogStore() LogStore {
	return &ldbLogStore{ldb.conn}
}

func (ldb *ldbTransparencyStore) PrefixStore() PrefixStore {
	return &ldbPrefixStore{ldb.conn}
}

func (ldb *ldbTransparencyStore) Commit() error {
	return ldb.conn.Commit()
}

// ldbLogStore implements the LogStore interface over LevelDB.
type ldbLogStore struct {
	conn *ldbConn
}

func (ls *ldbLogStore) BatchGet(keys []uint64) (map[uint64][]byte, error) {
	out := make(map[uint64][]byte)

	for _, key := range keys {
		value, err := ls.conn.Get("l" + fmt.Sprint(key))
		if err == leveldb.ErrNotFound {
			continue
		} else if err != nil {
			return nil, err
		}
		out[key] = value
	}

	return out, nil
}

func (ls *ldbLogStore) Put(key uint64, value []byte) error {
	if value == nil {
		return errors.New("leveldb: can not store nil value")
	}
	ls.conn.Put("l"+fmt.Sprint(key), value)
	return nil
}

func (ls *ldbLogStore) Delete(key uint64) error {
	ls.conn.Put("l"+fmt.Sprint(key), nil)
	return nil
}

// ldbPrefixStore implements the PrefixStore interface over LevelDB.
type ldbPrefixStore struct {
	conn *ldbConn
}

func (ps *ldbPrefixStore) BatchGet(keys []string) (map[string][]byte, error) {
	out := make(map[string][]byte)

	for _, key := range keys {
		value, err := ps.conn.Get("p" + key)
		if err == leveldb.ErrNotFound {
			continue
		} else if err != nil {
			return nil, err
		}
		out[key] = value
	}

	return out, nil
}

func (ps *ldbPrefixStore) Put(key string, value []byte) error {
	if value == nil {
		return errors.New("leveldb: can not store nil value")
	}
	ps.conn.Put("p"+key, value)
	return nil
}

func (ps *ldbPrefixStore) Delete(key string) error {
	ps.conn.Put("p"+key, nil)
	return nil
}
