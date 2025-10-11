package db

import (
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
)

const leveldbTreeHeadKey = "tree-head"

func dup(in []byte) []byte {
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
		}
		b.Put([]byte(key), value)
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

func (ldb *ldbTransparencyStore) SetTreeHead(raw []byte) error {
	ldb.conn.Put(leveldbTreeHeadKey, raw)
	return nil
}

func (ldb *ldbTransparencyStore) SetAuditorTreeHead(raw []byte) error {
	ldb.conn.Put("auditor-tree-head", raw)
	return nil
}

func (ldb *ldbTransparencyStore) GetLabelInfo(label []byte) ([]byte, error) {
	raw, err := ldb.conn.Get("i" + fmt.Sprintf("%x", label))
	if err == leveldb.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return raw, nil
}

func (ldb *ldbTransparencyStore) SetLabelInfo(label, info []byte) error {
	ldb.conn.Put("i"+fmt.Sprintf("%x", label), info)
	return nil
}

func (ldb *ldbTransparencyStore) Get(key uint64) ([]byte, error) {
	return ldb.conn.Get("t" + fmt.Sprint(key))
}

func (ldb *ldbTransparencyStore) Put(key uint64, data []byte) error {
	ldb.conn.Put("t"+fmt.Sprint(key), data)
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

func (ls *ldbLogStore) BatchPut(data map[uint64][]byte) error {
	for key, value := range data {
		ls.conn.Put("l"+fmt.Sprint(key), value)
	}
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

func (ps *ldbPrefixStore) BatchPut(data map[string][]byte) error {
	for key, value := range data {
		ps.conn.Put("p"+key, value)
	}
	return nil
}
