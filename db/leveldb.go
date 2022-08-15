package db

import (
	"encoding/json"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
)

func dup(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// ldbConn is a wrapper around a base LevelDB database that handles batching
// writes between commits transparently.
type ldbConn struct {
	conn  *leveldb.DB
	batch map[string][]byte
}

// TODO: Consider adding LRU cache.

func newLDBConn(conn *leveldb.DB) *ldbConn {
	return &ldbConn{conn, make(map[string][]byte)}
}

func (c *ldbConn) Get(key string) ([]byte, error) {
	if value, ok := c.batch[key]; ok {
		return dup(value), nil
	}
	return c.conn.Get([]byte(key), nil)
}

func (c *ldbConn) Put(key string, value []byte) {
	c.batch[key] = dup(value)
}

func (c *ldbConn) Commit() error {
	var b *leveldb.Batch
	for key, value := range c.batch {
		if key == "root" {
			continue
		}
		b.Put([]byte(key), value)
	}
	if err := c.conn.Write(b, nil); err != nil {
		return err
	}
	if value, ok := c.batch["root"]; ok {
		if err := c.conn.Put([]byte("root"), value, nil); err != nil {
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
	return &ldbTransparencyStore{newLDBConn(conn)}, nil
}

func (ldb *ldbTransparencyStore) GetRoot() (*TransparencyTreeRoot, error) {
	latest, err := ldb.conn.Get("root")
	if err == leveldb.ErrNotFound {
		return &TransparencyTreeRoot{}, nil
	} else if err != nil {
		return nil, err
	}
	out := &TransparencyTreeRoot{}
	if err := json.Unmarshal(latest, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (ldb *ldbTransparencyStore) SetRoot(root *TransparencyTreeRoot) error {
	raw, err := json.Marshal(root)
	if err != nil {
		return err
	}
	ldb.conn.Put("root", raw)
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

func (ls *ldbLogStore) BatchGet(keys []int) (map[int][]byte, error) {
	out := make(map[int][]byte)

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

func (ls *ldbLogStore) BatchPut(data map[int][]byte) error {
	for key, value := range data {
		ls.conn.Put("l"+fmt.Sprint(key), value)
	}
	return nil
}

// ldbPrefixStore implements the PrefixStore interface over LevelDB.
type ldbPrefixStore struct {
	conn *ldbConn
}

func (ps *ldbPrefixStore) Get(key uint64) ([]byte, error) {
	return ps.conn.Get("p" + fmt.Sprint(key))
}

func (ps *ldbPrefixStore) Put(key uint64, data []byte) error {
	ps.conn.Put("p"+fmt.Sprint(key), data)
	return nil
}
