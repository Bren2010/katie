package db

import (
	"context"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type ldbKeyValue struct {
	conn *leveldb.DB
}

// NewLDBKeyValueStore returns an implementation of the KeyValueStore interface
// that's backed by a LevelDB file.
func NewLDBKeyValueStore(file string) (KeyValueStore, error) {
	conn, err := leveldb.OpenFile(file, nil)
	if errors.IsCorrupted(err) {
		conn, err = leveldb.RecoverFile(file, nil)
	}
	if err != nil {
		return nil, err
	}
	return ldbKeyValue{conn: conn}, nil
}

func (kv ldbKeyValue) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	out := make([][]byte, len(keys))

	for i, key := range keys {
		res, err := kv.conn.Get([]byte(key), nil)
		if err == leveldb.ErrNotFound {
			out[i] = nil
		} else if err != nil {
			return nil, err
		} else {
			out[i] = res
		}
	}

	return out, nil
}

func (kv ldbKeyValue) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	b := new(leveldb.Batch)
	for key, value := range batch {
		if value == nil {
			b.Delete([]byte(key))
		} else {
			b.Put([]byte(key), value)
		}
	}
	b.Put([]byte(treeHeadKey), treeHead)

	return kv.conn.Write(b, &opt.WriteOptions{Sync: true})
}
