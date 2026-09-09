package db

import (
	"context"
	"encoding/binary"

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

type ldbManagedLog struct {
	conn *leveldb.DB
}

// NewLDBManagedLogStore returns an implementation of the ManagedLogStore
// interface that's backed by a LevelDB file.
func NewLDBManagedLogStore(file string) (ManagedLogStore, error) {
	conn, err := leveldb.OpenFile(file, nil)
	if errors.IsCorrupted(err) {
		conn, err = leveldb.RecoverFile(file, nil)
	}
	if err != nil {
		return nil, err
	}
	return ldbManagedLog{conn: conn}, nil
}

func (ml ldbManagedLog) IncrementGreatestVersion(ctx context.Context, label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	} else if int64(count) > maxVersion {
		return 0, errors.New("count is greater than the maximum version")
	} else if len(label) == 0 {
		return 0, errors.New("label must not be empty")
	}

	prev := int64(-1)
	raw, err := ml.conn.Get(label, nil)
	if err == nil {
		if len(raw) != 4 {
			return 0, errors.New("stored version is malformed")
		}
		prev = int64(binary.BigEndian.Uint32(raw))
	} else if err != leveldb.ErrNotFound {
		return 0, err
	}

	ver := prev + int64(count)
	if ver > maxVersion {
		return 0, errors.New("increasing label version would exceed maximum")
	}
	next := make([]byte, 4)
	binary.BigEndian.PutUint32(next, uint32(ver))

	// Losing a counter would let the Service Operator sign two different values
	// under the same version, so the write is synced before returning.
	if err := ml.conn.Put(label, next, &opt.WriteOptions{Sync: true}); err != nil {
		return 0, err
	}

	return int(prev), nil
}
