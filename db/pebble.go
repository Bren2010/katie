package db

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/bloom"
)

const (
	// pebbleMaxOpenFiles bounds the number of sstables Pebble keeps open. The
	// default of 1000 is far fewer than a large prefix tree has, which causes
	// tables to be repeatedly re-opened (and their index blocks re-read) on the
	// read path.
	pebbleMaxOpenFiles = 16384

	// pebbleReadWorkers is the maximum number of concurrent point lookups that
	// BatchGet issues. Lookups are dominated by random disk reads, so issuing
	// them concurrently lets the disk work on many at once.
	pebbleReadWorkers = 32
)

// openPebble opens the Pebble database at `file`, creating it if it doesn't
// exist. `cacheSize` is the size of the block cache in bytes, or zero to use
// Pebble's default.
func openPebble(file string, cacheSize int64) (*pebble.DB, error) {
	opts := &pebble.Options{MaxOpenFiles: pebbleMaxOpenFiles}
	// Bloom filters let point lookups skip sstables that don't contain the key.
	// The policy set on L0 is inherited by all other levels.
	opts.Levels[0].FilterPolicy = bloom.FilterPolicy(10)
	if cacheSize > 0 {
		cache := pebble.NewCache(cacheSize)
		defer cache.Unref()
		opts.Cache = cache
	}
	return pebble.Open(file, opts)
}

// getPebble returns a copy of the value of `key`, or nil if it doesn't exist.
func getPebble(conn *pebble.DB, key []byte) ([]byte, error) {
	value, closer, err := conn.Get(key)
	if err == pebble.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer closer.Close()
	return dup(value), nil
}

type pdbKeyValue struct {
	conn *pebble.DB
}

// NewPDBKeyValueStore returns an implementation of the KeyValueStore interface
// that's backed by a Pebble database. `cacheSize` is the size of the block
// cache in bytes, or zero to use Pebble's default. It should generally be set
// as large as available memory allows.
func NewPDBKeyValueStore(file string, cacheSize int64) (KeyValueStore, error) {
	conn, err := openPebble(file, cacheSize)
	if err != nil {
		return nil, err
	}
	return pdbKeyValue{conn: conn}, nil
}

func (kv pdbKeyValue) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	out := make([][]byte, len(keys))

	var (
		next     atomic.Int64
		once     sync.Once
		firstErr error
		wg       sync.WaitGroup
	)
	for range min(len(keys), pebbleReadWorkers) {
		wg.Go(func() {
			for {
				i := int(next.Add(1) - 1)
				if i >= len(keys) {
					return
				} else if err := ctx.Err(); err != nil {
					once.Do(func() { firstErr = err })
					return
				}
				value, err := getPebble(kv.conn, []byte(keys[i]))
				if err != nil {
					once.Do(func() { firstErr = err })
					return
				}
				out[i] = value
			}
		})
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func (kv pdbKeyValue) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	b := kv.conn.NewBatch()
	defer b.Close()
	for key, value := range batch {
		var err error
		if value == nil {
			err = b.Delete([]byte(key), nil)
		} else {
			err = b.Set([]byte(key), value, nil)
		}
		if err != nil {
			return err
		}
	}
	if err := b.Set([]byte(treeHeadKey), treeHead, nil); err != nil {
		return err
	}

	return b.Commit(pebble.Sync)
}

type pdbManagedLog struct {
	conn *pebble.DB
}

// NewPDBManagedLogStore returns an implementation of the ManagedLogStore
// interface that's backed by a Pebble database.
func NewPDBManagedLogStore(file string) (ManagedLogStore, error) {
	conn, err := openPebble(file, 0)
	if err != nil {
		return nil, err
	}
	return pdbManagedLog{conn: conn}, nil
}

func (ml pdbManagedLog) IncrementGreatestVersion(ctx context.Context, label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	} else if int64(count) > maxVersion {
		return 0, errors.New("count is greater than the maximum version")
	} else if len(label) == 0 {
		return 0, errors.New("label must not be empty")
	}

	prev := int64(-1)
	raw, err := getPebble(ml.conn, label)
	if err != nil {
		return 0, err
	} else if raw != nil {
		if len(raw) != 4 {
			return 0, errors.New("stored version is malformed")
		}
		prev = int64(binary.BigEndian.Uint32(raw))
	}

	ver := prev + int64(count)
	if ver > maxVersion {
		return 0, errors.New("increasing label version would exceed maximum")
	}
	next := make([]byte, 4)
	binary.BigEndian.PutUint32(next, uint32(ver))

	// Losing a counter would let the Service Operator sign two different values
	// under the same version, so the write is synced before returning.
	if err := ml.conn.Set(label, next, pebble.Sync); err != nil {
		return 0, err
	}

	return int(prev), nil
}
