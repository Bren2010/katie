package test

import (
	"context"
	"crypto/rand"
	"strings"

	"github.com/Bren2010/katie/db"
)

// CountingKV wraps an in-memory key-value store and keeps a copy of the keys
// committed to it. The db package doesn't expose the contents of a store, so
// this is how tests assert on how many entries of each kind were persisted.
type CountingKV struct {
	inner    db.KeyValueStore
	treeHead []byte
	data     map[string]struct{}

	// CommitErr, if set, is returned by Commit without writing anything.
	CommitErr error
}

func NewCountingKV() *CountingKV {
	return &CountingKV{
		inner: db.NewMemoryKeyValueStore(),
		data:  make(map[string]struct{}),
	}
}

func (kv *CountingKV) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	return kv.inner.BatchGet(ctx, keys)
}

func (kv *CountingKV) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	if kv.CommitErr != nil {
		return kv.CommitErr
	}
	if err := kv.inner.Commit(ctx, batch, treeHead); err != nil {
		return err
	}
	for key, value := range batch {
		if value == nil {
			delete(kv.data, key)
		} else {
			kv.data[key] = struct{}{}
		}
	}
	kv.treeHead = treeHead
	return nil
}

// TreeHead returns the most recently committed tree head.
func (kv *CountingKV) TreeHead() []byte { return kv.treeHead }

// Count returns the number of committed keys with the given prefix, ignoring
// keys that were deleted. The prefixes mirror the key layout of
// db.TransparencyStore: "i" for label indices, "v" for label versions, and "t"
// for log entries.
func (kv *CountingKV) Count(prefix string) int {
	out := 0
	for key := range kv.data {
		if strings.HasPrefix(key, prefix) {
			out++
		}
	}
	return out
}

// MemStoreCounting returns a TransparencyStore along with the CountingKV that
// backs it.
func MemStoreCounting() (db.TransparencyStore, *CountingKV) {
	kv := NewCountingKV()
	return db.NewTransparencyStore(context.Background(), kv, false), kv
}

// MemStore returns a TransparencyStore backed by an in-memory key-value store.
func MemStore() db.TransparencyStore {
	kv := db.NewMemoryKeyValueStore()
	return db.NewTransparencyStore(context.Background(), kv, false)
}

// RandomLabels returns `n` random 8-byte labels.
func RandomLabels(n int) [][]byte {
	labels := make([][]byte, n)
	for i := range labels {
		labels[i] = make([]byte, 8)
		rand.Read(labels[i])
	}
	return labels
}
