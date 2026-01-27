// Package db implements database wrappers that match a common interface.
package db

// LogStore is the interface a Log Tree uses to communicate with its database.
type LogStore interface {
	BatchGet(keys []uint64) (map[uint64][]byte, error)
	Put(key uint64, value []byte) error
	Delete(key uint64) error
}

// PrefixStore is the interface a Prefix Tree uses to communicate with its
// database.
type PrefixStore interface {
	BatchGet(keys []string) (map[string][]byte, error)
	Put(key string, value []byte) error
	Delete(key string) error
}

// TransparencyStore is the interface a Transparency Log implementation uses to
// communicate with its database.
type TransparencyStore interface {
	// Clone returns a read-only clone of the current transparency store,
	// suitable for distributing to child goroutines.
	Clone() TransparencyStore

	GetTreeHead() (treeHead, auditor []byte, err error)
	PutTreeHead(raw []byte) error
	PutAuditorTreeHead(raw []byte) error

	BatchGetIndex(label [][]byte) ([][]byte, error)
	PutIndex(label, index []byte) error
	DeleteIndex(label []byte) error

	GetVersion(label []byte, ver uint32) ([]byte, error)
	PutVersion(label []byte, ver uint32, data []byte) error
	DeleteVersion(label []byte, ver uint32) error

	BatchGet(keys []uint64) (map[uint64][]byte, error)
	Put(key uint64, data []byte) error
	Delete(key uint64) error

	LogStore() LogStore
	PrefixStore() PrefixStore

	// Commit writes all pending changes to the database and returns nil on
	// success. The TransparencyStore should no longer be used after calling.
	Commit() error
}
