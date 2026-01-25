// Package db implements database wrappers that match a common interface.
package db

// LogStore is the interface a Log Tree uses to communicate with its database.
type LogStore interface {
	BatchGet(keys []uint64) (map[uint64][]byte, error)
	BatchPut(data map[uint64][]byte) error
}

// PrefixStore is the interface a Prefix Tree uses to communicate with its
// database.
type PrefixStore interface {
	BatchGet(keys []string) (map[string][]byte, error)
	BatchPut(data map[string][]byte) error
}

// TransparencyStore is the interface a Transparency Log implementation uses to
// communicate with its database.
type TransparencyStore interface {
	// Clone returns a read-only clone of the current transparency store,
	// suitable for distributing to child goroutines.
	Clone() TransparencyStore

	GetTreeHead() (treeHead, auditor []byte, err error)
	SetTreeHead(raw []byte) error
	SetAuditorTreeHead(raw []byte) error

	BatchGetLabelIndex(label [][]byte) ([][]byte, error)
	SetLabelIndex(label, index []byte) error

	GetLabelValue(label []byte, ver uint32) ([]byte, error)
	SetLabelValue(label []byte, ver uint32, data []byte) error

	BatchGet(keys []uint64) (map[uint64][]byte, error)
	Put(key uint64, data []byte) error

	LogStore() LogStore
	PrefixStore() PrefixStore

	// Commit writes all pending changes to the database and returns nil on
	// success. The TransparencyStore should no longer be used after calling.
	Commit() error
}
