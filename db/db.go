// Package db implements database wrappers that match a common interface.
package db

// LogStore is the interface a log tree uses to communicate with its database.
type LogStore interface {
	BatchGet(keys []int) (data map[int][]byte, err error)
	BatchPut(data map[int][]byte) error
}

// PrefixStore is the interface a prefix tree uses to communicate with its
// database.
type PrefixStore interface {
	Get(key uint64) ([]byte, error)
	Put(key uint64, data []byte) error
}

// TransparencyTreeRoot represents the signed root of a transparency tree.
type TransparencyTreeRoot struct {
	TreeSize  uint64 `json:"n"`
	Timestamp int64  `json:"ts"`
	Signature []byte `json:"sig"`
}

// TransparencyStore is the interface a transparency tree uses to communicate
// with its database.
type TransparencyStore interface {
	// Clone returns a read-only clone of the current transparency store,
	// suitable for distributing to child goroutines.
	Clone() TransparencyStore

	// GetRoot returns the most recent tree root, or the zero value of
	// TransparencyTreeRoot if there hasn't been a signed root yet.
	GetRoot() (*TransparencyTreeRoot, error)
	// SetRoot sets the input value as the most recent tree root.
	SetRoot(*TransparencyTreeRoot) error

	Get(key uint64) ([]byte, error)
	Put(key uint64, data []byte) error

	LogStore() LogStore
	PrefixStore() PrefixStore

	Commit() error
}
