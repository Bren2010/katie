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

	BatchGetIndex(labels [][]byte) ([][]byte, error)
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

// AuditorStore is the interface that a Third-Party Auditor uses to communicate
// with its database.
type AuditorStore interface {
	GetState() (raw []byte, err error)
	PutState(raw []byte) error
}

// ManagedLogStore is the interface that a Service Operator with a Third-Party
// Manager uses to communicate with its database.
type ManagedLogStore interface {
	// IncrementGreatestVersion atomically increments the greatest version of
	// the label that exists by `count` and returns the previous greatest
	// version of the label, or -1 if the label didn't exist previously.
	IncrementGreatestVersion(label []byte, count int) (int, error)
}

// ClientStore is the interface that a Key Transparency client uses to interact
// with its locally-stored data regarding a Transparency Log.
type ClientStore interface {
	// GetState returns the Transparency Log state for the client.
	GetState() ([]byte, error)

	// GetLabelState returns the state specific to `label`.
	GetLabelState(label []byte) ([]byte, error)

	// GetStaleLabel returns any label stored with a `terminal` value less than
	// or equal to `cutoff`.
	GetStaleLabel(cutoff uint64) ([][]byte, error)

	// PutState updates the global Transparency Log state to `raw`.
	PutState(raw []byte) error

	// PutLabelState updates the global Transparency Log state to `raw`. It also
	// updates the label-specific state for `label` to be `rawLabel` with
	// terminal log entry `terminal` (used in GetStaleLabel).
	//
	// The global state and label-specific state are updated atomically.
	// `rawLabel` may be nil, in which case the label-specific state is deleted.
	PutLabelState(raw, label, rawLabel []byte, terminal uint64) error
}
