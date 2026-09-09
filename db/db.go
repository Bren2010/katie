// Package db implements database wrappers that match a common interface.
package db

import "context"

const maxVersion = (int64(1) << 32) - 1

func dup(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// KeyValueStore is the interface implemented by a key-value store, which is the
// persistent layer to a TransparencyStore.
type KeyValueStore interface {
	// BatchGet returns the values of the corresponding keys.
	BatchGet(ctx context.Context, keys []string) ([][]byte, error)

	// Commit writes a batch of new key-value pairs to the database and updates
	// the key "tree-head" to have the value `treeHead`.
	//
	// The store ensures that the "tree-head" key is only modified if all of the
	// elements of `batch` were successfully persisted. If the underlying
	// database supports it, all key-value pairs (including "tree-head") may be
	// written as a single atomic batch, but this is not required.
	Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error
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
	IncrementGreatestVersion(ctx context.Context, label []byte, count int) (int, error)
}

// ClientStore is the interface that a Key Transparency client uses to interact
// with its locally-stored data regarding a Transparency Log.
type ClientStore interface {
	// GetState returns the Transparency Log state for the client.
	GetState() ([]byte, error)

	// GetLabelState returns the state specific to `label`.
	GetLabelState(label []byte) ([]byte, error)

	// GetStaleLabel returns any label stored with a `terminal` value less than
	// or equal to `cutoff` and its corresponding state, or nil if there are
	// none.
	GetStaleLabel(cutoff uint64) ([]byte, []byte, error)

	// PutState updates the global Transparency Log state to `raw`.
	PutState(raw []byte) error

	// PutLabelState updates the global Transparency Log state to `raw`. It also
	// updates the label-specific state for `label` to be `rawLabel` with
	// terminal log entry `terminal` (used in GetStaleLabel).
	//
	// `rawLabel` may be nil, in which case the label-specific state is deleted.
	// The global state and label-specific state are either both updated
	// successfully, or neither are.
	PutLabelState(raw, label, rawLabel []byte, terminal uint64) error
}
