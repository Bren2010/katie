// Package db implements database wrappers that match a common interface.
package db

// KvStore is the interface for an internally-consistent transaction with a
// key-value database.
type KvStore interface {
	BatchGet(keys []string) (data map[string][]byte, err error)
	BatchPut(data map[string][]byte) error
}
