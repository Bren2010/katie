// Package db implements database wrappers that match a common interface.
package db

// LogStore is the interface a log tree uses to communicate with its database.
type LogStore interface {
	BatchGet(keys []int) (data map[int][]byte, err error)
	BatchPut(data map[int][]byte) error
}
