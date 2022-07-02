// Package db implements database wrappers that match a common interface.
package db

type Tx interface {
	BatchGet(keys []string) (data map[string][]byte, err error)
	BatchPut(data map[string][]byte) error
}
