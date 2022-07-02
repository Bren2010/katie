// Package db implements database wrappers that match a common interface.
package db

// Tx is the interface for an internally-consistent transaction with a database.
// Transactions are guaranteed to be all-or-nothing.
type Tx interface {
	BatchGet(keys []string) (data map[string][]byte, err error)
	BatchPut(data map[string][]byte) error
}

// MemoryTx implements the Tx interface over an in-memory map, mostly for
// testing use-cases.
type MemoryTx struct {
	data map[string][]byte
}

func NewMemoryTx() *MemoryTx {
	return &MemoryTx{data: make(map[string][]byte)}
}

func (m *MemoryTx) BatchGet(keys []string) (map[string][]byte, error) {
	out := make(map[string][]byte)

	for _, key := range keys {
		if d, ok := m.data[key]; ok {
			out[key] = d
		}
	}

	return out, nil
}

func (m *MemoryTx) BatchPut(data map[string][]byte) error {
	for key, d := range data {
		buf := make([]byte, len(d))
		copy(buf, d)
		m.data[key] = buf
	}
	return nil
}
