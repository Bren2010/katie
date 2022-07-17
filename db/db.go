// Package db implements database wrappers that match a common interface.
package db

// KvStore is the interface for an internally-consistent transaction with a
// key-value database.
type KvStore interface {
	BatchGet(keys []string) (data map[string][]byte, err error)
	BatchPut(data map[string][]byte) error
}

// MemoryKv implements the KvStore interface over an in-memory map, mostly for
// testing use-cases.
type MemoryKv struct {
	Data map[string][]byte
}

func NewMemoryKv() *MemoryKv {
	return &MemoryKv{Data: make(map[string][]byte)}
}

func (m *MemoryKv) BatchGet(keys []string) (map[string][]byte, error) {
	out := make(map[string][]byte)

	for _, key := range keys {
		if d, ok := m.Data[key]; ok {
			out[key] = d
		}
	}

	return out, nil
}

func (m *MemoryKv) BatchPut(data map[string][]byte) error {
	for key, d := range data {
		buf := make([]byte, len(d))
		copy(buf, d)
		m.Data[key] = buf
	}
	return nil
}
