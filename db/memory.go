package db

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
)

type memKeyValue struct {
	data map[string][]byte
}

// NewMemoryKeyValueStore returns an in-memory implementation of the
// KeyValueStore interface.
func NewMemoryKeyValueStore() KeyValueStore {
	return memKeyValue{make(map[string][]byte)}
}

func (kv memKeyValue) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	out := make([][]byte, len(keys))
	for i, key := range keys {
		out[i] = dup(kv.data[key])
	}
	return out, nil
}

func (kv memKeyValue) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	for key, value := range batch {
		kv.data[key] = dup(value)
	}
	kv.data[treeHeadKey] = dup(treeHead)
	return nil
}

type memAuditor struct {
	Data []byte
}

// NewMemoryAuditorStore returns an in-memory implementation of the AuditorStore
// interface.
func NewMemoryAuditorStore() AuditorStore { return &memAuditor{} }

func (as *memAuditor) GetState() ([]byte, error) { return dup(as.Data), nil }

func (as *memAuditor) PutState(raw []byte) error {
	as.Data = dup(raw)
	return nil
}

type memManagedLog struct {
	data map[string]int
}

// NewMemoryManagedLogStore returns an in-memory implementation of the
// ManagedLogStore interface.
func NewMemoryManagedLogStore() ManagedLogStore {
	return memManagedLog{data: make(map[string]int)}
}

func (mls memManagedLog) IncrementGreatestVersion(ctx context.Context, label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	} else if int64(count) > maxVersion {
		return 0, errors.New("count is greater than the maximum version")
	} else if len(label) == 0 {
		return 0, errors.New("label must not be empty")
	}

	labelStr := fmt.Sprintf("%x", label)
	ver, ok := mls.data[labelStr]
	if !ok {
		ver = -1
	}
	if int64(ver)+int64(count) > maxVersion {
		return 0, errors.New("increasing label version would exceed maximum")
	}
	mls.data[labelStr] = ver + count

	return ver, nil
}

type memClientLabel struct {
	raw      []byte
	terminal uint64
}

type memClient struct {
	state  []byte
	labels map[string]memClientLabel
}

// NewMemoryClientStore returns an in-memory implementation of the ClientStore
// interface.
func NewMemoryClientStore() ClientStore {
	return &memClient{labels: make(map[string]memClientLabel)}
}

func (cs *memClient) GetState() ([]byte, error) { return dup(cs.state), nil }

func (cs *memClient) GetLabelState(label []byte) ([]byte, error) {
	return dup(cs.labels[hex.EncodeToString(label)].raw), nil
}

func (cs *memClient) GetStaleLabel(cutoff uint64) ([]byte, []byte, error) {
	// Iterate in sorted order so that the label returned is deterministic.
	for _, labelStr := range slices.Sorted(maps.Keys(cs.labels)) {
		state := cs.labels[labelStr]
		if state.terminal <= cutoff {
			label, err := hex.DecodeString(labelStr)
			if err != nil {
				return nil, nil, err
			}
			return label, dup(state.raw), nil
		}
	}
	return nil, nil, nil
}

func (cs *memClient) PutState(raw []byte) error {
	cs.state = dup(raw)
	return nil
}

func (cs *memClient) PutLabelState(raw, label, rawLabel []byte, terminal uint64) error {
	cs.state = dup(raw)

	labelStr := hex.EncodeToString(label)
	if rawLabel == nil {
		delete(cs.labels, labelStr)
	} else {
		cs.labels[labelStr] = memClientLabel{raw: dup(rawLabel), terminal: terminal}
	}

	return nil
}
