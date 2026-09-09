package db

import (
	"context"
	"errors"
	"fmt"
)

type memKeyValue struct {
	Data map[string][]byte
}

// NewMemoryKeyValueStore returns an in-memory implementation of the
// KeyValueStore interface.
func NewMemoryKeyValueStore() KeyValueStore {
	return memKeyValue{make(map[string][]byte)}
}

func (kv memKeyValue) BatchGet(ctx context.Context, keys []string) ([][]byte, error) {
	out := make([][]byte, len(keys))
	for i, key := range keys {
		out[i] = dup(kv.Data[key])
	}
	return out, nil
}

func (kv memKeyValue) Commit(ctx context.Context, batch map[string][]byte, treeHead []byte) error {
	for key, value := range batch {
		kv.Data[key] = dup(value)
	}
	kv.Data[treeHeadKey] = dup(treeHead)
	return nil
}

type memAuditor struct {
	Data []byte
}

func NewMemoryAuditorStore() AuditorStore { return &memAuditor{} }

func (as *memAuditor) GetState() ([]byte, error) { return dup(as.Data), nil }

func (as *memAuditor) PutState(raw []byte) error {
	as.Data = dup(raw)
	return nil
}

type memManagedLog struct {
	Data map[string]int
}

func NewMemoryManagedLogStore() ManagedLogStore {
	return memManagedLog{Data: make(map[string]int)}
}

func (mls memManagedLog) IncrementGreatestVersion(label []byte, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("count must be greater than or equal to 1")
	}
	labelStr := fmt.Sprintf("%x", label)
	ver, ok := mls.Data[labelStr]
	if !ok {
		ver = -1
	}
	mls.Data[labelStr] = ver + count
	return ver, nil
}

// type ClientLabelState struct {
// 	Raw      []byte
// 	Terminal uint64
// }
//
// type ClientStore struct {
// 	State      []byte
// 	LabelState map[string]ClientLabelState
// }

// func NewClientState() *ClientStore {
// 	return &ClientStore{LabelState: make(map[string]ClientLabelState)}
// }

// func (cs *ClientStore) GetState() ([]byte, error) {
// 	return dup(cs.State), nil
// }

// func (cs *ClientStore) GetLabelState(label []byte) ([]byte, error) {
// 	return dup(cs.LabelState[hex.EncodeToString(label)].Raw), nil
// }

// func (cs *ClientStore) GetStaleLabel(cutoff uint64) ([]byte, []byte, error) {
// 	for labelStr, state := range cs.LabelState {
// 		if state.Terminal <= cutoff {
// 			label, err := hex.DecodeString(labelStr)
// 			if err != nil {
// 				return nil, nil, err
// 			}
// 			return label, dup(state.Raw), nil
// 		}
// 	}
// 	return nil, nil, nil
// }

// func (cs *ClientStore) PutState(raw []byte) error {
// 	cs.State = dup(raw)
// 	return nil
// }

// func (cs *ClientStore) PutLabelState(raw, label, rawLabel []byte, terminal uint64) error {
// 	cs.State = dup(raw)

// 	labelStr := hex.EncodeToString(label)
// 	if rawLabel == nil {
// 		delete(cs.LabelState, labelStr)
// 	} else {
// 		cs.LabelState[labelStr] = ClientLabelState{
// 			Raw:      dup(rawLabel),
// 			Terminal: terminal,
// 		}
// 	}

// 	return nil
// }
