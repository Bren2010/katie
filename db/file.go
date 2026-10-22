package db

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
)

// checkParentDir returns an error if the directory that `file` would be
// created in doesn't exist.
func checkParentDir(file string) error {
	dir := filepath.Dir(file)
	info, err := os.Stat(dir)
	if err != nil {
		return err
	} else if !info.IsDir() {
		return fmt.Errorf("%v is not a directory", dir)
	}
	return nil
}

// writeFileAtomic replaces the contents of `file` with `raw`. Either the old
// contents or the new contents will be present after a crash, and the new
// contents are synced to disk before it returns.
func writeFileAtomic(file string, raw []byte) error {
	temp := file + ".tmp"

	// Write new state to a temporary file in the same directory.
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	} else if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	} else if err := f.Sync(); err != nil {
		f.Close()
		return err
	} else if err := f.Close(); err != nil {
		return err
	}

	// Rename the temporary file over the real one.
	if err := os.Rename(temp, file); err != nil {
		return err
	}

	// The rename is only durable once the directory entry has been synced too.
	dir, err := os.Open(filepath.Dir(file))
	if err != nil {
		return err
	} else if err := dir.Sync(); err != nil {
		dir.Close()
		return err
	}
	return dir.Close()
}

// fileAuditor implements the AuditorStore interface over a single file on disk.
type fileAuditor struct {
	file string
}

// NewFileAuditorStore returns an implementation of the AuditorStore interface
// that keeps the auditor's state in a single file on disk. Writes are atomic
// and synced to disk before PutState returns.
func NewFileAuditorStore(file string) (AuditorStore, error) {
	if file == "" {
		return nil, errors.New("no file name provided")
	} else if err := checkParentDir(file); err != nil {
		return nil, err
	}
	return fileAuditor{file: file}, nil
}

func (as fileAuditor) GetState() ([]byte, error) {
	raw, err := os.ReadFile(as.file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return raw, nil
}

func (as fileAuditor) PutState(raw []byte) error {
	return writeFileAtomic(as.file, raw)
}

type fileClientLabel struct {
	Raw      []byte `json:"raw"`
	Terminal uint64 `json:"terminal"`
}

// fileClientData is the on-disk format of a fileClient. Labels are keyed by
// their hex encoding.
type fileClientData struct {
	State  []byte                     `json:"state"`
	Labels map[string]fileClientLabel `json:"labels"`
}

// fileClient implements the ClientStore interface over a single file on disk.
// The entire contents of the file are kept in memory, and the file is
// rewritten on every update.
type fileClient struct {
	file string
	data fileClientData
}

// NewFileClientStore returns an implementation of the ClientStore interface
// that keeps the client's state in a single file on disk. Writes are atomic
// and synced to disk before they return.
func NewFileClientStore(file string) (ClientStore, error) {
	if file == "" {
		return nil, errors.New("no file name provided")
	}

	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		if err := checkParentDir(file); err != nil {
			return nil, err
		}
		return &fileClient{
			file: file,
			data: fileClientData{Labels: make(map[string]fileClientLabel)},
		}, nil
	} else if err != nil {
		return nil, err
	}

	var data fileClientData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parsing client state file: %w", err)
	}
	if data.Labels == nil {
		data.Labels = make(map[string]fileClientLabel)
	}
	return &fileClient{file: file, data: data}, nil
}

// commit writes `data` to disk and, only if that succeeds, makes it the
// in-memory state.
func (cs *fileClient) commit(data fileClientData) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	} else if err := writeFileAtomic(cs.file, raw); err != nil {
		return err
	}
	cs.data = data
	return nil
}

func (cs *fileClient) GetState() ([]byte, error) { return dup(cs.data.State), nil }

func (cs *fileClient) GetLabelState(label []byte) ([]byte, error) {
	return dup(cs.data.Labels[hex.EncodeToString(label)].Raw), nil
}

func (cs *fileClient) GetStaleLabel(cutoff uint64) ([]byte, []byte, error) {
	for labelStr, state := range cs.data.Labels {
		if state.Terminal <= cutoff {
			label, err := hex.DecodeString(labelStr)
			if err != nil {
				return nil, nil, err
			}
			return label, dup(state.Raw), nil
		}
	}
	return nil, nil, nil
}

func (cs *fileClient) PutState(raw []byte) error {
	return cs.commit(fileClientData{State: dup(raw), Labels: cs.data.Labels})
}

func (cs *fileClient) PutLabelState(raw, label, rawLabel []byte, terminal uint64) error {
	// Copy the label map so that the in-memory state is unchanged if the write
	// fails.
	labels := maps.Clone(cs.data.Labels)
	labelStr := hex.EncodeToString(label)
	if rawLabel == nil {
		delete(labels, labelStr)
	} else {
		labels[labelStr] = fileClientLabel{Raw: dup(rawLabel), Terminal: terminal}
	}

	return cs.commit(fileClientData{State: dup(raw), Labels: labels})
}
