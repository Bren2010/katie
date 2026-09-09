package db

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

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
	}

	// Fail now rather than on the first write if the directory is unusable.
	dir := filepath.Dir(file)
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	} else if !info.IsDir() {
		return nil, fmt.Errorf("%v is not a directory", dir)
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
	temp := as.file + ".tmp"

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
	if err := os.Rename(temp, as.file); err != nil {
		return err
	}

	// The rename is only durable once the directory entry has been synced too.
	dir, err := os.Open(filepath.Dir(as.file))
	if err != nil {
		return err
	} else if err := dir.Sync(); err != nil {
		dir.Close()
		return err
	}
	return dir.Close()
}
