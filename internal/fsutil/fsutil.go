// Package fsutil holds the agent's one file-writing primitive.
package fsutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path through a temporary file in the same
// directory, fsyncs it and renames it into place, so a crash leaves either
// the old file or the new one, never a torn one. os.CreateTemp creates the
// file 0600 on Unix.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ReadFileCapped reads a whole file but refuses one larger than max, so a
// corrupted or planted file cannot make the agent allocate without bound.
func ReadFileCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), max)
	}
	return b, nil
}
