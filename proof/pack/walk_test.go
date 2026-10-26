package pack_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func walk(t *testing.T, dir string, f func([]byte)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err == nil {
			f(b)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
