//go:build !windows

package keystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultDir is the dev state directory on non-Windows machines.
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "kovyr-dev"), nil
}

// PrepareDir creates dir readable only by the current user.
func PrepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// seal stores the key unencrypted: this path is for development only and
// the file says so.
func seal(der []byte) ([]byte, string, error) {
	return append([]byte(nil), der...), storageDevFile, nil
}

func unseal(storage string, blob []byte) ([]byte, error) {
	if storage != storageDevFile {
		return nil, fmt.Errorf("key storage %q cannot be opened on this OS", storage)
	}
	return append([]byte(nil), blob...), nil
}

// checkFilePerms refuses a key file that others could read.
func checkFilePerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return errors.New("device key file is readable by other users; it must be mode 0600")
	}
	return nil
}
