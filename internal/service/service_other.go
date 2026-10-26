//go:build !windows

package service

import (
	"context"
	"os"
	"time"
)

// Elevated reports whether this process runs as root (development only).
func Elevated() bool { return os.Geteuid() == 0 }

// ProtectedRoots is empty outside Windows.
func ProtectedRoots() []string { return nil }

// IsService is false outside Windows.
func IsService() bool { return false }

func Install(exe, stateDir string) error    { return ErrWindowsOnly }
func Uninstall(timeout time.Duration) error { return ErrWindowsOnly }
func Start(timeout time.Duration) error     { return ErrWindowsOnly }
func Stop(timeout time.Duration) error      { return ErrWindowsOnly }
func Query() (Status, error)                { return Status{}, ErrWindowsOnly }

func Run(main func(ctx context.Context) error, logf func(string, ...any)) error {
	return ErrWindowsOnly
}
