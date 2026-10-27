//go:build !windows

package keystore

import "testing"

func skipIfCannotPrepare(t *testing.T, dir string) { t.Helper() }
