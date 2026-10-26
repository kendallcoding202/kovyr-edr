package keystore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "Kovyr")
}

func TestGenerateLoadRoundTrip(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	if _, err := Load(dir); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Load before keygen: %v, want ErrNoKey", err)
	}
	s, err := Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Protection().String() != "software" {
		t.Errorf("protection %v, want software", s.Protection())
	}
	again, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Public().KeyID() != s.Public().KeyID() {
		t.Fatal("loaded a different key")
	}
	if _, err := Generate(dir); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second keygen: %v, want ErrKeyExists", err)
	}
	if again2, _ := Load(dir); again2.Public().KeyID() != s.Public().KeyID() {
		t.Fatal("refused keygen still replaced the key")
	}

	var kf keyFile
	b, _ := os.ReadFile(Path(dir))
	if err := json.Unmarshal(b, &kf); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if kf.Storage != storageDPAPI || kf.DevOnly {
			t.Errorf("windows key stored as %q dev_only=%v", kf.Storage, kf.DevOnly)
		}
	} else {
		if kf.Storage != storageDevFile || !kf.DevOnly || !strings.Contains(kf.Warning, "DEV ONLY") {
			t.Errorf("dev key not marked dev-only: %+v", kf)
		}
		fi, _ := os.Stat(Path(dir))
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %v, want 0600", fi.Mode().Perm())
		}
	}
}

func TestLoadRejectsTamperedFiles(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	if _, err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(Path(dir))
	other := testDir(t)
	if _, err := Generate(other); err != nil {
		t.Fatal(err)
	}
	otherFile, _ := os.ReadFile(Path(other))
	var o keyFile
	json.Unmarshal(otherFile, &o)

	mutations := map[string]func(kf map[string]any){
		"public key swapped": func(kf map[string]any) { kf["public_key"] = o.PublicKey },
		"unknown field":      func(kf map[string]any) { kf["command"] = "x" },
		"protection claim":   func(kf map[string]any) { kf["protection"] = "tpm2" },
		"wrong storage":      func(kf map[string]any) { kf["storage"] = "something_else" },
		"bad sealed":         func(kf map[string]any) { kf["sealed"] = "!!" },
	}
	for name, m := range mutations {
		var kf map[string]any
		json.Unmarshal(orig, &kf)
		m(kf)
		b, _ := json.Marshal(kf)
		if err := os.WriteFile(Path(dir), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Errorf("%s: Load accepted it", name)
		}
	}
}

func TestDevKeyFileMustNotBeWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows protects the key with DPAPI and a directory ACL")
	}
	dir := testDir(t)
	if _, err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(Path(dir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("loaded a key file other users can read")
	}
}
