package keystore

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// skipIfCannotPrepare skips when the test is not elevated: the key
// directory is created for SYSTEM and Administrators only.
func skipIfCannotPrepare(t *testing.T, dir string) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated (administrator) process, as the agent does")
	}
}

func TestDPAPISealIsNotPlaintext(t *testing.T) {
	k, err := proof.GenerateSoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	sealed, storage, err := seal(der)
	if err != nil {
		t.Fatal(err)
	}
	if storage != storageDPAPI || bytes.Contains(sealed, der) {
		t.Fatal("DPAPI output contains the plain key")
	}
	plain, err := unseal(storage, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, der) {
		t.Fatal("unseal did not return the key")
	}
	if _, err := unseal(storageDevFile, der); err == nil {
		t.Fatal("Windows accepted a plain dev key file")
	}
	corrupt := append([]byte(nil), sealed...)
	corrupt[len(corrupt)/2] ^= 0xff
	if _, err := unseal(storage, corrupt); err == nil {
		t.Fatal("unsealed a corrupted blob")
	}
}

func TestKeyFileHoldsNoPlainKey(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	if _, err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(Path(dir))
	var kf keyFile
	json.Unmarshal(b, &kf)
	sealed, _ := base64.StdEncoding.DecodeString(kf.Sealed)
	if _, err := x509.ParsePKCS8PrivateKey(sealed); err == nil {
		t.Fatal("key file holds a plain PKCS#8 key")
	}
}
