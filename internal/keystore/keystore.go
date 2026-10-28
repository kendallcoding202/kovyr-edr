// Package keystore keeps the device signing key.
//
// v0 uses a software ECDSA P-256 key; its evidence strength is "software"
// and every statement says so. On Windows the private key is sealed with
// DPAPI in machine scope (CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE)
// and stored under %ProgramData%\Kovyr. Machine-scope DPAPI only ties the
// blob to this computer; any process on it can unseal it. What keeps the
// key from other users is the access list: the directory, and the key
// file itself, are open only to SYSTEM and Administrators, and an
// existing directory is checked (and refused or repaired) before it is
// used (dirsafety.go). Elsewhere it is a plain 0600 file, for development
// only.
//
// Callers get a proof.Signer, so a TPM-backed key in the Microsoft
// Platform Crypto Provider can replace this package without touching the
// statement code.
package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kendallcoding202/kovyr-edr/internal/fsutil"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// FileName is the key file inside the state directory.
const FileName = "device-key.json"

const fileType = "kovyr-device-key/v1"

var (
	// ErrNoKey means keygen has not run.
	ErrNoKey = errors.New("no device key: run `kovyr-agent keygen` first")
	// ErrKeyExists protects an enrolled key from being overwritten.
	ErrKeyExists = errors.New("a device key already exists; delete it by hand only if you mean to re-enroll this device")
)

// keyFile is the on-disk form.
type keyFile struct {
	Type       string `json:"type"`
	Alg        string `json:"alg"`
	Protection string `json:"protection"` // evidence strength
	Storage    string `json:"storage"`    // storageDPAPI or storageDevFile
	DevOnly    bool   `json:"dev_only,omitempty"`
	Warning    string `json:"warning,omitempty"`
	PublicKey  string `json:"public_key"` // base64 SPKI
	Sealed     string `json:"sealed"`     // base64: DPAPI blob, or raw PKCS#8 for the dev file
}

const (
	storageDPAPI   = "dpapi_machine"
	storageDevFile = "plain_file_dev_only"
	devWarning     = "DEV ONLY: this private key is NOT encrypted. Never use it on a customer machine."
)

// Path returns the key file path in dir.
func Path(dir string) string { return filepath.Join(dir, FileName) }

// Exists reports whether a key file is present.
func Exists(dir string) bool {
	_, err := os.Stat(Path(dir))
	return err == nil
}

// Generate creates a new device key in dir and refuses to overwrite one.
func Generate(dir string) (proof.Signer, error) {
	if err := PrepareDir(dir); err != nil {
		return nil, err
	}
	if Exists(dir) {
		return nil, ErrKeyExists
	}
	k, err := proof.GenerateSoftwareKey()
	if err != nil {
		return nil, err
	}
	signer, err := proof.NewSoftwareSigner(k)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	blob, storage, err := seal(der)
	if err != nil {
		return nil, fmt.Errorf("seal device key: %w", err)
	}
	kf := keyFile{
		Type: fileType, Alg: proof.AlgES256, Protection: proof.KeySoftware.String(), Storage: storage,
		PublicKey: signer.Public().Base64(), Sealed: base64.StdEncoding.EncodeToString(blob),
	}
	if storage == storageDevFile {
		kf.DevOnly, kf.Warning = true, devWarning
	}
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(Path(dir), append(b, '\n')); err != nil {
		return nil, err
	}
	// Its own protected access list, rather than only what the folder
	// passes down.
	if err := protectKeyFile(Path(dir)); err != nil {
		return nil, fmt.Errorf("restrict the device key file: %w", err)
	}
	return signer, nil
}

// Load opens the device key in dir, after checking that only SYSTEM and
// Administrators control dir and the key file (on Windows; CheckDir).
func Load(dir string) (proof.Signer, error) {
	if err := CheckDir(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoKey
		}
		return nil, err
	}
	path := Path(dir)
	if err := checkFilePerms(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoKey
		}
		return nil, err
	}
	b, err := fsutil.ReadFileCapped(path, 64<<10)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kf); err != nil {
		return nil, fmt.Errorf("device key file: %w", err)
	}
	if kf.Type != fileType || kf.Alg != proof.AlgES256 || kf.Protection != proof.KeySoftware.String() {
		return nil, errors.New("device key file: unsupported type, algorithm or protection")
	}
	blob, err := base64.StdEncoding.DecodeString(kf.Sealed)
	if err != nil {
		return nil, errors.New("device key file: bad sealed key encoding")
	}
	der, err := unseal(kf.Storage, blob)
	if err != nil {
		return nil, fmt.Errorf("unseal device key: %w", err)
	}
	defer clear(der)
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("device key file: bad private key")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("device key file: not an ECDSA key")
	}
	signer, err := proof.NewSoftwareSigner(ek)
	if err != nil {
		return nil, err
	}
	if signer.Public().Base64() != kf.PublicKey {
		return nil, errors.New("device key file: private and public key do not match")
	}
	return signer, nil
}
