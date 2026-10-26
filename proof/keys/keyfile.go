// Package keys reads and writes software key files. It is kept apart from
// package sigs so that the statement builder's dependencies never touch the
// file system.
//
// Production device keys never exist in this form: they are generated
// inside a TPM or Secure Enclave and only the public key leaves the chip.
// Such keys plug in through sigs.NewSigner(crypto.Signer).
package keys

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

// KeyFile is the on-disk form of a software private key.
type KeyFile struct {
	Type     string   `json:"type"` // "private-key/v1"
	Alg      sigs.Alg `json:"alg"`
	Role     string   `json:"role"`
	Name     string   `json:"name"`
	PKCS8    string   `json:"pkcs8"` // base64 DER PKCS#8
	Strength string   `json:"strength"`
	DemoOnly bool     `json:"demo_only,omitempty"`
	Warning  string   `json:"warning,omitempty"`
}

// PublicKeyFile is the shareable half.
type PublicKeyFile struct {
	Type      string   `json:"type"` // "public-key/v1"
	Alg       sigs.Alg `json:"alg"`
	Role      string   `json:"role"`
	Name      string   `json:"name"`
	PublicKey string   `json:"public_key"` // base64 DER SPKI
	KeyID     string   `json:"keyid"`
	Strength  string   `json:"strength"`
}

// New serializes a software key.
func New(cs crypto.Signer, role, name string) (*KeyFile, error) {
	pub, err := sigs.NewPublicKey(cs.Public())
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(cs)
	if err != nil {
		return nil, err
	}
	return &KeyFile{
		Type: "private-key/v1", Alg: pub.Alg, Role: role, Name: name,
		PKCS8: base64.StdEncoding.EncodeToString(der), Strength: "software",
	}, nil
}

// Generate creates a new software key file.
func Generate(alg sigs.Alg, role, name string) (*KeyFile, error) {
	cs, err := sigs.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	return New(cs, role, name)
}

// CryptoSigner returns the underlying crypto.Signer.
func (kf *KeyFile) CryptoSigner() (crypto.Signer, error) {
	if kf.Type != "private-key/v1" {
		return nil, fmt.Errorf("unexpected key file type %q", kf.Type)
	}
	der, err := sigs.DecodeBase64(kf.PKCS8)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	cs, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return cs, nil
}

// Signer loads the private key as a sigs.Signer.
func (kf *KeyFile) Signer() (sigs.Signer, error) {
	cs, err := kf.CryptoSigner()
	if err != nil {
		return nil, err
	}
	s, err := sigs.NewSigner(cs)
	if err != nil {
		return nil, err
	}
	if s.Public().Alg != kf.Alg {
		return nil, fmt.Errorf("key file says %s but key is %s", kf.Alg, s.Public().Alg)
	}
	return s, nil
}

// PublicFile derives the public half.
func (kf *KeyFile) PublicFile() (*PublicKeyFile, error) {
	s, err := kf.Signer()
	if err != nil {
		return nil, err
	}
	return &PublicKeyFile{
		Type: "public-key/v1", Alg: kf.Alg, Role: kf.Role, Name: kf.Name,
		PublicKey: s.Public().Base64(), KeyID: s.Public().KeyID(), Strength: kf.Strength,
	}, nil
}

// Load reads a private key file.
func Load(path string) (*KeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &kf, nil
}

// LoadSigner reads a private key file and returns its signer.
func LoadSigner(path string) (sigs.Signer, error) {
	kf, err := Load(path)
	if err != nil {
		return nil, err
	}
	return kf.Signer()
}

// Save writes the key file with owner-only permissions where the OS
// supports them. (On Windows this mode bit does not restrict other users;
// production keys live in the TPM instead.)
func (kf *KeyFile) Save(path string) error {
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// SavePublic writes a public key file.
func (pf *PublicKeyFile) Save(path string) error {
	b, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadPublic reads a public key file.
func LoadPublic(path string) (*PublicKeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pf PublicKeyFile
	if err := json.Unmarshal(b, &pf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &pf, nil
}
