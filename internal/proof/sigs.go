package proof

// Device keys and signatures, in the proof engine's encodings (ported from
// proof-of-protection/engine/sigs; see the TODO in canon.go):
//
//   - algorithm ecdsa-p256-sha256 (ES256): ECDSA on P-256 over SHA-256 of
//     the DSSE pre-authentication encoding. P-256 is what TPM 2.0 supports,
//     so the key can later move into the TPM without changing the format;
//   - public keys are DER SubjectPublicKeyInfo (91 bytes for P-256), in
//     standard padded base64 on the wire, and only the canonical encoding
//     is accepted;
//   - the DSSE keyid is the lowercase hex SHA-256 of the SPKI;
//   - signatures are IEEE P1363 r||s (64 bytes) with low S (s <= n/2), so
//     each statement has exactly one valid signature encoding.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// AlgES256 is the only device signature algorithm.
const AlgES256 = "ecdsa-p256-sha256"

var (
	// ErrBadSignature means the signature does not verify.
	ErrBadSignature = errors.New("signature does not verify")
	// ErrHighS means a malleable high-S ECDSA signature was presented.
	ErrHighS = errors.New("ECDSA signature has high S; only low-S is accepted")
	// ErrSigEncoding means the signature is not 64-byte P1363.
	ErrSigEncoding = errors.New("signature is not a 64-byte IEEE P1363 r||s value")
)

var (
	p256N     = elliptic.P256().Params().N
	p256HalfN = new(big.Int).Rsh(p256N, 1)
)

// PublicKey is a parsed, canonical P-256 public key.
type PublicKey struct {
	SPKI []byte
	key  *ecdsa.PublicKey
}

// NewPublicKey wraps a P-256 public key.
func NewPublicKey(k crypto.PublicKey) (*PublicKey, error) {
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("public key: only ECDSA P-256 keys are accepted")
	}
	spki, err := x509.MarshalPKIXPublicKey(ek)
	if err != nil {
		return nil, err
	}
	return &PublicKey{SPKI: spki, key: ek}, nil
}

// ParsePublicKey parses a DER SPKI and insists on the canonical encoding.
func ParsePublicKey(spki []byte) (*PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pk, err := NewPublicKey(k)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pk.SPKI, spki) {
		return nil, errors.New("public key: non-canonical SPKI encoding")
	}
	return pk, nil
}

// ParsePublicKeyBase64 parses a standard padded base64 SPKI.
func ParsePublicKeyBase64(s string) (*PublicKey, error) {
	b, err := DecodeBase64(s)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return ParsePublicKey(b)
}

// KeyID is the lowercase hex SHA-256 of the SPKI (the DSSE keyid).
func (k *PublicKey) KeyID() string {
	h := sha256.Sum256(k.SPKI)
	return hex.EncodeToString(h[:])
}

// DeviceID is the attester identifier derived from the key: "dev_" plus
// the first 16 hex characters of the keyid. It cannot be mistyped and
// carries no host or user name.
func (k *PublicKey) DeviceID() string { return DevicePrefix + k.KeyID()[:16] }

// Base64 returns the SPKI in standard padded base64.
func (k *PublicKey) Base64() string { return base64.StdEncoding.EncodeToString(k.SPKI) }

// Verify checks a P1363 low-S signature over SHA-256(msg).
func (k *PublicKey) Verify(msg, sig []byte) error {
	if len(sig) != 64 {
		return ErrSigEncoding
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(p256N) >= 0 || s.Cmp(p256N) >= 0 {
		return ErrBadSignature
	}
	if s.Cmp(p256HalfN) > 0 {
		return ErrHighS
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(k.key, digest[:], r, s) {
		return ErrBadSignature
	}
	return nil
}

// Signer is a device signing key. v0 uses a software key (see package
// keystore); a TPM-backed key in the Microsoft Platform Crypto Provider
// will implement the same interface later, through NewCryptoSigner, without
// any change to statements or the receiver.
type Signer interface {
	Public() *PublicKey
	// Sign returns the ES256 signature of msg in P1363 low-S encoding.
	Sign(msg []byte) ([]byte, error)
	// Protection says where the private key lives. Every statement
	// reports it, so a verifier knows the evidence strength.
	Protection() KeyProtection
}

// NewCryptoSigner adapts any crypto.Signer holding a P-256 key: an
// in-memory key today, a CNG/TPM key later.
func NewCryptoSigner(cs crypto.Signer, protection KeyProtection) (Signer, error) {
	if _, err := enumName(keyProtectionNames, uint8(protection)); err != nil {
		return nil, fmt.Errorf("key protection: %w", err)
	}
	pub, err := NewPublicKey(cs.Public())
	if err != nil {
		return nil, err
	}
	return &cryptoSigner{cs: cs, pub: pub, protection: protection}, nil
}

// NewSoftwareSigner wraps an in-memory software key. Its evidence strength
// is "software".
func NewSoftwareSigner(k *ecdsa.PrivateKey) (Signer, error) {
	return NewCryptoSigner(k, KeySoftware)
}

// GenerateSoftwareKey creates a new P-256 key.
func GenerateSoftwareKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

type cryptoSigner struct {
	cs         crypto.Signer
	pub        *PublicKey
	protection KeyProtection
}

func (s *cryptoSigner) Public() *PublicKey        { return s.pub }
func (s *cryptoSigner) Protection() KeyProtection { return s.protection }

func (s *cryptoSigner) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	var rnd = rand.Reader
	if _, ok := s.cs.(*ecdsa.PrivateKey); ok {
		rnd = nil // Go 1.24+: nil selects deterministic RFC 6979 nonces
	}
	der, err := s.cs.Sign(rnd, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return ECDSAFromDER(der)
}

// ECDSAFromDER converts an ASN.1 DER ECDSA signature to low-S P1363.
func ECDSAFromDER(der []byte) ([]byte, error) {
	var v struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("malformed DER ECDSA signature")
	}
	if v.R.Sign() <= 0 || v.S.Sign() <= 0 || v.R.Cmp(p256N) >= 0 || v.S.Cmp(p256N) >= 0 {
		return nil, errors.New("ECDSA signature values out of range")
	}
	s := v.S
	if s.Cmp(p256HalfN) > 0 {
		s = new(big.Int).Sub(p256N, s)
	}
	out := make([]byte, 64)
	v.R.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// highS returns the malleated twin (r, n-s) of a P1363 signature, for tests.
func highS(p1363 []byte) []byte {
	out := append([]byte(nil), p1363...)
	s := new(big.Int).SetBytes(p1363[32:])
	new(big.Int).Sub(p256N, s).FillBytes(out[32:])
	return out
}

// DecodeBase64 decodes standard padded base64 and rejects any
// non-canonical encoding.
func DecodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid base64")
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("non-canonical base64")
	}
	return b, nil
}
