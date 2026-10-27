// Package sigs defines the two signature algorithms the engine accepts and
// the exact byte encodings of their keys and signatures.
//
//	ecdsa-p256-sha256  (ES256) statements and enrollments. TPM 2.0 and the
//	                   Apple Secure Enclave support P-256, so hardware-bound
//	                   device keys use it.
//	ed25519            log checkpoints, witness cosignatures and simulated
//	                   timestamp authorities (C2SP signed-note convention);
//	                   also allowed for server-side attesters.
//
// Public keys are exchanged as DER SubjectPublicKeyInfo (SPKI), the format
// every crypto library and WebCrypto import directly. Only the canonical
// encodings are accepted: Ed25519 SPKI (44 bytes) and uncompressed P-256
// SPKI (91 bytes); the parsed key is re-encoded and compared byte for byte.
//
// ES256 signatures are IEEE P1363 r||s (64 bytes, big-endian, each half
// zero-padded to 32 bytes) with low S (s <= n/2). P1363 is what WebCrypto and
// Windows CNG emit natively; DER signatures (what most libraries, Go's
// crypto.Signer and the Secure Enclave emit) must be converted with
// ECDSAFromDER before they go into an envelope. Low S removes signature
// malleability, so every signed statement has exactly one valid encoding.
package sigs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

// Alg names a signature algorithm as it appears in enrollment records.
type Alg string

const (
	ES256   Alg = "ecdsa-p256-sha256"
	Ed25519 Alg = "ed25519"
)

var (
	ErrBadSignature = errors.New("signature does not verify")
	ErrHighS        = errors.New("ECDSA signature has high S; only low-S (s <= n/2) is accepted")
	ErrSigEncoding  = errors.New("signature is not a 64-byte raw signature (ES256 must be IEEE P1363 r||s, not DER)")
)

var (
	p256N     = elliptic.P256().Params().N
	p256HalfN = new(big.Int).Rsh(p256N, 1)
)

// PublicKey is a parsed, canonical public key.
type PublicKey struct {
	Alg  Alg
	SPKI []byte // canonical DER SubjectPublicKeyInfo
	key  crypto.PublicKey
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

// ParsePublicKeyBase64 parses a standard, padded base64 SPKI.
func ParsePublicKeyBase64(s string) (*PublicKey, error) {
	b, err := DecodeBase64(s)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return ParsePublicKey(b)
}

// NewPublicKey wraps a Go public key (*ecdsa.PublicKey on P-256 or
// ed25519.PublicKey).
func NewPublicKey(k crypto.PublicKey) (*PublicKey, error) {
	var alg Alg
	switch pk := k.(type) {
	case *ecdsa.PublicKey:
		if pk.Curve != elliptic.P256() {
			return nil, errors.New("public key: only the P-256 curve is accepted")
		}
		alg = ES256
	case ed25519.PublicKey:
		if len(pk) != ed25519.PublicKeySize {
			return nil, errors.New("public key: bad Ed25519 key length")
		}
		alg = Ed25519
	default:
		return nil, fmt.Errorf("public key: unsupported key type %T", k)
	}
	spki, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}
	return &PublicKey{Alg: alg, SPKI: spki, key: k}, nil
}

// KeyID is the lowercase hex SHA-256 of the SPKI. It is the DSSE keyid.
func (k *PublicKey) KeyID() string {
	h := sha256.Sum256(k.SPKI)
	return hex.EncodeToString(h[:])
}

// Base64 returns the SPKI in standard padded base64.
func (k *PublicKey) Base64() string { return base64.StdEncoding.EncodeToString(k.SPKI) }

// Ed25519Raw returns the 32-byte key for Ed25519 keys (used by signed notes).
func (k *PublicKey) Ed25519Raw() (ed25519.PublicKey, error) {
	pk, ok := k.key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return pk, nil
}

// Verify checks sig over msg. For ES256 msg is hashed with SHA-256 first.
func (k *PublicKey) Verify(msg, sig []byte) error {
	switch k.Alg {
	case Ed25519:
		if len(sig) != ed25519.SignatureSize {
			return ErrSigEncoding
		}
		if !ed25519.Verify(k.key.(ed25519.PublicKey), msg, sig) {
			return ErrBadSignature
		}
		return nil
	case ES256:
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
		if !ecdsa.Verify(k.key.(*ecdsa.PublicKey), digest[:], r, s) {
			return ErrBadSignature
		}
		return nil
	}
	return fmt.Errorf("unsupported algorithm %q", k.Alg)
}

// Signer produces signatures in this package's wire encoding.
type Signer interface {
	Public() *PublicKey
	Sign(msg []byte) ([]byte, error)
}

// NewSigner adapts any crypto.Signer: an in-memory key, or a hardware key
// such as a TPM key behind Windows CNG or a Secure Enclave key, as long as
// it exposes the standard Go interface. ECDSA output (DER) is converted to
// low-S P1363. In-memory ECDSA keys sign deterministically (RFC 6979).
func NewSigner(cs crypto.Signer) (Signer, error) {
	pub, err := NewPublicKey(cs.Public())
	if err != nil {
		return nil, err
	}
	return &stdSigner{cs: cs, pub: pub}, nil
}

type stdSigner struct {
	cs  crypto.Signer
	pub *PublicKey
}

func (s *stdSigner) Public() *PublicKey { return s.pub }

func (s *stdSigner) Sign(msg []byte) ([]byte, error) {
	switch s.pub.Alg {
	case Ed25519:
		return s.cs.Sign(nil, msg, crypto.Hash(0))
	case ES256:
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
	return nil, fmt.Errorf("unsupported algorithm %q", s.pub.Alg)
}

// ECDSAFromDER converts an ASN.1 DER ECDSA-Sig-Value into the 64-byte
// low-S P1363 encoding this format requires.
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

// ECDSAToDER converts P1363 r||s to DER, for interoperating with libraries
// that only accept DER.
func ECDSAToDER(p1363 []byte) ([]byte, error) {
	if len(p1363) != 64 {
		return nil, ErrSigEncoding
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(p1363[:32]), new(big.Int).SetBytes(p1363[32:]),
	})
}

// HighS returns the malleated twin (r, n-s) of a P1363 signature. It exists
// so tests can prove that verifiers reject it.
func HighS(p1363 []byte) []byte {
	out := append([]byte(nil), p1363...)
	s := new(big.Int).SetBytes(p1363[32:])
	new(big.Int).Sub(p256N, s).FillBytes(out[32:])
	return out
}

// GenerateKey creates a new software key.
func GenerateKey(alg Alg) (crypto.Signer, error) {
	switch alg {
	case ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("unsupported algorithm %q", alg)
}

// DecodeBase64 decodes standard padded base64 and rejects any
// non-canonical encoding (stray bits, missing padding, newlines).
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
