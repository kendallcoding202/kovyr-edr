package proof

// Device keys, signers and envelopes, built on the shared proof library
// (proof/sigs, proof/dsse, proof/canon). This file adds only the device
// agent's narrower rules on top:
//
//   - a device key is ECDSA P-256 (ES256) and nothing else, so it can
//     move into the TPM without a format change; the library also accepts
//     Ed25519, which is for service keys;
//   - a device envelope carries exactly one signature, by the device key;
//   - every signer says where its private key lives (KeyProtection), the
//     evidence strength SPEC section 14 talks about;
//   - envelopes are size-capped before they are parsed.
//
// Encodings (canonical JSON, PAE, P1363 low-S signatures, SPKI, key IDs)
// are the library's, byte for byte; testdata/golden-heartbeat.json pins
// the result.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

// AlgES256 is the only device signature algorithm.
const AlgES256 = string(sigs.ES256)

// PayloadTypeInToto is the only payload type signed or accepted.
const PayloadTypeInToto = dsse.PayloadTypeInToto

// MaxEnvelopeBytes bounds an envelope on disk and on the wire. A
// heartbeat envelope is about 2 KB.
const MaxEnvelopeBytes = 16 << 10

// PublicKey is a parsed, canonical public key; Envelope is a DSSE
// envelope. Both are the shared library's types.
type (
	PublicKey = sigs.PublicKey
	Envelope  = dsse.Envelope
)

var (
	// ErrBadSignature means the signature does not verify.
	ErrBadSignature = sigs.ErrBadSignature
	// ErrHighS means a malleable high-S ECDSA signature was presented.
	ErrHighS = sigs.ErrHighS
	// errNotDeviceKey means a key is not ECDSA P-256.
	errNotDeviceKey = errors.New("public key: device keys are ECDSA P-256 (ES256) only")
)

// DeviceID is the attester identifier derived from the key: "dev_" plus
// the first 16 hex characters of the key ID (SPEC section 5). It cannot be
// mistyped and carries no host or user name.
func DeviceID(k *PublicKey) string { return posture.AttesterID(posture.DeviceAgent, k) }

// ParsePublicKeyBase64 parses a standard padded base64 SPKI and insists on
// a canonical P-256 key.
func ParsePublicKeyBase64(s string) (*PublicKey, error) {
	k, err := sigs.ParsePublicKeyBase64(s)
	if err != nil {
		return nil, err
	}
	if k.Alg != sigs.ES256 {
		return nil, errNotDeviceKey
	}
	return k, nil
}

// Signer is a device signing key. v0 uses a software key (see package
// keystore); a TPM-backed key in the Microsoft Platform Crypto Provider
// will implement the same interface later, through NewCryptoSigner,
// without any change to statements or the receiver.
type Signer interface {
	// Public and Sign are the shared library's signer: Sign returns the
	// ES256 signature of msg in P1363 low-S encoding.
	sigs.Signer
	// Protection says where the private key lives. Per SPEC section 6.3
	// it belongs in the attester enrollment record; enroll --print-pubkey
	// reports it.
	Protection() KeyProtection
}

// NewCryptoSigner adapts any crypto.Signer holding a P-256 key: an
// in-memory key today, a CNG/TPM key later.
func NewCryptoSigner(cs crypto.Signer, protection KeyProtection) (Signer, error) {
	if _, err := enumName(keyProtectionNames, uint8(protection)); err != nil {
		return nil, fmt.Errorf("key protection: %w", err)
	}
	s, err := sigs.NewSigner(cs)
	if err != nil {
		return nil, err
	}
	if s.Public().Alg != sigs.ES256 {
		return nil, errNotDeviceKey
	}
	return &deviceSigner{Signer: s, protection: protection}, nil
}

// NewSoftwareSigner wraps an in-memory software key. Its evidence strength
// is "software". In-memory keys sign deterministically (RFC 6979).
func NewSoftwareSigner(k *ecdsa.PrivateKey) (Signer, error) {
	return NewCryptoSigner(k, KeySoftware)
}

// GenerateSoftwareKey creates a new P-256 key.
func GenerateSoftwareKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

type deviceSigner struct {
	sigs.Signer
	protection KeyProtection
}

func (s *deviceSigner) Protection() KeyProtection { return s.protection }

// SignEnvelope signs an in-toto payload with the device key.
func SignEnvelope(payload []byte, s Signer) (*Envelope, error) {
	env, err := dsse.Sign(PayloadTypeInToto, payload, s)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return env, nil
}

// VerifyEnvelope checks a device envelope: in-toto payload type, exactly
// one signature, whose keyid names key and which verifies over the PAE.
func VerifyEnvelope(e *Envelope, key *PublicKey) error {
	if e.PayloadType != PayloadTypeInToto {
		return fmt.Errorf("payloadType must be %s", PayloadTypeInToto)
	}
	if len(e.Signatures) != 1 {
		return errors.New("a device envelope carries exactly one signature")
	}
	return e.VerifySignature(0, key)
}

// ParseEnvelope decodes canonical envelope bytes strictly: size-capped,
// then exactly the DSSE keys, canonical base64, at least one signature.
func ParseEnvelope(b []byte) (*Envelope, error) {
	if len(b) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("envelope: larger than %d bytes", MaxEnvelopeBytes)
	}
	return dsse.Parse(b)
}
