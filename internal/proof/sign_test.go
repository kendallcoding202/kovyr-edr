package proof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

func newTestSigner(t *testing.T) Signer {
	t.Helper()
	k, err := GenerateSoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSoftwareSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := newTestSigner(t)
	payload := []byte(`{"hello":"world"}`)
	env, err := SignEnvelope(payload, s)
	if err != nil {
		t.Fatal(err)
	}
	if s.Protection() != KeySoftware {
		t.Fatalf("software key reports protection %v", s.Protection())
	}
	parsed, err := ParseEnvelope(env.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelope(parsed, s.Public()); err != nil {
		t.Fatalf("own signature does not verify: %v", err)
	}
	// Deterministic: the same payload signs to the same bytes.
	env2, _ := SignEnvelope(payload, s)
	if !bytes.Equal(env.Signatures[0].Sig, env2.Signatures[0].Sig) {
		t.Error("software signatures are not deterministic (RFC 6979)")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	s := newTestSigner(t)
	other := newTestSigner(t)
	payload := []byte(`{"a":1}`)
	env, _ := SignEnvelope(payload, s)

	tampered := *env
	tampered.Payload = []byte(`{"a":2}`)
	if err := VerifyEnvelope(&tampered, s.Public()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("changed payload: got %v, want ErrBadSignature", err)
	}
	if err := VerifyEnvelope(env, other.Public()); err == nil {
		t.Error("verified against the wrong key")
	}
	// Same keyid claimed, but a different key signed.
	forged, _ := SignEnvelope(payload, other)
	forged.Signatures[0].KeyID = s.Public().KeyID()
	if err := VerifyEnvelope(forged, s.Public()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged keyid: got %v", err)
	}
	// A valid signature under a keyid that names some other key.
	misnamed := *env
	misnamed.Signatures = []dsse.Signature{{KeyID: other.Public().KeyID(), Sig: env.Signatures[0].Sig}}
	if err := VerifyEnvelope(&misnamed, s.Public()); err == nil || errors.Is(err, ErrBadSignature) {
		t.Errorf("keyid naming another key: got %v, want a keyid error", err)
	}
	high := *env
	high.Signatures = []dsse.Signature{{KeyID: env.Signatures[0].KeyID, Sig: sigs.HighS(env.Signatures[0].Sig)}}
	if err := VerifyEnvelope(&high, s.Public()); !errors.Is(err, ErrHighS) {
		t.Errorf("high-S twin: got %v, want ErrHighS", err)
	}
	two := *env
	two.Signatures = append(append([]dsse.Signature(nil), env.Signatures...), env.Signatures...)
	if err := VerifyEnvelope(&two, s.Public()); err == nil {
		t.Error("accepted an envelope with two signatures")
	}
	wrongType := *env
	wrongType.PayloadType = "text/plain"
	if err := VerifyEnvelope(&wrongType, s.Public()); err == nil {
		t.Error("accepted a non in-toto payload type")
	}
	// Validly signed, but over another payload type.
	other2, _ := dsse.Sign("text/plain", payload, s)
	if err := VerifyEnvelope(other2, s.Public()); err == nil {
		t.Error("accepted a validly signed envelope of another payload type")
	}
}

func TestOnlyP256KeysAreAccepted(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewSoftwareSigner(k); err == nil {
		t.Fatal("accepted a P-384 key")
	}
	if _, err := NewCryptoSigner(newKey(t), KeyProtection(0)); err == nil {
		t.Fatal("accepted a signer with no key protection label")
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewCryptoSigner(ed, KeySoftware); err == nil {
		t.Fatal("accepted an Ed25519 device key (service keys only)")
	}
	pub, _ := sigs.NewPublicKey(ed.Public())
	if _, err := ParsePublicKeyBase64(pub.Base64()); err == nil {
		t.Fatal("parsed an Ed25519 key as a device key")
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := GenerateSoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseEnvelopeIsStrict(t *testing.T) {
	s := newTestSigner(t)
	env, _ := SignEnvelope([]byte(`{"a":1}`), s)
	good := env.Canonical()
	bad := map[string][]byte{
		"whitespace":    append([]byte(" "), good...),
		"extra field":   bytes.Replace(good, []byte(`{"payload"`), []byte(`{"cmd":"x","payload"`), 1),
		"no sigs":       []byte(`{"payload":"eyJhIjoxfQ==","payloadType":"application/vnd.in-toto+json","signatures":[]}`),
		"bad base64":    []byte(`{"payload":"eyJhIjoxfQ","payloadType":"application/vnd.in-toto+json","signatures":[]}`),
		"too large":     bytes.Repeat([]byte("a"), MaxEnvelopeBytes+1),
		"not an object": []byte(`[]`),
	}
	for name, b := range bad {
		if _, err := ParseEnvelope(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A well-formed envelope over the size cap is refused before parsing.
	big, _ := SignEnvelope(bytes.Repeat([]byte("a"), MaxEnvelopeBytes), s)
	if _, err := dsse.Parse(big.Canonical()); err != nil {
		t.Fatalf("the oversized envelope should be valid DSSE: %v", err)
	}
	if _, err := ParseEnvelope(big.Canonical()); err == nil {
		t.Error("accepted an envelope over MaxEnvelopeBytes")
	}
}
