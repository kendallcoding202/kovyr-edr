package proof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
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
	if err := parsed.Verify(s.Public()); err != nil {
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
	if err := tampered.Verify(s.Public()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("changed payload: got %v, want ErrBadSignature", err)
	}
	if err := env.Verify(other.Public()); err == nil {
		t.Error("verified against the wrong key")
	}
	// Same keyid claimed, but a different key signed.
	forged, _ := SignEnvelope(payload, other)
	forged.Signatures[0].KeyID = s.Public().KeyID()
	if err := forged.Verify(s.Public()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged keyid: got %v", err)
	}
	high := *env
	high.Signatures = []Signature{{KeyID: env.Signatures[0].KeyID, Sig: highS(env.Signatures[0].Sig)}}
	if err := high.Verify(s.Public()); !errors.Is(err, ErrHighS) {
		t.Errorf("high-S twin: got %v, want ErrHighS", err)
	}
	two := *env
	two.Signatures = append(append([]Signature(nil), env.Signatures...), env.Signatures...)
	if err := two.Verify(s.Public()); err == nil {
		t.Error("accepted an envelope with two signatures")
	}
	wrongType := *env
	wrongType.PayloadType = "text/plain"
	if err := wrongType.Verify(s.Public()); err == nil {
		t.Error("accepted a non in-toto payload type")
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
}
