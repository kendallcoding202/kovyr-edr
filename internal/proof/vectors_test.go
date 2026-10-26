package proof

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
)

// The shared test vectors (proof/testdata/vectors), read through the
// agent's own entry points: its signer, envelope parser and verifier.
// Passing them shows the device code produces exactly the shared format.

const vectorDir = "../../proof/testdata/vectors/"

func loadJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(vectorDir + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalizationVectors(t *testing.T) {
	var v struct {
		Version      string `json:"version"`
		Canonicalize []struct {
			Name, Input, Canonical, Sha256 string
		} `json:"canonicalize"`
		RejectAsCanonical []struct{ Name, Input string } `json:"reject_as_canonical"`
		RejectAlways      []struct{ Name, Input string } `json:"reject_in_signed_data_always"`
	}
	loadJSON(t, "canonicalization.json", &v)
	if v.Version != canon.Version {
		t.Fatalf("vector version %q, want %q", v.Version, canon.Version)
	}
	if len(v.Canonicalize) == 0 || len(v.RejectAsCanonical) == 0 || len(v.RejectAlways) == 0 {
		t.Fatal("vector file has no cases")
	}
	for _, c := range v.Canonicalize {
		// The canonical form must parse as canonical and hash as stated.
		if _, err := canon.Parse([]byte(c.Canonical)); err != nil {
			t.Errorf("%s: canonical form rejected: %v", c.Name, err)
		}
		h := sha256.Sum256([]byte(c.Canonical))
		if hex.EncodeToString(h[:]) != c.Sha256 {
			t.Errorf("%s: sha256 mismatch", c.Name)
		}
		if c.Input != c.Canonical {
			if _, err := canon.Parse([]byte(c.Input)); err == nil {
				t.Errorf("%s: non-canonical input accepted", c.Name)
			}
		}
	}
	for _, c := range append(v.RejectAsCanonical, v.RejectAlways...) {
		if _, err := canon.Parse([]byte(c.Input)); err == nil {
			t.Errorf("%s: accepted %q", c.Name, c.Input)
		}
	}
}

func TestDSSEVectors(t *testing.T) {
	var v struct {
		PAEHex      string `json:"pae_hex"`
		Payload     string `json:"payload"`
		PayloadType string `json:"payload_type"`
		Signatures  []struct {
			EnvelopeCanonical string `json:"envelope_canonical"`
			Key               struct{ Alg, Keyid, Pkcs8, Spki string }
			Sig               string
		}
		MustReject []struct{ Name, Sig, Spki string } `json:"must_reject"`
	}
	loadJSON(t, "dsse.json", &v)
	payload, _ := base64.StdEncoding.DecodeString(v.Payload)
	if got := hex.EncodeToString(dsse.PAE(v.PayloadType, payload)); got != v.PAEHex {
		t.Fatalf("PAE mismatch:\n got %s\nwant %s", got, v.PAEHex)
	}
	es256 := 0
	for _, s := range v.Signatures {
		if s.Key.Alg != AlgES256 {
			continue // device keys are ES256 only; Ed25519 is for service keys
		}
		es256++
		pub, err := ParsePublicKeyBase64(s.Key.Spki)
		if err != nil {
			t.Fatal(err)
		}
		if pub.KeyID() != s.Key.Keyid {
			t.Errorf("keyid %s, want %s", pub.KeyID(), s.Key.Keyid)
		}
		env, err := ParseEnvelope([]byte(s.EnvelopeCanonical))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyEnvelope(env, pub); err != nil {
			t.Errorf("engine envelope does not verify here: %v", err)
		}
		if string(env.Canonical()) != s.EnvelopeCanonical {
			t.Error("envelope does not re-encode to the same canonical bytes")
		}
		// Deterministic RFC 6979 signing with the same key must reproduce
		// the engine's signature byte for byte.
		der, _ := base64.StdEncoding.DecodeString(s.Key.Pkcs8)
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := NewSoftwareSigner(k.(*ecdsa.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		mine, err := SignEnvelope(payload, signer)
		if err != nil {
			t.Fatal(err)
		}
		if string(mine.Canonical()) != s.EnvelopeCanonical {
			t.Errorf("signing here does not reproduce the engine envelope:\n got %s\nwant %s", mine.Canonical(), s.EnvelopeCanonical)
		}
	}
	if es256 == 0 {
		t.Fatal("no ES256 vector found")
	}
	rejected := 0
	for _, r := range v.MustReject {
		pub, err := ParsePublicKeyBase64(r.Spki)
		if err != nil {
			continue // an Ed25519 case
		}
		sig, _ := base64.StdEncoding.DecodeString(r.Sig)
		if err := pub.Verify(dsse.PAE(v.PayloadType, payload), sig); err == nil {
			t.Errorf("%s: accepted", r.Name)
		}
		rejected++
	}
	if rejected < 3 {
		t.Fatalf("expected at least 3 ES256 must_reject cases, found %d", rejected)
	}
}

// The statement vector's device key, through the agent's signer, must
// reproduce the engine's envelope byte for byte (signing does not depend
// on the predicate type).
func TestStatementVectorEnvelope(t *testing.T) {
	var v struct {
		Payload  string                        `json:"payload_canonical"`
		Envelope string                        `json:"envelope_canonical"`
		Device   struct{ Pkcs8, Keyid string } `json:"device_key"`
	}
	loadJSON(t, "statement.json", &v)
	der, _ := base64.StdEncoding.DecodeString(v.Device.Pkcs8)
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSoftwareSigner(k.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if s.Public().KeyID() != v.Device.Keyid {
		t.Fatal("device key ID differs from the vector")
	}
	env, err := SignEnvelope([]byte(v.Payload), s)
	if err != nil {
		t.Fatal(err)
	}
	if string(env.Canonical()) != v.Envelope {
		t.Fatalf("agent signer does not reproduce the vector envelope:\n got %s\nwant %s", env.Canonical(), v.Envelope)
	}
	parsed, err := ParseEnvelope([]byte(v.Envelope))
	if err != nil || VerifyEnvelope(parsed, s.Public()) != nil {
		t.Fatalf("vector envelope does not parse and verify here: %v", err)
	}
}
