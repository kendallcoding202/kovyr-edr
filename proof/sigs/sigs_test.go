package sigs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestRoundTripBothAlgorithms(t *testing.T) {
	for _, alg := range []Alg{ES256, Ed25519} {
		cs, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewSigner(cs)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("statement bytes")
		sig, err := s.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 64 {
			t.Fatalf("%s: signature length %d", alg, len(sig))
		}
		pub, err := ParsePublicKey(s.Public().SPKI)
		if err != nil {
			t.Fatal(err)
		}
		if err := pub.Verify(msg, sig); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if err := pub.Verify([]byte("statement bytez"), sig); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s: modified message accepted: %v", alg, err)
		}
		// A signature from a different key must not verify.
		other, _ := GenerateKey(alg)
		os, _ := NewSigner(other)
		forged, _ := os.Sign(msg)
		if err := pub.Verify(msg, forged); err == nil {
			t.Fatalf("%s: signature by another key accepted", alg)
		}
	}
}

func TestES256EncodingRules(t *testing.T) {
	cs, _ := GenerateKey(ES256)
	s, _ := NewSigner(cs)
	msg := []byte("hello")
	sig, _ := s.Sign(msg)

	// Deterministic for in-memory keys (RFC 6979), so demo data reproduces.
	sig2, _ := s.Sign(msg)
	if !bytes.Equal(sig, sig2) {
		t.Fatal("in-memory ECDSA signing is not deterministic")
	}

	// High-S twin is mathematically valid but must be rejected.
	if err := s.Public().Verify(msg, HighS(sig)); !errors.Is(err, ErrHighS) {
		t.Fatalf("high-S accepted: %v", err)
	}

	// DER must be converted, never accepted directly.
	der, err := ECDSAToDER(sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Public().Verify(msg, der); !errors.Is(err, ErrSigEncoding) {
		t.Fatalf("DER accepted: %v", err)
	}
	back, err := ECDSAFromDER(der)
	if err != nil || !bytes.Equal(back, sig) {
		t.Fatal("DER round trip failed")
	}

	// A raw DER signature from the standard library (possibly high-S)
	// normalizes to a valid low-S P1363 signature.
	digest := sha256.Sum256(msg)
	rawDER, _ := ecdsa.SignASN1(rand.Reader, cs.(*ecdsa.PrivateKey), digest[:])
	p1363, err := ECDSAFromDER(rawDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Public().Verify(msg, p1363); err != nil {
		t.Fatal(err)
	}
	if _, err := ECDSAFromDER(append(rawDER, 0)); err == nil {
		t.Fatal("trailing bytes after DER accepted")
	}
}

func TestPublicKeyCanonical(t *testing.T) {
	cs, _ := GenerateKey(ES256)
	pub, _ := NewPublicKey(cs.Public())
	if len(pub.SPKI) != 91 {
		t.Fatalf("P-256 SPKI length %d", len(pub.SPKI))
	}
	ed, _ := GenerateKey(Ed25519)
	edPub, _ := NewPublicKey(ed.Public())
	if len(edPub.SPKI) != 44 {
		t.Fatalf("Ed25519 SPKI length %d", len(edPub.SPKI))
	}
	if _, err := ParsePublicKey(append(append([]byte(nil), pub.SPKI...), 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := ParsePublicKeyBase64(pub.Base64() + "\n"); err == nil {
		t.Fatal("non-canonical base64 accepted")
	}
}
