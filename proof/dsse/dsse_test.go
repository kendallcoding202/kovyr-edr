package dsse

import (
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

// Vector from the DSSE protocol specification.
func TestPAEVector(t *testing.T) {
	got := string(PAE("http://example.com/HelloWorld", []byte("hello world")))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSignVerifyAndForgery(t *testing.T) {
	for _, alg := range []sigs.Alg{sigs.ES256, sigs.Ed25519} {
		cs, _ := sigs.GenerateKey(alg)
		s, _ := sigs.NewSigner(cs)
		env, err := Sign(PayloadTypeInToto, []byte(`{"a":1}`), s)
		if err != nil {
			t.Fatal(err)
		}
		round, err := Parse(env.Canonical())
		if err != nil {
			t.Fatal(err)
		}
		if err := round.VerifySignature(0, s.Public()); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}

		tampered := *round
		tampered.Payload = []byte(`{"a":2}`)
		if tampered.VerifySignature(0, s.Public()) == nil {
			t.Fatalf("%s: tampered payload accepted", alg)
		}
		retyped := *round
		retyped.PayloadType = "text/plain"
		if retyped.VerifySignature(0, s.Public()) == nil {
			t.Fatalf("%s: changed payloadType accepted", alg)
		}

		other, _ := sigs.GenerateKey(alg)
		os, _ := sigs.NewSigner(other)
		if round.VerifySignature(0, os.Public()) == nil {
			t.Fatalf("%s: wrong key accepted", alg)
		}
		// A forger who re-signs with their own key but keeps the victim's
		// keyid still fails: the signature only verifies under their key.
		forged, _ := Sign(PayloadTypeInToto, []byte(`{"a":2}`), os)
		forged.Signatures[0].KeyID = s.Public().KeyID()
		if forged.VerifySignature(0, s.Public()) == nil {
			t.Fatalf("%s: forged signature accepted", alg)
		}
	}
}

func TestParseRejectsExtraFields(t *testing.T) {
	bad := `{"extra":"x","payload":"e30=","payloadType":"t","signatures":[{"keyid":"k","sig":"AA=="}]}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("extra envelope field accepted")
	}
	noSig := `{"payload":"e30=","payloadType":"t","signatures":[]}`
	if _, err := Parse([]byte(noSig)); err == nil {
		t.Fatal("unsigned envelope accepted")
	}
}

// A hostile container must not be able to crash the verifier with
// strings that have no canonical encoding.
func TestFromValueRejectsNonCanonicalStrings(t *testing.T) {
	v := map[string]any{"payload": "e30=", "payloadType": "t", "signatures": []any{map[string]any{"keyid": "ké", "sig": "AA=="}}}
	if _, err := FromValue(v); err == nil {
		t.Fatal("non-ASCII keyid accepted")
	}
}
