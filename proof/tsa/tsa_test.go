package tsa

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

func newTSA(t *testing.T, name string, at time.Time) (*SimulatedAuthority, Trusted) {
	cs, _ := sigs.GenerateKey(sigs.Ed25519)
	s, _ := sigs.NewSigner(cs)
	a, err := NewSimulated(name, s, func() time.Time { return at }, 0)
	if err != nil {
		t.Fatal(err)
	}
	return a, Trusted{Name: name, Kind: KindSimulated, PublicKey: s.Public()}
}

func TestSimulatedTokens(t *testing.T) {
	at := time.Date(2026, 10, 14, 13, 58, 0, 0, time.UTC)
	a, trustA := newTSA(t, "tsa-a.example/sim", at)
	_, trustB := newTSA(t, "tsa-b.example/sim", at)
	imprint := Imprint([]byte("envelope"))
	tok, err := a.Timestamp(context.Background(), imprint)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through canonical JSON, as tokens do inside log entries.
	v, err := canon.Parse(canon.MustEncode(tok))
	if err != nil {
		t.Fatal(err)
	}
	tok = v.(map[string]any)
	got, err := Verify(tok, imprint, []Trusted{trustA, trustB})
	if err != nil || !got.GenTime.Equal(at) {
		t.Fatalf("verify: %v %v", err, got)
	}
	if _, err := Verify(tok, Imprint([]byte("other envelope")), []Trusted{trustA}); err == nil {
		t.Fatal("token accepted for a different document")
	}
	if _, err := Verify(tok, imprint, []Trusted{trustB}); err == nil {
		t.Fatal("token from untrusted TSA accepted")
	}
	// Moving the time back (backdating the token itself) breaks the signature.
	tst := tok["tst"].(map[string]any)
	tst["gen_time"] = "2026-10-12T14:00:00Z"
	if _, err := Verify(tok, imprint, []Trusted{trustA}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("edited gen_time accepted: %v", err)
	}
	if _, err := Verify(map[string]any{"kind": KindRFC3161, "token": "AA=="}, imprint, nil); err == nil {
		t.Fatal("unverified RFC 3161 token accepted")
	}
}
