// Package tsa abstracts timestamp authorities: outside clocks that sign
// "this digest existed at time T".
//
// Production uses RFC 3161 timestamp authorities (for example Sigstore's
// open-source timestamp-authority plus a commercial TSA). This prototype
// ships only SimulatedAuthority, a local Ed25519 key that signs a small JSON
// token. Tokens carry their kind, so swapping in RFC 3161 means adding one
// Authority (an HTTP client) and one TokenVerifier (CMS SignedData checks);
// nothing else in the engine changes.
package tsa

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

// Token kinds.
const (
	KindSimulated = "simulated-tsa/v1"
	KindRFC3161   = "rfc3161" // {"kind":"rfc3161","token":"<base64 DER TimeStampToken>"}
)

// TimeLayout is the only timestamp format used anywhere in signed data.
const TimeLayout = "2006-01-02T15:04:05Z"

// Authority issues timestamp tokens over a SHA-256 imprint. Real
// authorities are remote services, so Timestamp takes a context.
type Authority interface {
	Name() string
	Timestamp(ctx context.Context, imprint [32]byte) (map[string]any, error)
}

// Trusted describes a TSA a verifier trusts.
type Trusted struct {
	Name      string
	Kind      string
	PublicKey *sigs.PublicKey // simulated kind; RFC 3161 would hold roots
}

// Verified is the result of checking one token.
type Verified struct {
	TSA     string
	GenTime time.Time
}

// SimulatedAuthority is a local stand-in for an RFC 3161 TSA. Its tokens
// say "simulated" in their kind; verifiers report them as simulated.
type SimulatedAuthority struct {
	name   string
	signer sigs.Signer
	clock  func() time.Time
	mu     sync.Mutex
	serial int64
}

// NewSimulated creates a simulated TSA. clock lets tests and the demo
// generator control time.
func NewSimulated(name string, signer sigs.Signer, clock func() time.Time, firstSerial int64) (*SimulatedAuthority, error) {
	if signer.Public().Alg != sigs.Ed25519 {
		return nil, errors.New("simulated TSA keys are Ed25519")
	}
	return &SimulatedAuthority{name: name, signer: signer, clock: clock, serial: firstSerial}, nil
}

func (a *SimulatedAuthority) Name() string { return a.name }

// SetClock replaces the clock (the demo generator moves time forward).
func (a *SimulatedAuthority) SetClock(c func() time.Time) { a.clock = c }

// SimulatedMessage is the exact byte string a simulated TSA signs.
func SimulatedMessage(tst map[string]any) ([]byte, error) {
	b, err := canon.Encode(tst)
	if err != nil {
		return nil, err
	}
	return append([]byte(KindSimulated+"\n"), b...), nil
}

func (a *SimulatedAuthority) Timestamp(ctx context.Context, imprint [32]byte) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := a.clock().UTC()
	// Serials follow the clock (milliseconds) so they are unique and, for
	// the reproducible demo, independent of how many tokens came before.
	a.mu.Lock()
	serial := now.UnixMilli()
	if serial <= a.serial {
		serial = a.serial + 1
	}
	a.serial = serial
	a.mu.Unlock()
	tst := map[string]any{
		"gen_time": now.Format(TimeLayout),
		"imprint":  hex.EncodeToString(imprint[:]),
		"serial":   serial,
		"tsa":      a.name,
	}
	msg, err := SimulatedMessage(tst)
	if err != nil {
		return nil, err
	}
	sig, err := a.signer.Sign(msg)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kind": KindSimulated,
		"sig":  base64.StdEncoding.EncodeToString(sig),
		"tst":  tst,
	}, nil
}

// Verify checks one token against the trusted TSAs and the expected
// imprint.
func Verify(token map[string]any, imprint [32]byte, trusted []Trusted) (Verified, error) {
	kind, _ := token["kind"].(string)
	switch kind {
	case KindSimulated:
		return verifySimulated(token, imprint, trusted)
	case KindRFC3161:
		return Verified{}, errors.New("RFC 3161 tokens are specified but not verified by this prototype")
	}
	return Verified{}, fmt.Errorf("unknown timestamp token kind %q", kind)
}

func verifySimulated(token map[string]any, imprint [32]byte, trusted []Trusted) (Verified, error) {
	if len(token) != 3 {
		return Verified{}, errors.New("timestamp token must have exactly kind, sig and tst")
	}
	tst, ok := token["tst"].(map[string]any)
	if !ok || len(tst) != 4 {
		return Verified{}, errors.New("timestamp token tst must have exactly gen_time, imprint, serial and tsa")
	}
	name, _ := tst["tsa"].(string)
	var t *Trusted
	for i := range trusted {
		if trusted[i].Name == name && trusted[i].Kind == KindSimulated {
			t = &trusted[i]
		}
	}
	if t == nil {
		return Verified{}, fmt.Errorf("timestamp from untrusted authority %q", name)
	}
	sigB64, _ := token["sig"].(string)
	sig, err := sigs.DecodeBase64(sigB64)
	if err != nil {
		return Verified{}, fmt.Errorf("timestamp signature: %w", err)
	}
	msg, err := SimulatedMessage(tst)
	if err != nil {
		return Verified{}, err
	}
	if err := t.PublicKey.Verify(msg, sig); err != nil {
		return Verified{}, fmt.Errorf("timestamp from %s: %w", name, err)
	}
	if got, _ := tst["imprint"].(string); got != hex.EncodeToString(imprint[:]) {
		return Verified{}, fmt.Errorf("timestamp from %s is for a different document", name)
	}
	if _, ok := tst["serial"].(int64); !ok {
		return Verified{}, errors.New("timestamp serial is not an integer")
	}
	gs, _ := tst["gen_time"].(string)
	gt, err := ParseTime(gs)
	if err != nil {
		return Verified{}, fmt.Errorf("timestamp from %s: %w", name, err)
	}
	return Verified{TSA: name, GenTime: gt}, nil
}

// ParseTime parses the canonical UTC timestamp format strictly.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil || t.Format(TimeLayout) != s {
		return time.Time{}, fmt.Errorf("bad timestamp %q", s)
	}
	return t, nil
}

// Imprint is the digest a TSA is asked to sign for a log entry: SHA-256 of
// the canonical DSSE envelope, so the token covers the signatures too.
func Imprint(canonicalEnvelope []byte) [32]byte { return sha256.Sum256(canonicalEnvelope) }
