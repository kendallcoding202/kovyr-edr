package tlog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

type rig struct {
	now    time.Time
	srv    *Server
	tenant sigs.Signer
	dev    sigs.Signer
	devID  string
	prev   posture.Digest
}

func newRig(t *testing.T) *rig {
	r := &rig{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return r.now }
	seed := sha256.Sum256([]byte("log"))
	l, _ := NewLog("example.com/test-log", ed25519.NewKeyFromSeed(seed[:]), clock)
	var tsas []Authority
	for _, n := range []string{"a.example", "b.example"} {
		cs, _ := sigs.GenerateKey(sigs.Ed25519)
		s, _ := sigs.NewSigner(cs)
		a, _ := tsa.NewSimulated(n, s, clock, 0)
		tsas = append(tsas, a)
	}
	r.srv = NewServer(l, tsas, clock, rand.Reader)
	a, _ := sigs.GenerateKey(sigs.ES256)
	b, _ := sigs.GenerateKey(sigs.ES256)
	r.tenant, _ = sigs.NewSigner(a)
	r.dev, _ = sigs.NewSigner(b)

	tid := posture.TenantID(r.tenant.Public())
	n, _ := r.srv.IssueNonce(tid)
	salt, _ := posture.NewSalt()
	g, _ := posture.BuildTenantGenesis(r.tenant.Public(), posture.Digest{1}, r.now, n, salt)
	env, _ := posture.Sign(g, r.tenant)
	if _, err := r.srv.Submit(ctx, env); err != nil {
		t.Fatal(err)
	}
	r.devID = posture.AttesterID(posture.DeviceAgent, r.dev.Public())
	n, _ = r.srv.IssueNonce(r.devID)
	e, _ := posture.BuildAttesterEnrollment(r.tenant.Public(), r.dev.Public(), posture.EnrollmentInfo{Kind: posture.DeviceAgent,
		KeyProtection: "software", KeyAttestation: "none", Method: "enrollment_code", DeviceClass: "laptop", Platform: "windows",
		DeviceNumber: 1, StaffRole: "none"}, r.now, n, salt)
	env, _ = posture.Sign(e, r.tenant, r.dev)
	if _, err := r.srv.Submit(ctx, env); err != nil {
		t.Fatal(err)
	}
	r.prev = posture.PayloadDigest(e)
	return r
}

type Authority = tsa.Authority

func (r *rig) statement(t *testing.T, seq uint32, observed time.Time) []byte {
	n, err := r.srv.IssueNonce(r.devID)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := posture.NewSalt()
	p, err := posture.BuildDevice(posture.Header{TenantKey: r.tenant.Public(), Attester: r.dev.Public(), Kind: posture.DeviceAgent,
		Seq: seq, Prev: r.prev, Nonce: n, Salt: salt, ObservedAt: observed}, posture.DeviceChecks{DiskEncryption: "on", OSPatch: "current",
		FirewallOn: true, ScreenLockOn: true, ScreenLockMaxIdleMin: 10, EDRRunning: true, EDRKind: "defender", LocalAdminCount: 1,
		HeartbeatIntervalS: 300, Heartbeats24h: 288})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIngestChecks(t *testing.T) {
	r := newRig(t)
	p := r.statement(t, 1, r.now)
	env, _ := posture.Sign(p, r.dev)
	if _, err := r.srv.Submit(ctx, env); err != nil {
		t.Fatal(err)
	}
	r.prev = posture.PayloadDigest(p)
	// Replaying the same envelope: nonce already used.
	if _, err := r.srv.Submit(ctx, env); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay accepted: %v", err)
	}
	// Old sequence number.
	old, _ := posture.Sign(r.statement(t, 1, r.now), r.dev)
	if _, err := r.srv.Submit(ctx, old); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("old sequence accepted: %v", err)
	}
	// Backdated: claims to be from yesterday.
	back, _ := posture.Sign(r.statement(t, 2, r.now.Add(-24*time.Hour)), r.dev)
	if _, err := r.srv.Submit(ctx, back); err == nil || !strings.Contains(err.Error(), "backdated") {
		t.Fatalf("backdated statement accepted: %v", err)
	}
	// Expired nonce.
	stale := r.statement(t, 2, r.now)
	r.now = r.now.Add(NonceLifetime + time.Minute)
	se, _ := posture.Sign(stale, r.dev)
	if _, err := r.srv.Submit(ctx, se); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired nonce accepted: %v", err)
	}
	// Signed by an unenrolled key.
	cs, _ := sigs.GenerateKey(sigs.ES256)
	other, _ := sigs.NewSigner(cs)
	forged, _ := posture.Sign(r.statement(t, 2, r.now), other)
	if _, err := r.srv.Submit(ctx, forged); err == nil {
		t.Fatal("forged statement accepted")
	}
	// A fresh, correct statement is still accepted.
	okp := r.statement(t, 2, r.now)
	ok, _ := posture.Sign(okp, r.dev)
	ev, err := r.srv.Submit(ctx, ok)
	if err != nil {
		t.Fatal(err)
	}
	if ev.LostBefore != 0 {
		t.Fatalf("contiguous report recorded %d lost reports", ev.LostBefore)
	}
	r.prev = posture.PayloadDigest(okp)
	// A wrong prev on the next contiguous report is refused.
	r.prev = posture.Digest{9}
	badPrev := r.statement(t, 3, r.now)
	be, _ := posture.Sign(badPrev, r.dev)
	if _, err := r.srv.Submit(ctx, be); err == nil || !strings.Contains(err.Error(), "prev") {
		t.Fatalf("broken prev accepted: %v", err)
	}
}

// SPEC 8: reports 3 and 4 never arrive. Ingest accepts report 5 and
// records the hole, so one lost upload cannot lock the device out.
func TestIngestAcceptsALostUploadAndRecordsTheGap(t *testing.T) {
	r := newRig(t)
	for seq := uint32(1); seq <= 2; seq++ {
		p := r.statement(t, seq, r.now)
		env, _ := posture.Sign(p, r.dev)
		if _, err := r.srv.Submit(ctx, env); err != nil {
			t.Fatal(err)
		}
		r.prev = posture.PayloadDigest(p)
	}
	// Reports 3 and 4 are signed (each spends its number) but lost.
	for seq := uint32(3); seq <= 4; seq++ {
		r.prev = posture.PayloadDigest(r.statement(t, seq, r.now))
	}
	p5 := r.statement(t, 5, r.now)
	env, _ := posture.Sign(p5, r.dev)
	ev, err := r.srv.Submit(ctx, env)
	if err != nil {
		t.Fatalf("a seq jump locked the device out: %v", err)
	}
	if ev.LostBefore != 2 {
		t.Fatalf("lost reports recorded as %d, want 2", ev.LostBefore)
	}
	if a := r.srv.Attester(posture.TenantID(r.tenant.Public()), r.devID); a.LastSeq != 5 {
		t.Fatalf("last seq %d, want 5", a.LastSeq)
	}
	// The chain continues from report 5.
	r.prev = posture.PayloadDigest(p5)
	p6 := r.statement(t, 6, r.now)
	env6, _ := posture.Sign(p6, r.dev)
	if ev, err := r.srv.Submit(ctx, env6); err != nil || ev.LostBefore != 0 {
		t.Fatalf("report 6 after the gap: %v", err)
	}
	// A lost report that turns up later is a replay of an old number.
	r.prev = posture.Digest{}
	late, _ := posture.Sign(r.statement(t, 4, r.now), r.dev)
	if _, err := r.srv.Submit(ctx, late); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("an old seq was accepted after the gap: %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	r := newRig(t)
	p := r.statement(t, 1, r.now)
	env, _ := posture.Sign(p, r.dev)
	if _, err := r.srv.Submit(ctx, env); err != nil {
		t.Fatal(err)
	}
	if _, err := r.srv.Log.SignCheckpoint(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := r.srv.Save(dir); err != nil {
		t.Fatal(err)
	}
	s2, err := Load(dir, nil, nil, func() time.Time { return r.now }, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Log.Size() != r.srv.Log.Size() || s2.Log.Latest() != r.srv.Log.Latest() {
		t.Fatal("log did not round-trip")
	}
	pt, err := ReadPublic(dir + "/public")
	if err != nil || pt.Size != 3 {
		t.Fatalf("public tiles: %v", err)
	}
}

func TestTilePath(t *testing.T) {
	for n, want := range map[uint64]string{0: "000", 7: "007", 1234: "x001/234", 1234067: "x001/x234/067"} {
		if got := TilePath(n); got != want {
			t.Errorf("%d: %s want %s", n, got, want)
		}
	}
}

var ctx = context.Background()
