package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

type fakeTransport struct {
	mu        sync.Mutex
	nonces    int
	devices   []string
	chalErr   error
	posted    [][]byte
	postErr   func(n int) error // n counts post attempts from 1
	attempts  int
	lastNonce proof.Nonce
}

func (f *fakeTransport) Challenge(ctx context.Context, device string) (proof.Nonce, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices = append(f.devices, device)
	if f.chalErr != nil {
		return proof.Nonce{}, f.chalErr
	}
	f.nonces++
	n, _ := proof.NewAgentNonce()
	f.lastNonce = n
	return n, nil
}

func (f *fakeTransport) PostHeartbeat(ctx context.Context, env []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.postErr != nil {
		if err := f.postErr(f.attempts); err != nil {
			return err
		}
	}
	f.posted = append(f.posted, append([]byte(nil), env...))
	return nil
}

func newSigner(t *testing.T) proof.Signer {
	k, err := proof.GenerateSoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := proof.NewSoftwareSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newAgent(t *testing.T, dir string, s proof.Signer, tr Transport) *Agent {
	t.Helper()
	a, err := New(Config{Dir: dir}, s, checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func decode(t *testing.T, env []byte) (*proof.Envelope, *proof.Statement) {
	t.Helper()
	e, err := proof.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	st, err := proof.ValidateStatement(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return e, st
}

func TestBeatsFormAChainAcrossRestarts(t *testing.T) {
	dir, s, tr := t.TempDir(), newSigner(t), &fakeTransport{}
	a := newAgent(t, dir, s, tr)
	for i := 0; i < 3; i++ {
		if _, err := a.Beat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// Restart: a new Agent continues the same chain.
	a = newAgent(t, dir, s, tr)
	if _, err := a.Beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(tr.posted) != 4 || a.QueueLen() != 0 {
		t.Fatalf("posted %d, queued %d", len(tr.posted), a.QueueLen())
	}
	for _, d := range tr.devices {
		if d != proof.DeviceID(s.Public()) {
			t.Fatalf("challenge asked for %q, want this device's ID", d)
		}
	}
	prev := proof.GenesisPrev
	for i, env := range tr.posted {
		e, st := decode(t, env)
		if err := proof.VerifyEnvelope(e, s.Public()); err != nil {
			t.Fatal(err)
		}
		if st.Seq != uint32(i+1) {
			t.Errorf("statement %d has seq %d (sent oldest first?)", i, st.Seq)
		}
		if st.Prev != prev {
			t.Errorf("seq %d: prev does not link to the previous payload", st.Seq)
		}
		if st.SensorHealth != SensorHealth() || st.AgentVersion != Version {
			t.Errorf("seq %d: header %+v", st.Seq, st)
		}
		prev = proof.PayloadDigest(e.Payload)
	}
}

// SPEC section 8: a report needs a server nonce. Offline, the agent makes
// no statement and spends no seq; statements whose upload failed wait in
// the queue and go out oldest first.
func TestOfflineMakesNoStatementAndSpendsNoSeq(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	tr := &fakeTransport{chalErr: errors.New("offline")}
	a := newAgent(t, dir, s, tr)
	for i := 0; i < 3; i++ {
		if st, err := a.Beat(context.Background()); !errors.Is(err, ErrNoChallenge) || st != nil {
			t.Fatalf("offline beat: %v, %v", st, err)
		}
	}
	if a.State().Seq != 0 || a.QueueLen() != 0 {
		t.Fatalf("offline beats spent seq %d / queued %d", a.State().Seq, a.QueueLen())
	}
	// Challenges work but uploads fail: statements queue up.
	tr.chalErr = nil
	tr.postErr = func(int) error { return errors.New("upload failed") }
	for i := 0; i < 3; i++ {
		if _, err := a.Beat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Flush(context.Background()); err == nil {
		t.Fatal("flush succeeded while uploads fail")
	}
	if a.QueueLen() != 3 {
		t.Fatalf("queue %d, want 3 kept for retry", a.QueueLen())
	}
	tr.postErr = nil
	if err := a.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, env := range tr.posted {
		_, st := decode(t, env)
		if st.Seq != uint32(i+1) {
			t.Errorf("out of order: position %d has seq %d", i, st.Seq)
		}
	}
	if len(tr.posted) != 3 {
		t.Fatalf("posted %d", len(tr.posted))
	}
	_, last := decode(t, tr.posted[2])
	if last.Nonce != tr.lastNonce {
		t.Error("statement does not carry the server nonce")
	}
}

func TestRefusedEnvelopesAreDroppedNotRetriedForever(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	tr := &fakeTransport{postErr: func(n int) error {
		if n == 1 {
			return ErrRefused
		}
		return nil
	}}
	a := newAgent(t, dir, s, tr)
	a.Beat(context.Background())
	a.Beat(context.Background())
	if err := a.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.QueueLen() != 0 || len(tr.posted) != 1 {
		t.Fatalf("queue %d posted %d", a.QueueLen(), len(tr.posted))
	}
}

func TestCrashBetweenQueueAndStateNeverReusesASeq(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	tr := &fakeTransport{postErr: func(int) error { return errors.New("offline") }}
	a := newAgent(t, dir, s, tr)
	a.Beat(context.Background())
	a.Beat(context.Background())
	// Simulate a crash after seq 2 was queued but before its state was
	// saved: roll the state back to seq 1.
	_, env1, _, _ := a.queue.Oldest()
	e1, _ := decode(t, env1)
	d := proof.PayloadDigest(e1.Payload)
	if err := saveState(dir, ChainState{KeyID: s.Public().KeyID(), Seq: 1, Prev: hex.EncodeToString(d[:])}); err != nil {
		t.Fatal(err)
	}
	a = newAgent(t, dir, s, tr)
	if a.State().Seq != 2 {
		t.Fatalf("after restart the chain head is %d, want 2 (recovered from the queue)", a.State().Seq)
	}
	st, err := a.Beat(context.Background())
	if err != nil || st.Seq != 3 {
		t.Fatalf("next seq %v, %v; want 3", st, err)
	}
}

func TestStateOfAnotherKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	tr := &fakeTransport{}
	a := newAgent(t, dir, newSigner(t), tr)
	a.Beat(context.Background())
	if _, err := New(Config{Dir: dir}, newSigner(t), checks.NewRunner(checks.HealthyFake()), tr); err == nil {
		t.Fatal("a new key silently continued another key's chain")
	}
}

func TestIntervalBounds(t *testing.T) {
	for _, d := range []time.Duration{time.Second, 59 * time.Second, 61*time.Minute + time.Second, 90500 * time.Millisecond} {
		if _, err := New(Config{Dir: t.TempDir(), Interval: d}, newSigner(t), checks.NewRunner(checks.HealthyFake()), &fakeTransport{}); err == nil {
			t.Errorf("interval %v accepted", d)
		}
	}
}

// A hostile challenge (one carrying a command) changes nothing: it is not
// a nonce, so no statement is made, no seq is spent and nothing is written.
func TestHostileChallengeIsIgnored(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	_, err := ParseChallenge([]byte(`{"command":"isolate","nonce":"00112233445566778899aabbccddeeff"}`))
	if !errors.Is(err, ErrNotANonce) {
		t.Fatalf("parse: %v", err)
	}
	tr := &fakeTransport{chalErr: err}
	a := newAgent(t, dir, s, tr)
	if _, berr := a.Beat(context.Background()); !errors.Is(berr, ErrNoChallenge) {
		t.Fatalf("beat: %v", berr)
	}
	if a.State().Seq != 0 || a.QueueLen() != 0 {
		t.Error("a hostile challenge led to a statement")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "queue" {
			t.Errorf("unexpected file %s written", e.Name())
		}
	}
}

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	waits  []time.Duration
	onWait func(n int)
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	if d < 0 {
		d = 0
	}
	c.now = c.now.Add(d)
	c.waits = append(c.waits, d)
	n := len(c.waits)
	c.mu.Unlock()
	if c.onWait != nil {
		c.onWait(n)
	}
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

func TestRunLoopBeatsOnScheduleAndBacksOff(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	tr := &fakeTransport{postErr: func(n int) error {
		if n <= 4 {
			return errors.New("server down")
		}
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	clk.onWait = func(n int) {
		if n >= 40 {
			cancel()
		}
	}
	a, err := New(Config{Dir: dir, Clock: clk, Backoff: Backoff{Base: 5 * time.Second, Rand: func() float64 { return 0 }}},
		s, checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	// Retries after the first beat: 2.5s, 5s, 10s, 20s (low jitter), then
	// success; every later wait is a full interval.
	want := []time.Duration{2500 * time.Millisecond, 5 * time.Second, 10 * time.Second, 20 * time.Second}
	for i, w := range want {
		if clk.waits[i] != w {
			t.Errorf("wait %d is %v, want %v", i, clk.waits[i], w)
		}
	}
	for i, w := range clk.waits[len(want)+1 : 30] {
		if w != DefaultInterval {
			t.Errorf("steady-state wait %d is %v, want %v", i, w, DefaultInterval)
		}
	}
	for _, w := range clk.waits {
		if w < time.Second {
			t.Fatalf("hot loop: waited only %v", w)
		}
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.posted) < 30 {
		t.Fatalf("only %d heartbeats delivered", len(tr.posted))
	}
	for i, env := range tr.posted {
		_, st := decode(t, env)
		if st.Seq != uint32(i+1) {
			t.Fatalf("delivery %d has seq %d", i, st.Seq)
		}
	}
}

func TestRunLoopRetriesAMissedChallengeSoon(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	tr := &fakeTransport{chalErr: errors.New("offline")}
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	clk.onWait = func(n int) {
		if n == 3 {
			tr.mu.Lock()
			tr.chalErr = nil // back online after three failed tries
			tr.mu.Unlock()
		}
		if n >= 6 {
			cancel()
		}
	}
	a, err := New(Config{Dir: dir, Clock: clk, Backoff: Backoff{Base: 5 * time.Second, Rand: func() float64 { return 0 }}},
		s, checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	a.Run(ctx)
	// Three missed challenges retried after 2.5s, 5s, 10s, not 15 minutes.
	for i, w := range []time.Duration{2500 * time.Millisecond, 5 * time.Second, 10 * time.Second} {
		if clk.waits[i] != w {
			t.Errorf("wait %d is %v, want %v", i, clk.waits[i], w)
		}
	}
	if clk.waits[3] != DefaultInterval {
		t.Errorf("after a successful beat the wait is %v, want the interval", clk.waits[3])
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.posted) == 0 {
		t.Fatal("no heartbeat after coming back online")
	}
	if _, st := decode(t, tr.posted[0]); st.Seq != 1 {
		t.Errorf("first delivered seq is %d; failed tries must not spend seqs", st.Seq)
	}
}

func TestQueueFilesHoldOnlyEnvelopes(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	a := newAgent(t, dir, s, &fakeTransport{postErr: func(int) error { return errors.New("down") }})
	a.Beat(context.Background())
	files, _ := filepath.Glob(filepath.Join(dir, "queue", "*"))
	if len(files) != 1 {
		t.Fatalf("queue files %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if _, err := proof.ParseEnvelope(b); err != nil {
		t.Fatalf("queue file is not a canonical envelope: %v", err)
	}
}
