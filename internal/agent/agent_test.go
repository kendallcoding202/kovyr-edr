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
	chalErr   error
	posted    [][]byte
	postErr   func(n int) error // n counts post attempts from 1
	attempts  int
	lastNonce proof.Nonce
}

func (f *fakeTransport) Challenge(ctx context.Context) (proof.Nonce, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	st, err := proof.ValidateSensorHealth(e.Payload)
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
	prev := proof.GenesisPrev
	for i, env := range tr.posted {
		e, st := decode(t, env)
		if err := e.Verify(s.Public()); err != nil {
			t.Fatal(err)
		}
		if st.Seq != uint32(i+1) {
			t.Errorf("statement %d has seq %d (sent oldest first?)", i, st.Seq)
		}
		if st.Prev != prev {
			t.Errorf("seq %d: prev does not link to the previous payload", st.Seq)
		}
		if st.NonceSource != proof.NonceServer || st.KeyProtection != proof.KeySoftware || st.HeartbeatIntervalS != 900 {
			t.Errorf("seq %d: header %+v", st.Seq, st)
		}
		prev = proof.PayloadDigest(e.Payload)
	}
}

func TestOfflineBeatsUseAgentNoncesAndWaitInTheQueue(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	tr := &fakeTransport{chalErr: errors.New("offline"), postErr: func(int) error { return errors.New("offline") }}
	a := newAgent(t, dir, s, tr)
	for i := 0; i < 3; i++ {
		st, err := a.Beat(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if st.NonceSource != proof.NonceAgent {
			t.Errorf("offline statement claims nonce source %v", st.NonceSource)
		}
	}
	if err := a.Flush(context.Background()); err == nil {
		t.Fatal("flush succeeded while offline")
	}
	if a.QueueLen() != 3 {
		t.Fatalf("queue %d, want 3 kept for retry", a.QueueLen())
	}
	// Back online: all three go out, oldest first, then a challenged one.
	tr.chalErr, tr.postErr = nil, nil
	if _, err := a.Beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(tr.posted) != 4 {
		t.Fatalf("posted %d", len(tr.posted))
	}
	for i, env := range tr.posted {
		_, st := decode(t, env)
		if st.Seq != uint32(i+1) {
			t.Errorf("out of order: position %d has seq %d", i, st.Seq)
		}
	}
	_, last := decode(t, tr.posted[3])
	if last.NonceSource != proof.NonceServer || last.Nonce != tr.lastNonce {
		t.Error("online statement does not carry the server nonce")
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

// A hostile challenge (one carrying a command) changes nothing: the agent
// treats it as no challenge, signs with its own nonce and carries on.
func TestHostileChallengeIsIgnored(t *testing.T) {
	dir, s := t.TempDir(), newSigner(t)
	_, err := ParseChallenge([]byte(`{"command":"isolate","nonce":"00112233445566778899aabbccddeeff"}`))
	tr := &fakeTransport{chalErr: err}
	a := newAgent(t, dir, s, tr)
	st, berr := a.Beat(context.Background())
	if err == nil || berr != nil {
		t.Fatalf("parse err %v, beat err %v", err, berr)
	}
	if st.NonceSource != proof.NonceAgent {
		t.Error("the hostile nonce was used")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		switch e.Name() {
		case "queue", stateFile:
		default:
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
