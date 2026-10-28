package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
	"github.com/kendallcoding202/kovyr-edr/internal/receiver"
)

// world is the dev receiver behind a real HTTP server, sharing the test's
// clock. gate stands in front of it (an outage, an on-path attacker): it
// returns 0 to pass a request on, a status code to answer with, or -1 to
// reset the connection.
type world struct {
	rcv    *receiver.Receiver
	client *HTTPClient
	clk    Clock

	mu    sync.Mutex
	gate  func(r *http.Request, now time.Time) int
	posts []post // every POST that reached the server
}

type post struct {
	at   time.Time
	code int
}

func newWorld(t *testing.T, clk Clock, s proof.Signer) *world {
	t.Helper()
	rcv, err := receiver.New(receiver.Config{Now: clk.Now},
		[]receiver.Device{{DeviceID: proof.DeviceID(s.Public()), PublicKey: s.Public().Base64()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{rcv: rcv, clk: clk}
	h := rcv.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		now := clk.Now()
		w.mu.Lock()
		gate := w.gate
		w.mu.Unlock()
		code := 0
		if gate != nil {
			code = gate(r, now)
		}
		switch {
		case code < 0:
			if conn, _, err := rw.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		case code > 0:
			rw.WriteHeader(code)
		default:
			rec := &codeRecorder{ResponseWriter: rw, code: http.StatusOK}
			h.ServeHTTP(rec, r)
			code = rec.code
		}
		if r.Method == http.MethodPost {
			w.mu.Lock()
			w.posts = append(w.posts, post{now, code})
			w.mu.Unlock()
		}
	}))
	t.Cleanup(srv.Close)
	if w.client, err = NewHTTPClient(srv.URL, true); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) setGate(g func(r *http.Request, now time.Time) int) {
	w.mu.Lock()
	w.gate = g
	w.mu.Unlock()
}

func (w *world) postsSince(at time.Time) []post {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []post
	for _, p := range w.posts {
		if !p.at.Before(at) {
			out = append(out, p)
		}
	}
	return out
}

func (w *world) device(t *testing.T) receiver.DeviceStatus {
	t.Helper()
	ds := w.rcv.Status().Devices
	if len(ds) != 1 {
		t.Fatalf("%d devices", len(ds))
	}
	return ds[0]
}

type codeRecorder struct {
	http.ResponseWriter
	code int
}

func (r *codeRecorder) WriteHeader(c int) { r.code = c; r.ResponseWriter.WriteHeader(c) }

// set moves a fake clock.
func (c *fakeClock) set(at time.Time) { c.mu.Lock(); c.now = at; c.mu.Unlock() }

// PROTO-6: a queued statement older than the nonce lifetime (plus a
// minute) can only be refused, so it is dropped without being sent, even
// while uploads fail. Younger ones stay for the retry.
func TestStatementsTooOldToBeAcceptedAreDroppedUnsent(t *testing.T) {
	clk := &fakeClock{now: t0}
	tr := &fakeTransport{postErr: func(int) error { return errors.New("upload failed") }}
	var logs []string
	a, err := New(Config{Dir: t.TempDir(), Clock: clk, Logf: func(f string, v ...any) { logs = append(logs, f) }},
		newSigner(t), checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Duration{0, 5 * time.Minute, 12 * time.Minute} {
		clk.set(t0.Add(at))
		if _, err := a.Beat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	clk.set(t0.Add(16 * time.Minute)) // ages 16m, 11m and 4m
	if err := a.Flush(context.Background()); err == nil {
		t.Fatal("flush succeeded while uploads fail")
	}
	seqs, _ := a.queue.Seqs()
	if len(seqs) != 2 || seqs[0] != 2 || seqs[1] != 3 {
		t.Fatalf("queue holds %v, want [2 3] (seq 1 is 16 minutes old)", seqs)
	}
	if tr.attempts != 1 {
		t.Errorf("%d uploads tried, want 1 (the newest)", tr.attempts)
	}
	found := false
	for _, l := range logs {
		found = found || l == "dropped %d queued statement(s) too old for the server to accept; it records them as lost reports"
	}
	if !found {
		t.Errorf("no log line for the drop: %q", logs)
	}
}

// PROTO-6, end to end: after a day in which challenges work but every
// upload fails (a 503 outage), the agent does not replay a stale backlog
// oldest first behind the rate limit. Within one interval of the server
// coming back, and within two uploads, its newest statement is accepted.
func TestNewestStatementIsAcceptedSoonAfterAnOutage(t *testing.T) {
	clk := &fakeClock{now: t0}
	s := newSigner(t)
	w := newWorld(t, clk, s)
	recoverAt := t0.Add(24*time.Hour + 5*time.Minute)
	w.setGate(func(r *http.Request, now time.Time) int {
		if r.Method == http.MethodPost && now.Before(recoverAt) {
			return http.StatusServiceUnavailable
		}
		return 0
	})
	ctx, cancel := context.WithCancel(context.Background())
	clk.onWait = func(int) {
		if clk.Now().After(recoverAt.Add(30 * time.Minute)) {
			cancel()
			clk.stop()
		}
	}
	a, err := New(Config{Dir: t.TempDir(), Clock: clk, Backoff: Backoff{Base: 5 * time.Second, Rand: func() float64 { return 0 }}},
		s, checks.NewRunner(checks.HealthyFake()), w.client)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	after := w.postsSince(recoverAt)
	first := -1
	for i, p := range after {
		if p.code == http.StatusOK {
			first = i
			break
		}
	}
	if first < 0 {
		t.Fatalf("nothing accepted after the outage; uploads %+v", after)
	}
	for _, p := range after[:first+1] {
		t.Logf("upload %v after recovery: HTTP %d", p.at.Sub(recoverAt), p.code)
	}
	if late := after[first].at.Sub(recoverAt); first > 1 || late > 15*time.Minute {
		t.Fatalf("first acceptance %v after recovery, after %d refused upload(s)", late, first)
	}
	d := w.device(t)
	if a.QueueLen() != 0 || d.LastSeq != a.State().Seq {
		t.Errorf("queue %d, receiver at seq %d, agent at %d", a.QueueLen(), d.LastSeq, a.State().Seq)
	}
	if d.LostStatements == 0 {
		t.Error("the outage's statements are not disclosed as lost")
	}
}
