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
	"github.com/kendallcoding202/kovyr-edr/internal/tripwire"
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

// ingestFake judges uploads like ingest: a statement is accepted only if
// it arrives within 5 minutes of its observed_at and after the last
// accepted seq. blockPost makes uploads fail in transit (an outage, or an
// on-path attacker resetting them); failChallenge makes challenges fail.
// lenient answers 2xx before judging, as halden does (202). refuse
// refuses upload number n (from 1) outright.
type ingestFake struct {
	now           func() time.Time
	blockPost     func(now time.Time) bool
	failChallenge func(now time.Time) bool
	refuse        func(n int) bool
	lenient       bool

	mu         sync.Mutex
	challenges int
	uploads    int
	sent       []*proof.Statement // every upload, delivered or not
	accepted   []*proof.Statement
	refused    int
}

func (f *ingestFake) Challenge(ctx context.Context, device string) (proof.Nonce, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenges++
	if f.failChallenge != nil && f.failChallenge(f.now()) {
		return proof.Nonce{}, errors.New("offline")
	}
	return proof.NewAgentNonce()
}

func (f *ingestFake) PostHeartbeat(ctx context.Context, env []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	f.uploads++
	e, err := proof.ParseEnvelope(env)
	if err != nil {
		return err
	}
	st, err := proof.ValidateStatement(e.Payload)
	if err != nil {
		return err
	}
	f.sent = append(f.sent, st)
	if f.blockPost != nil && f.blockPost(now) {
		return errors.New("connection reset")
	}
	age := now.Sub(st.ObservedAt)
	if f.refuse != nil && f.refuse(f.uploads) {
		f.refused++
		return ErrRefused
	}
	if age <= 5*time.Minute && age >= -5*time.Minute && (len(f.accepted) == 0 || st.Seq > f.accepted[len(f.accepted)-1].Seq) {
		f.accepted = append(f.accepted, st)
		return nil
	}
	f.refused++
	if f.lenient {
		return nil
	}
	return ErrRefused
}

// runTrips runs the loop with a real detector until until, with bursts of
// ransomware-like renames at the given times, and returns the clock.
func runTrips(t *testing.T, ing *ingestFake, load *clockedLoad, until time.Duration, bursts ...time.Duration) *tripClock {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	clk := &tripClock{fakeClock: fakeClock{now: t0}, until: t0.Add(until), cancel: cancel}
	for _, b := range bursts {
		clk.burstAt = append(clk.burstAt, t0.Add(b))
	}
	det, err := tripwire.NewDetector(tripwire.Thresholds{}, nil, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	det.SetState(proof.AvailOK, 2)
	clk.det = det
	ing.now = clk.Now
	cfg := Config{Dir: t.TempDir(), Clock: clk, Tripwire: det,
		Backoff: Backoff{Base: 5 * time.Second, Rand: func() float64 { return 0 }}}
	if load != nil {
		load.clk = &clk.fakeClock
		cfg.Conditions = load
	}
	a, err := New(cfg, newSigner(t), checks.NewRunner(checks.HealthyFake()), ing)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	for _, w := range clk.waits {
		if w < time.Second {
			t.Fatalf("hot loop: waited only %v", w)
		}
	}
	return clk
}

// acceptedTrips returns when (after t0) each accepted statement was made,
// and whether it carried a trip.
func acceptedTrips(ing *ingestFake) (at []time.Duration, triggered []bool) {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	for _, st := range ing.accepted {
		at = append(at, st.ObservedAt.Sub(t0))
		triggered = append(triggered, st.Readings.Tripwire.Triggered)
	}
	return at, triggered
}

func checkAccepted(t *testing.T, ing *ingestFake, wantAt []time.Duration, wantTrig []bool) {
	t.Helper()
	at, trig := acceptedTrips(ing)
	if len(at) != len(wantAt) {
		t.Fatalf("accepted statements made at %v (triggered %v), want %v (%v)", at, trig, wantAt, wantTrig)
	}
	for i := range at {
		if at[i] != wantAt[i] || trig[i] != wantTrig[i] {
			t.Fatalf("accepted statements made at %v (triggered %v), want %v (%v)", at, trig, wantAt, wantTrig)
		}
	}
}

// PROTO-1: the ransomware tripwire fires at 5m and its upload is reset
// until 16m, past the nonce window of the statement that carried it. The
// trip is not lost: retries carry it in new statements (fresh nonces),
// and one is accepted at the first retry after the uploads come back,
// before the next scheduled heartbeat (30m). Once accepted, it is not
// reported again.
func TestUndeliveredTripIsCarriedUntilAccepted(t *testing.T) {
	ing := &ingestFake{blockPost: func(now time.Time) bool {
		return !now.Before(t0.Add(5*time.Minute)) && now.Before(t0.Add(16*time.Minute))
	}}
	runTrips(t, ing, nil, 31*time.Minute, 5*time.Minute)
	checkAccepted(t, ing,
		[]time.Duration{0, 22*time.Minute + 30*time.Second, 30 * time.Minute},
		[]bool{false, true, false})
	if ing.challenges > 10 {
		t.Errorf("%d challenges in 31 minutes", ing.challenges)
	}
}

// PROTO-1 against halden, which answers 202 before it checks the clock: a
// trip statement whose upload got through only after 5 minutes was
// answered 2xx but refused later. That 2xx must not count; the next
// statement (challenges failed until 12m) carries the trip again.
func TestLateDeliveryDoesNotAcknowledgeTheTrip(t *testing.T) {
	ing := &ingestFake{lenient: true,
		blockPost: func(now time.Time) bool {
			return !now.Before(t0.Add(5*time.Minute)) && now.Before(t0.Add(10*time.Minute))
		},
		failChallenge: func(now time.Time) bool {
			return !now.Before(t0.Add(6*time.Minute)) && now.Before(t0.Add(12*time.Minute))
		}}
	runTrips(t, ing, nil, 31*time.Minute, 5*time.Minute)
	checkAccepted(t, ing,
		[]time.Duration{0, 15 * time.Minute, 30 * time.Minute},
		[]bool{false, true, false})
	if ing.refused != 1 {
		t.Errorf("%d late uploads, want the one 5 minutes late", ing.refused)
	}
}

// A trip statement the server refuses is not the end of the trip: the
// retry carries it in a new statement at once, without waiting for the
// next scheduled heartbeat.
func TestRefusedTripIsSentAgainSoon(t *testing.T) {
	ing := &ingestFake{refuse: func(n int) bool { return n == 2 }}
	runTrips(t, ing, nil, 16*time.Minute, 5*time.Minute)
	checkAccepted(t, ing,
		[]time.Duration{0, 5*time.Minute + 2*time.Second, 15 * time.Minute}, // made 2.5s later, at whole seconds
		[]bool{false, true, false})
}

// A scheduled heartbeat that would carry a trip not yet accepted is not
// deferred for load (ransomware keeps the processor busy).
func TestOwedTripStopsLoadDeferral(t *testing.T) {
	ing := &ingestFake{blockPost: func(now time.Time) bool {
		return !now.Before(t0.Add(5*time.Minute)) && now.Before(t0.Add(16*time.Minute))
	}}
	busy := &clockedLoad{busyAt: func(time.Time) int { return 100 }}
	runTrips(t, ing, busy, 16*time.Minute, 5*time.Minute)
	ing.mu.Lock()
	defer ing.mu.Unlock()
	for _, st := range ing.sent {
		if at := st.ObservedAt.Sub(t0); at >= 15*time.Minute {
			if at != 15*time.Minute || st.Schedule.DeferredS != 0 || !st.Readings.Tripwire.Triggered {
				t.Fatalf("the heartbeat due at 15m was made at %v, deferred %ds, triggered %v",
					at, st.Schedule.DeferredS, st.Readings.Tripwire.Triggered)
			}
			return
		}
	}
	t.Fatal("no heartbeat at 15m")
}

// A server that refuses every upload while a trip is owed gets new
// statements only as fast as the retry backoff allows: no hot loop, and
// at most about one extra statement per backoff step.
func TestTripRetriesBackOff(t *testing.T) {
	ing := &ingestFake{}
	refuseAll := &refusingIngest{ingestFake: ing}
	ctx, cancel := context.WithCancel(context.Background())
	clk := &tripClock{fakeClock: fakeClock{now: t0}, until: t0.Add(3 * time.Hour), cancel: cancel,
		burstAt: []time.Time{t0.Add(5 * time.Minute)}}
	det, _ := tripwire.NewDetector(tripwire.Thresholds{}, nil, clk.Now)
	det.SetState(proof.AvailOK, 2)
	clk.det = det
	ing.now = clk.Now
	a, err := New(Config{Dir: t.TempDir(), Clock: clk, Tripwire: det,
		Backoff: Backoff{Base: 5 * time.Second, Rand: func() float64 { return 0 }}},
		newSigner(t), checks.NewRunner(checks.HealthyFake()), refuseAll)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	for _, w := range clk.waits {
		if w < time.Second {
			t.Fatalf("hot loop: waited only %v", w)
		}
	}
	// 12 scheduled heartbeats, the trip's, and retries backing off to
	// 7.5 minutes (low jitter): about 35 statements in 3 hours.
	if a.State().Seq > 40 {
		t.Fatalf("%d statements in 3 hours", a.State().Seq)
	}
	t.Logf("%d statements, %d uploads in 3 hours", a.State().Seq, ing.uploads)
}

type refusingIngest struct{ *ingestFake }

func (r *refusingIngest) PostHeartbeat(ctx context.Context, env []byte) error {
	r.mu.Lock()
	r.uploads++
	r.mu.Unlock()
	return ErrRefused
}

// The acknowledgements kept for queued statements are bounded, and the
// newest statement's still acknowledges the tripwire once it is accepted.
func TestPendingAcknowledgementsAreBounded(t *testing.T) {
	tw := &countingTripwire{}
	tr := &fakeTransport{postErr: func(int) error { return errors.New("upload failed") }}
	a, err := New(Config{Dir: t.TempDir(), Tripwire: tw}, newSigner(t), checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3*maxPendingAcks; i++ {
		if _, err := a.Beat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(a.pending); n > maxPendingAcks {
		t.Fatalf("%d acknowledgements kept, want at most %d", n, maxPendingAcks)
	}
	tr.postErr = nil
	if err := a.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tw.acks != 1 || len(a.pending) != 0 || a.QueueLen() != 0 {
		t.Fatalf("acks %d, pending %d, queued %d", tw.acks, len(a.pending), a.QueueLen())
	}
}

// PROTO-1, end to end over HTTP with the dev receiver (the audit's
// proof of concept, inverted): the tripwire statement's uploads are reset
// for 6 minutes, so it goes stale and is refused. The next statement
// still says triggered, the receiver raises ransomware_suspected once,
// and the statement after that is quiet.
func TestTripReachesTheReceiverAfterItsUploadIsReset(t *testing.T) {
	clk := &fakeClock{now: t0}
	s := newSigner(t)
	w := newWorld(t, clk, s)
	det, err := tripwire.NewDetector(tripwire.Thresholds{}, nil, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	det.SetState(proof.AvailOK, 2)
	a, err := New(Config{Dir: t.TempDir(), Clock: clk, Tripwire: det}, s, checks.NewRunner(checks.HealthyFake()), w.client)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	advance := func(d time.Duration) { clk.set(clk.Now().Add(d)) }
	beat := func() *proof.Statement {
		t.Helper()
		st, err := a.Beat(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	beat()
	if err := a.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	advance(5 * time.Minute)
	det.AddN(tripwire.ExtensionChanged, 300)
	det.Flush()
	w.setGate(func(r *http.Request, _ time.Time) int {
		if r.Method == http.MethodPost {
			return -1
		}
		return 0
	})
	if !beat().Readings.Tripwire.Triggered {
		t.Fatal("tripwire statement not triggered")
	}
	for i := 0; i < 6; i++ {
		if err := a.Flush(ctx); err == nil {
			t.Fatal("flush succeeded while uploads are reset")
		}
		advance(time.Minute)
	}
	w.setGate(nil)
	if err := a.Flush(ctx); err != nil { // refused: 6 minutes old
		t.Fatal(err)
	}
	advance(4 * time.Minute)
	if !beat().Readings.Tripwire.Triggered {
		t.Fatal("the trip was forgotten when its statement was refused")
	}
	if err := a.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	advance(15 * time.Minute)
	if beat().Readings.Tripwire.Triggered {
		t.Fatal("an accepted trip was reported again")
	}
	if err := a.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	d := w.device(t)
	ransom := 0
	for _, e := range d.Events {
		if e.Kind == receiver.EvRansomware {
			ransom++
		}
	}
	if ransom != 1 || d.Accepted != 3 || d.Refused != 1 {
		t.Fatalf("ransomware events %d, accepted %d, refused %d; want 1, 3, 1", ransom, d.Accepted, d.Refused)
	}
}
