package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
	"github.com/kendallcoding202/kovyr-edr/internal/sysload"
	"github.com/kendallcoding202/kovyr-edr/internal/tripwire"
)

// tripClock is a fake clock that sets off a mass rename at given times: a
// wait that would pass one ends there, with the burst fed to the real
// detector (which signals the agent). A wait that would pass until stops
// the loop instead, so the statements made are exactly those before it.
type tripClock struct {
	fakeClock
	burstAt []time.Time
	det     *tripwire.Detector
	until   time.Time
	cancel  func()
}

func (c *tripClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	burst := len(c.burstAt) > 0 && !c.now.Add(d).Before(c.burstAt[0])
	if !burst && !c.now.Add(d).Before(c.until) {
		c.mu.Unlock()
		c.cancel()
		return nil
	}
	if burst {
		at := c.burstAt[0]
		c.burstAt = c.burstAt[1:]
		d = at.Sub(c.now)
		c.mu.Unlock()
		ch := c.fakeClock.After(d) // the clock is now at the burst
		c.det.AddN(tripwire.ExtensionChanged, 300)
		c.det.Flush()
		return ch
	}
	c.mu.Unlock()
	return c.fakeClock.After(d)
}

type tripRun struct {
	cfg     Config
	until   time.Duration
	burstAt []time.Duration
	chalErr func(n int) error // n counts challenges from 1
}

// run runs the loop with a real detector and returns the delivered
// statements.
func (r tripRun) run(t *testing.T) []*proof.Statement {
	t.Helper()
	tr := &challengeFails{fails: r.chalErr}
	ctx, cancel := context.WithCancel(context.Background())
	clk := &tripClock{fakeClock: fakeClock{now: t0}, until: t0.Add(r.until), cancel: cancel}
	for _, b := range r.burstAt {
		clk.burstAt = append(clk.burstAt, t0.Add(b))
	}
	det, err := tripwire.NewDetector(tripwire.Thresholds{}, nil, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	det.SetState(proof.AvailOK, 2)
	clk.det = det
	cfg := r.cfg
	cfg.Dir, cfg.Clock, cfg.Tripwire = t.TempDir(), clk, det
	cfg.Backoff = Backoff{Base: 5 * time.Second, Rand: func() float64 { return 0 }}
	if cfg.Conditions != nil {
		cfg.Conditions.(*clockedLoad).clk = &clk.fakeClock
	}
	a, err := New(cfg, newSigner(t), checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	var out []*proof.Statement
	for i, env := range tr.posted {
		_, st := decode(t, env)
		if st.Seq != uint32(i+1) {
			t.Fatalf("statement %d has seq %d", i, st.Seq)
		}
		out = append(out, st)
	}
	return out
}

// challengeFails is a transport whose challenges fail when fails says so.
type challengeFails struct {
	fakeTransport
	fails func(n int) error
	n     int
}

func (c *challengeFails) Challenge(ctx context.Context, device string) (proof.Nonce, error) {
	c.mu.Lock()
	c.n++
	n := c.n
	c.mu.Unlock()
	if c.fails != nil {
		if err := c.fails(n); err != nil {
			return proof.Nonce{}, err
		}
	}
	return c.fakeTransport.Challenge(ctx, device)
}

type beatAt struct {
	at        time.Duration
	triggered bool
	intervalS uint16
	deferredS uint16
}

func checkBeats(t *testing.T, got []*proof.Statement, want []beatAt) {
	t.Helper()
	if len(got) != len(want) {
		for _, st := range got {
			t.Logf("seq %d at %v triggered %v %+v", st.Seq, st.ObservedAt.Sub(t0), st.Readings.Tripwire.Triggered, st.Schedule)
		}
		t.Fatalf("%d statements, want %d", len(got), len(want))
	}
	for i, w := range want {
		st := got[i]
		tw := st.Readings.Tripwire
		if at := st.ObservedAt.Sub(t0); at != w.at.Truncate(time.Second) || tw.Triggered != w.triggered ||
			st.Schedule.IntervalS != w.intervalS || st.Schedule.DeferredS != w.deferredS {
			t.Errorf("seq %d: at %v triggered %v interval %d deferred %d; want %+v",
				st.Seq, at, tw.Triggered, st.Schedule.IntervalS, st.Schedule.DeferredS, w)
		}
		if tw.State != proof.AvailOK || tw.FoldersWatched != 2 {
			t.Errorf("seq %d: tripwire %+v", st.Seq, tw)
		}
		if w.triggered && (tw.Reason != proof.TripMassExtensionChange || tw.Counts.ExtensionChanged != proof.Bucket100to999) {
			t.Errorf("seq %d: trip %+v", st.Seq, tw)
		}
	}
}

// A trip between heartbeats sends one at once, which announces the time
// left until the scheduled one; the schedule is kept and the trip is
// reported once.
func TestTripSendsAnExtraHeartbeatAtOnce(t *testing.T) {
	got := tripRun{until: 31 * time.Minute, burstAt: []time.Duration{5 * time.Minute}}.run(t)
	checkBeats(t, got, []beatAt{
		{0, false, 900, 0},
		{5 * time.Minute, true, 600, 0},
		{15 * time.Minute, false, 900, 0},
		{30 * time.Minute, false, 900, 0},
	})
}

// An extra heartbeat right before a scheduled one announces the SPEC
// minimum, never less.
func TestTripJustBeforeAHeartbeatAnnouncesTheMinimum(t *testing.T) {
	got := tripRun{until: 16 * time.Minute, burstAt: []time.Duration{14*time.Minute + 50*time.Second}}.run(t)
	checkBeats(t, got, []beatAt{
		{0, false, 900, 0},
		{14*time.Minute + 50*time.Second, true, proof.MinIntervalS, 0},
		{15 * time.Minute, false, 900, 0},
	})
}

// Ransomware keeps the processor busy, so a heartbeat being deferred for
// load is made at once when the tripwire fires.
func TestTripIsNeverDeferredForLoad(t *testing.T) {
	busy := &clockedLoad{busyAt: func(time.Time) int { return 100 }}
	got := tripRun{cfg: Config{Conditions: busy}, until: 16*time.Minute + 40*time.Second,
		burstAt: []time.Duration{16*time.Minute + 30*time.Second}}.run(t)
	checkBeats(t, got, []beatAt{
		{0, false, 900, 0},
		{16*time.Minute + 30*time.Second, true, 900, 90}, // was due at 15m
	})
}

// Offline when it trips: the trip is not lost. It waits (unacknowledged)
// and goes out with the retry.
func TestTripSurvivesAFailedHeartbeat(t *testing.T) {
	got := tripRun{until: 21 * time.Minute, burstAt: []time.Duration{5 * time.Minute},
		chalErr: func(n int) error {
			if n == 2 {
				return errors.New("offline")
			}
			return nil
		}}.run(t)
	checkBeats(t, got, []beatAt{
		{0, false, 900, 0},
		{5*time.Minute + 2500*time.Millisecond, true, 900, 0}, // the retry is the heartbeat now
		{20*time.Minute + 2500*time.Millisecond, false, 900, 0},
	})
}

// A second burst inside the cooldown sends nothing extra; it rides on the
// next scheduled heartbeat.
func TestTripsInsideTheCooldownWaitForTheSchedule(t *testing.T) {
	got := tripRun{until: 16 * time.Minute, burstAt: []time.Duration{2 * time.Minute, 8 * time.Minute}}.run(t)
	checkBeats(t, got, []beatAt{
		{0, false, 900, 0},
		{2 * time.Minute, true, 780, 0},
		{15 * time.Minute, true, 900, 0},
	})
}

// Without a tripwire the section says unknown.
func TestNoTripwireIsReportedUnknown(t *testing.T) {
	a := newAgent(t, t.TempDir(), newSigner(t), &fakeTransport{})
	st, err := a.Beat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Readings.Tripwire != (proof.Tripwire{State: proof.AvailUnknown}) {
		t.Fatalf("tripwire %+v", st.Readings.Tripwire)
	}
}

// countingTripwire counts acknowledgements.
type countingTripwire struct {
	mu   sync.Mutex
	acks int
}

func (c *countingTripwire) Snapshot() (proof.Tripwire, func()) {
	return proof.Tripwire{State: proof.AvailNotApplicable}, func() { c.mu.Lock(); c.acks++; c.mu.Unlock() }
}
func (c *countingTripwire) Trips() <-chan struct{} { return nil }

// The tripwire's news is acknowledged only once the server accepts a
// statement carrying it: not when there is no statement, not when it is
// merely queued, not when its upload fails.
func TestTripwireIsAcknowledgedOnlyWhenAccepted(t *testing.T) {
	tw := &countingTripwire{}
	tr := &fakeTransport{chalErr: errors.New("offline"), postErr: func(n int) error {
		if n == 1 {
			return errors.New("upload failed")
		}
		return nil
	}}
	a, err := New(Config{Dir: t.TempDir(), Tripwire: tw}, newSigner(t), checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	a.Beat(context.Background())
	if tw.acks != 0 {
		t.Fatal("acknowledged without a statement")
	}
	tr.chalErr = nil
	st, err := a.Beat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tw.acks != 0 || st.Readings.Tripwire.State != proof.AvailNotApplicable {
		t.Fatalf("acks %d when queued, tripwire %+v", tw.acks, st.Readings.Tripwire)
	}
	if err := a.Flush(context.Background()); err == nil || tw.acks != 0 {
		t.Fatalf("flush %v, acks %d after a failed upload", err, tw.acks)
	}
	if err := a.Flush(context.Background()); err != nil || tw.acks != 1 {
		t.Fatalf("flush %v, acks %d after delivery, want 1", err, tw.acks)
	}
}

var _ sysload.Source = (*clockedLoad)(nil)

// Offline when it trips just before a heartbeat: the retry never pushes
// the scheduled heartbeat later.
func TestFailedTripHeartbeatNeverDelaysTheSchedule(t *testing.T) {
	got := tripRun{until: 16 * time.Minute, burstAt: []time.Duration{14*time.Minute + 59*time.Second},
		chalErr: func(n int) error {
			if n == 2 {
				return errors.New("offline")
			}
			return nil
		}}.run(t)
	checkBeats(t, got, []beatAt{
		{0, false, 900, 0},
		{15 * time.Minute, true, 900, 0},
	})
}

// signalTripwire signals a trip on demand.
type signalTripwire struct {
	countingTripwire
	trips chan struct{}
}

func (s *signalTripwire) Trips() <-chan struct{} { return s.trips }

// The loop wakes for a trip while it waits for the next heartbeat (real
// clock: the next scheduled heartbeat is 15 minutes away).
func TestLoopWakesForATrip(t *testing.T) {
	tw := &signalTripwire{trips: make(chan struct{}, 1)}
	tr := &fakeTransport{}
	a, err := New(Config{Dir: t.TempDir(), Tripwire: tw}, newSigner(t), checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() { cancel(); <-done }()
	posted := func(n int) bool {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			tr.mu.Lock()
			got := len(tr.posted)
			tr.mu.Unlock()
			if got >= n {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	if !posted(1) {
		t.Fatal("no first heartbeat")
	}
	tw.trips <- struct{}{}
	if !posted(2) {
		t.Fatal("no heartbeat after the trip")
	}
	tr.mu.Lock()
	_, st := decode(t, tr.posted[1])
	tr.mu.Unlock()
	if s := st.Schedule.IntervalS; s < 890 || s > 900 {
		t.Errorf("extra heartbeat announces %ds, want the time to the scheduled one", s)
	}
}

// A trip that rides on a scheduled heartbeat is done with: the next wake
// (a load sample) sends nothing extra.
func TestTripOnAScheduledHeartbeatIsSentOnce(t *testing.T) {
	idle := &clockedLoad{busyAt: func(time.Time) int { return 5 }}
	got := tripRun{cfg: Config{Conditions: idle}, until: 31 * time.Minute, burstAt: []time.Duration{15 * time.Minute}}.run(t)
	checkBeats(t, got, []beatAt{
		{0, false, 900, 0},
		{15 * time.Minute, true, 900, 0},
		{30 * time.Minute, false, 900, 0},
	})
}
