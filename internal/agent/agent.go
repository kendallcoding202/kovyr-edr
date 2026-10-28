// Package agent is the heartbeat loop: every interval it fetches a
// challenge, runs the checks, signs a statement, queues it on disk and
// sends the queue oldest first.
//
// SPEC section 8: every report carries a one-time server nonce issued for
// this device, and ingest refuses nonces older than 10 minutes and
// statements more than 5 minutes from the server's clock. So the agent
// signs only right after a challenge; with no challenge (offline) it makes
// no statement and the receiver sees a gap ("silence is a signal"). The
// queue bridges short upload failures, not long offline periods.
//
// The agent only reports. It never accepts commands: the server can hand
// it a nonce and a status code, nothing else (see Transport).
package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
	"github.com/kendallcoding202/kovyr-edr/internal/sysload"
)

// Version is this agent's version, reported in every statement.
var Version = proof.Version{Major: 0, Minor: 1, Patch: 0}

// ErrNoChallenge means no server nonce could be had, so no statement was
// made this time.
var ErrNoChallenge = errors.New("no server challenge")

// SensorHealth is the SPEC 6.4 sensor_health section for v0. The agent
// is running (it is making this report). v0 has no self-tamper checks yet,
// so tamper_detected is false meaning "none detected", not "checked and
// clean" (ransomware activity goes in the tripwire section, not here); it
// does not read the blocklist version (0) and has no policy (0).
func SensorHealth() proof.SensorHealth {
	return proof.SensorHealth{SensorRunning: true}
}

// DefaultInterval is the heartbeat interval.
const DefaultInterval = 15 * time.Minute

// Checker runs the protection checks (checks.Runner in production).
type Checker interface {
	RunWith(checks.RunOptions) (proof.Readings, []checks.CheckReport)
}

// Tripwire is the ransomware tripwire (tripwire.Detector in production).
// It only counts and signals; the agent reports what it says and takes no
// action on a trip.
type Tripwire interface {
	// Snapshot is the tripwire section for the next statement, and the
	// function to call once that statement is safely queued.
	Snapshot() (proof.Tripwire, func())
	// Trips signals that the tripwire fired and an extra heartbeat is
	// due now. It fires at most once per cooldown.
	Trips() <-chan struct{}
}

// Clock lets tests drive time.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Config configures an Agent. Zero values get defaults.
type Config struct {
	Dir             string // state directory (key, chain state, queue)
	Interval        time.Duration
	QueueMaxEntries int
	QueueMaxBytes   int64
	Backoff         Backoff // retry delays after failed sends
	// Conditions reads battery and processor load for Throttle; nil never
	// backs off (Beat and the tests).
	Conditions sysload.Source
	Throttle   Throttle
	// Tripwire is reported in every statement and triggers an extra
	// heartbeat when it fires; nil reports it as unknown.
	Tripwire Tripwire
	Clock    Clock
	Logf     func(format string, args ...any)
}

// Agent is the heartbeat loop.
type Agent struct {
	cfg       Config
	signer    proof.Signer
	checker   Checker
	transport Transport
	queue     *Queue
	state     ChainState

	load        *loadMonitor
	onBattery   bool      // last power state seen, to log changes once
	deferredDue time.Time // the due time of the heartbeat being deferred
}

// New opens the agent's state. It reconciles the chain head with the
// queue, so a crash between queueing an envelope and saving the state
// never reuses a seq.
func New(cfg Config, signer proof.Signer, checker Checker, transport Transport) (*Agent, error) {
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	if s := cfg.Interval.Seconds(); s < proof.MinIntervalS || s > proof.MaxIntervalS || cfg.Interval%time.Second != 0 {
		return nil, fmt.Errorf("interval must be whole seconds between %ds and %ds", proof.MinIntervalS, proof.MaxIntervalS)
	}
	if cfg.QueueMaxEntries == 0 {
		cfg.QueueMaxEntries = DefaultQueueMaxEntries
	}
	if cfg.QueueMaxBytes == 0 {
		cfg.QueueMaxBytes = DefaultQueueMaxBytes
	}
	if cfg.Backoff.Base == 0 {
		cfg.Backoff.Base = 5 * time.Second
	}
	if cfg.Backoff.Max == 0 {
		cfg.Backoff.Max = cfg.Interval
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	th, err := cfg.Throttle.WithDefaults()
	if err != nil {
		return nil, err
	}
	cfg.Throttle = th
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	q, err := OpenQueue(filepath.Join(cfg.Dir, "queue"), cfg.QueueMaxEntries, cfg.QueueMaxBytes)
	if err != nil {
		return nil, err
	}
	st, err := loadState(cfg.Dir, signer.Public().KeyID())
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, signer: signer, checker: checker, transport: transport, queue: q, state: st}
	if cfg.Conditions != nil {
		a.load = &loadMonitor{src: cfg.Conditions, window: th.Window}
	}
	if err := a.reconcile(); err != nil {
		return nil, err
	}
	return a, nil
}

// reconcile adopts the chain head from the newest queued envelope ahead of
// the saved state, but only from one this device signed: the device's
// public key is public, so anyone who can drop a file into the queue
// could otherwise move the chain head (to the last seq, say, which bricks
// the device). A file that is not this device's is removed and the next
// one is tried; each pass removes a file, so the loop ends.
func (a *Agent) reconcile() error {
	for {
		seq, env, ok, err := a.queue.Newest()
		if err != nil || !ok || seq <= a.state.Seq {
			return err
		}
		_, d, err := a.ownStatement(seq, env)
		if err != nil {
			a.cfg.Logf("queued file %d is not a statement signed by this device; removed", seq)
			if err := a.queue.Remove(seq); err != nil {
				return err
			}
			continue
		}
		a.state.Seq = seq
		a.state.Prev = fmt.Sprintf("%x", d[:])
		a.cfg.Logf("recovered chain head seq %d from the queue", seq)
		return saveState(a.cfg.Dir, a.state)
	}
}

// ownStatement opens a queued envelope. It returns the statement and its
// payload digest only if the envelope verifies under this device's key
// and the statement is about this key and filed under its own seq.
func (a *Agent) ownStatement(seq uint32, env []byte) (*proof.Statement, proof.Digest, error) {
	e, err := proof.ParseEnvelope(env)
	if err != nil {
		return nil, proof.Digest{}, err
	}
	if err := proof.VerifyEnvelope(e, a.signer.Public()); err != nil {
		return nil, proof.Digest{}, err
	}
	st, err := proof.ValidateStatement(e.Payload)
	if err != nil {
		return nil, proof.Digest{}, err
	}
	if st.Seq != seq || st.KeyID != a.signer.Public().KeyID() {
		return nil, proof.Digest{}, errors.New("statement is filed under another seq or key")
	}
	return st, proof.PayloadDigest(e.Payload), nil
}

// State returns the chain head (for tests and the CLI).
func (a *Agent) State() ChainState { return a.state }

// QueueLen returns the number of envelopes waiting to be sent.
func (a *Agent) QueueLen() int { return a.queue.Len() }

// Beat makes one statement now, with every check and the configured
// interval, and queues it. It does not send.
func (a *Agent) Beat(ctx context.Context) (*proof.Statement, error) {
	return a.beat(ctx, plan{interval: a.cfg.Interval})
}

func (a *Agent) beat(ctx context.Context, p plan) (*proof.Statement, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	nonce, err := a.transport.Challenge(cctx, proof.DeviceID(a.signer.Public()))
	cancel()
	if err != nil {
		// No nonce, no statement: a seq is never spent on a report the
		// server would refuse.
		return nil, fmt.Errorf("%w: %v", ErrNoChallenge, err)
	}
	readings, reports := a.checker.RunWith(checks.RunOptions{SkipHeavy: p.skipHeavy})
	for _, r := range reports {
		if r.Outcome != checks.OutcomeOK && r.Outcome != checks.OutcomeNotApplicable && r.Outcome != checks.OutcomeSkipped {
			a.cfg.Logf("check %s: %s", r.Name, r.Outcome)
		}
	}
	// The tripwire last, so the statement carries the newest window.
	// Without one it stays unknown (the zero value).
	ack := func() {}
	if a.cfg.Tripwire != nil {
		readings.Tripwire, ack = a.cfg.Tripwire.Snapshot()
	}
	env, st, err := a.seal(nonce, readings, p.schedule())
	if err != nil {
		return nil, err
	}
	dropped, err := a.queue.Push(st.Seq, env.Canonical())
	if err != nil {
		return nil, fmt.Errorf("queue: %w", err)
	}
	if dropped > 0 {
		a.cfg.Logf("queue full: dropped the %d oldest unsent statement(s)", dropped)
	}
	d := proof.PayloadDigest(env.Payload)
	a.state.Seq, a.state.Prev = st.Seq, fmt.Sprintf("%x", d[:])
	if err := saveState(a.cfg.Dir, a.state); err != nil {
		return nil, fmt.Errorf("save chain state: %w", err)
	}
	// Only now is the tripwire's news safely on its way: a statement that
	// was never made leaves the trip for the next one.
	ack()
	return st, nil
}

// seal builds and signs the next statement in the chain.
func (a *Agent) seal(nonce proof.Nonce, r proof.Readings, sched proof.Schedule) (*proof.Envelope, *proof.Statement, error) {
	if a.state.Seq == 1<<31-1 {
		return nil, nil, errors.New("sequence exhausted; re-enroll the device")
	}
	prev, err := a.state.prevDigest()
	if err != nil {
		return nil, nil, err
	}
	salt, err := proof.NewSalt()
	if err != nil {
		return nil, nil, err
	}
	h := proof.Header{
		Seq: a.state.Seq + 1, Prev: prev, Nonce: nonce, Salt: salt,
		ObservedAt: a.cfg.Clock.Now(), AgentVersion: Version, Schedule: sched,
	}
	payload, err := proof.BuildStatement(a.signer.Public(), h, SensorHealth(), r)
	if err != nil {
		return nil, nil, err
	}
	env, err := proof.SignEnvelope(payload, a.signer)
	if err != nil {
		return nil, nil, err
	}
	if err := proof.VerifyEnvelope(env, a.signer.Public()); err != nil {
		return nil, nil, fmt.Errorf("own signature does not verify: %w", err)
	}
	st, err := proof.ValidateStatement(payload)
	if err != nil {
		return nil, nil, err
	}
	return env, st, nil
}

// Flush sends queued envelopes oldest first. It stops at the first
// transient failure (so order is kept) and returns that error.
func (a *Agent) Flush(ctx context.Context) error {
	for {
		seq, env, ok, err := a.queue.Oldest()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, requestTimeout)
		err = a.transport.PostHeartbeat(cctx, env)
		cancel()
		switch {
		case err == nil:
		case errors.Is(err, ErrRefused):
			a.cfg.Logf("server refused statement %d (%v); dropping it", seq, err)
		default:
			return err
		}
		if err := a.queue.Remove(seq); err != nil {
			return err
		}
	}
}

// Run is the heartbeat loop. It beats immediately, then every interval
// (longer on battery, deferred under load: see Throttle); failed sends
// are retried with backoff and jitter, never in a hot loop. When the
// tripwire fires it makes an extra heartbeat at once, which is never
// deferred, and the scheduled heartbeat keeps its time.
func (a *Agent) Run(ctx context.Context) error {
	clk := a.cfg.Clock
	nextBeat := clk.Now()
	due := nextBeat // when the pending heartbeat was due, before any deferral
	var retryAt time.Time
	failures, beatFailures := 0, 0
	var trips <-chan struct{} // nil without a tripwire: never ready
	if a.cfg.Tripwire != nil {
		trips = a.cfg.Tripwire.Trips()
	}
	tripped := false // a trip waits for a statement
	for {
		select {
		case <-trips:
			tripped = true
		default:
		}
		now := clk.Now()
		a.load.observe(now)
		switch {
		case !now.Before(nextBeat) || tripped && !now.Before(due):
			// The scheduled heartbeat (or one being deferred). A trip
			// rides on it and stops any deferral.
			p, deferBy := a.decide(now, due, tripped)
			switch {
			case deferBy > 0:
				nextBeat = now.Add(deferBy)
			default:
				if _, err := a.beat(ctx, p); err != nil {
					// Typically offline. Try again soon (with backoff,
					// never later than one interval) so a short outage
					// costs a late report, not a missed one.
					beatFailures++
					d := a.cfg.Backoff.Delay(beatFailures)
					a.cfg.Logf("heartbeat not made (%v); next try in %v", err, d.Round(time.Second))
					nextBeat = now.Add(d)
				} else {
					beatFailures, tripped = 0, false
					nextBeat = now.Add(p.interval)
				}
				due = nextBeat
				retryAt = now
			}
		case tripped:
			// The extra heartbeat. It announces the time left until the
			// scheduled one, so the receiver expects that one on time.
			a.cfg.Logf("tripwire fired: sending a heartbeat now")
			if _, err := a.beat(ctx, plan{interval: untilNext(now, nextBeat)}); err != nil {
				// The trip waits; retry with backoff, or with the
				// scheduled heartbeat if that comes first.
				beatFailures++
				d := a.cfg.Backoff.Delay(beatFailures)
				a.cfg.Logf("tripwire heartbeat not made (%v); next try in %v", err, d.Round(time.Second))
				if at := now.Add(d); at.Before(nextBeat) {
					nextBeat, due = at, at
				}
			} else {
				beatFailures, tripped = 0, false
			}
			retryAt = now
		}
		if !retryAt.IsZero() && !now.Before(retryAt) {
			if err := a.Flush(ctx); err != nil {
				failures++
				d := a.cfg.Backoff.Delay(failures)
				a.cfg.Logf("send failed (%v); %d queued, retry in %v", err, a.queue.Len(), d.Round(time.Second))
				retryAt = now.Add(d)
			} else {
				failures, retryAt = 0, time.Time{}
			}
		}
		wake := nextBeat
		if !retryAt.IsZero() && retryAt.Before(wake) {
			wake = retryAt
		}
		// Sample the processor once a load window before the heartbeat.
		if a.load != nil {
			if at := nextBeat.Add(-a.cfg.Throttle.Window); at.After(now) && at.Before(wake) {
				wake = at
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-trips:
			tripped = true
		case <-clk.After(wake.Sub(clk.Now())):
		}
	}
}

// untilNext is the interval an extra heartbeat announces: the time left
// until the scheduled one, within the SPEC limits.
func untilNext(now, next time.Time) time.Duration {
	d := next.Sub(now)
	if lo := proof.MinIntervalS * time.Second; d < lo {
		return lo
	}
	return d
}
