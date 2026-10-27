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
// is running (it is making this report). v0 has no self-tamper checks yet
// (the tripwire is a later ticket), so tamper_detected is false meaning
// "none detected", not "checked and clean"; it does not read the
// blocklist version (0) and has no policy (0).
func SensorHealth() proof.SensorHealth {
	return proof.SensorHealth{SensorRunning: true}
}

// DefaultInterval is the heartbeat interval.
const DefaultInterval = 15 * time.Minute

// Checker runs the protection checks (checks.Runner in production).
type Checker interface {
	RunWith(checks.RunOptions) (proof.Readings, []checks.CheckReport)
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
	Clock      Clock
	Logf       func(format string, args ...any)
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

func (a *Agent) reconcile() error {
	seq, env, ok, err := a.queue.Newest()
	if err != nil || !ok || seq <= a.state.Seq {
		return err
	}
	e, err := proof.ParseEnvelope(env)
	if err != nil {
		return fmt.Errorf("queued envelope %d: %w", seq, err)
	}
	st, err := proof.ValidateStatement(e.Payload)
	if err != nil || st.Seq != seq || st.KeyID != a.signer.Public().KeyID() {
		return fmt.Errorf("queued envelope %d does not belong to this chain", seq)
	}
	d := proof.PayloadDigest(e.Payload)
	a.state.Seq = seq
	a.state.Prev = fmt.Sprintf("%x", d[:])
	a.cfg.Logf("recovered chain head seq %d from the queue", seq)
	return saveState(a.cfg.Dir, a.state)
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
// are retried with backoff and jitter, never in a hot loop.
func (a *Agent) Run(ctx context.Context) error {
	clk := a.cfg.Clock
	nextBeat := clk.Now()
	due := nextBeat // when the pending heartbeat was due, before any deferral
	var retryAt time.Time
	failures, beatFailures := 0, 0
	for {
		now := clk.Now()
		a.load.observe(now)
		if !now.Before(nextBeat) {
			p, deferBy := a.decide(now, due)
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
					beatFailures = 0
					nextBeat = now.Add(p.interval)
				}
				due = nextBeat
				retryAt = now
			}
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
		case <-clk.After(wake.Sub(clk.Now())):
		}
	}
}
