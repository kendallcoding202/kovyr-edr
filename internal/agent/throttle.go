package agent

import (
	"fmt"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
	"github.com/kendallcoding202/kovyr-edr/internal/sysload"
)

// Throttle is how the agent backs off (CLAUDE.md section 2: "Back off on
// battery and under load. Never block the user's work."):
//
//   - on battery the interval is multiplied by BatteryIntervalFactor and,
//     unless KeepHeavyOnBattery, the heavy checks are skipped (they report
//     unknown, and the statement says so);
//   - when the processor was busier than BusyPercent over the last Window,
//     the heartbeat is put off by DeferStep and the load is checked again,
//     for at most MaxDefer, after which the heartbeat is made anyway. A
//     heartbeat is never skipped, only delayed.
//
// Every statement announces its interval and deferral (SPEC 6.5
// schedule), so the receiver does not mistake a back-off for silence.
// Zero values get the defaults below.
type Throttle struct {
	BatteryIntervalFactor int
	KeepHeavyOnBattery    bool
	BusyPercent           int
	Window                time.Duration
	DeferStep             time.Duration
	MaxDefer              time.Duration
}

// Throttle defaults and limits.
const (
	DefaultBatteryIntervalFactor = 2
	DefaultBusyPercent           = 80
	DefaultLoadWindow            = time.Minute
	DefaultDeferStep             = time.Minute
	DefaultMaxDefer              = 5 * time.Minute

	maxBatteryIntervalFactor = 4
	minBusyPercent           = 50
)

// WithDefaults fills zero values and checks the ranges.
func (t Throttle) WithDefaults() (Throttle, error) {
	if t.BatteryIntervalFactor == 0 {
		t.BatteryIntervalFactor = DefaultBatteryIntervalFactor
	}
	if t.BusyPercent == 0 {
		t.BusyPercent = DefaultBusyPercent
	}
	if t.Window == 0 {
		t.Window = DefaultLoadWindow
	}
	if t.DeferStep == 0 {
		t.DeferStep = DefaultDeferStep
	}
	if t.MaxDefer == 0 {
		t.MaxDefer = DefaultMaxDefer
	}
	switch {
	case t.BatteryIntervalFactor < 1 || t.BatteryIntervalFactor > maxBatteryIntervalFactor:
		return t, fmt.Errorf("battery interval factor must be 1 to %d", maxBatteryIntervalFactor)
	case t.BusyPercent < minBusyPercent || t.BusyPercent > 100:
		return t, fmt.Errorf("busy threshold must be %d to 100 percent", minBusyPercent)
	case t.Window < 10*time.Second || t.Window > 5*time.Minute:
		return t, fmt.Errorf("load window must be 10s to 5m")
	case t.DeferStep < 10*time.Second || t.DeferStep > 10*time.Minute:
		return t, fmt.Errorf("defer step must be 10s to 10m")
	case t.MaxDefer < 0 || t.MaxDefer > 30*time.Minute:
		return t, fmt.Errorf("maximum deferral must be 0 to 30m")
	}
	return t, nil
}

// maxDefer is the longest a heartbeat may be put off: the configured
// limit, but never more than a third of the interval, so a deferred
// heartbeat still arrives inside the receiver's grace period.
func (t Throttle) maxDefer(interval time.Duration) time.Duration {
	if limit := interval / 3; t.MaxDefer > limit {
		return limit
	}
	return t.MaxDefer
}

// loadMonitor keeps the last few processor samples. The loop samples when
// it wakes, and wakes once a Window before each heartbeat, so it can tell
// whether the processor was busy over the last Window without a
// background thread.
type loadMonitor struct {
	src     sysload.Source
	window  time.Duration
	samples []loadSample // oldest first, at most maxSamples
}

type loadSample struct {
	at time.Time
	t  sysload.CPUTimes
}

const maxSamples = 4

func (m *loadMonitor) observe(now time.Time) {
	if m == nil || m.src == nil {
		return
	}
	t, err := m.src.CPUTimes()
	if err != nil {
		return
	}
	if n := len(m.samples); n > 0 && !now.After(m.samples[n-1].at) {
		m.samples[n-1] = loadSample{now, t}
		return
	}
	m.samples = append(m.samples, loadSample{now, t})
	if len(m.samples) > maxSamples {
		m.samples = m.samples[len(m.samples)-maxSamples:]
	}
}

// busy samples now and reports the busy share over the window. ok is false
// when there is no sample old enough (just started, or no source); then
// the agent does not defer.
func (m *loadMonitor) busy(now time.Time) (pct int, ok bool) {
	if m == nil || m.src == nil {
		return 0, false
	}
	m.observe(now)
	if len(m.samples) < 2 {
		return 0, false
	}
	cur := m.samples[len(m.samples)-1]
	// The newest sample at least half a window old: normally the one
	// taken a window before the heartbeat.
	for i := len(m.samples) - 2; i >= 0; i-- {
		if cur.at.Sub(m.samples[i].at) >= m.window/2 {
			return sysload.BusyPercent(m.samples[i].t, cur.t)
		}
	}
	return 0, false
}

// plan is what one heartbeat does.
type plan struct {
	interval  time.Duration // announced: the wait before the next heartbeat
	deferred  time.Duration // how long this heartbeat was put off
	skipHeavy bool
}

func (p plan) schedule() proof.Schedule {
	clamp := func(d time.Duration) uint16 {
		s := d / time.Second
		if s > proof.MaxIntervalS {
			s = proof.MaxIntervalS
		}
		return uint16(s)
	}
	return proof.Schedule{IntervalS: clamp(p.interval), DeferredS: clamp(p.deferred), HeavyChecksSkipped: p.skipHeavy}
}

// decide is called when a heartbeat is due (scheduled at due). It returns
// either a plan for a heartbeat now, or how long to defer it.
func (a *Agent) decide(now, due time.Time) (p plan, deferBy time.Duration) {
	th := a.cfg.Throttle
	p.interval = a.cfg.Interval
	if a.cfg.Conditions != nil {
		battery, err := a.cfg.Conditions.OnBattery()
		battery = battery && err == nil // unknown never backs off
		if battery {
			p.interval *= time.Duration(th.BatteryIntervalFactor)
			if max := proof.MaxIntervalS * time.Second; p.interval > max {
				p.interval = max
			}
			p.skipHeavy = !th.KeepHeavyOnBattery
		}
		if battery != a.onBattery {
			a.onBattery = battery
			if battery {
				a.cfg.Logf("on battery: heartbeat every %v, heavy checks skipped: %v", p.interval, p.skipHeavy)
			} else {
				a.cfg.Logf("on mains power (or unknown): heartbeat every %v", p.interval)
			}
		}
	}
	late := now.Sub(due)
	if late < 0 {
		late = 0
	}
	if pct, ok := a.load.busy(now); ok && pct > th.BusyPercent && late+th.DeferStep <= th.maxDefer(a.cfg.Interval) {
		if !a.deferredDue.Equal(due) {
			a.deferredDue = due
			a.cfg.Logf("processor %d%% busy over the last %v: heartbeat deferred (at most %v)", pct, th.Window, th.maxDefer(a.cfg.Interval))
		}
		return p, th.DeferStep
	}
	if a.deferredDue.Equal(due) {
		p.deferred = late
	}
	return p, 0
}
