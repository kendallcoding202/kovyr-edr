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
)

// clockedLoad is a sysload.Source whose processor counters advance with
// the fake clock, busy as busyAt says at each moment.
type clockedLoad struct {
	mu      sync.Mutex
	clk     *fakeClock
	busyAt  func(t time.Time) int
	battery func(t time.Time) (bool, error)
	last    time.Time
	times   sysload.CPUTimes
}

func (c *clockedLoad) OnBattery() (bool, error) {
	if c.battery == nil {
		return false, nil
	}
	return c.battery(c.clk.Now())
}

func (c *clockedLoad) CPUTimes() (sysload.CPUTimes, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clk.Now()
	if !c.last.IsZero() && now.After(c.last) {
		ticks := uint64(now.Sub(c.last) / 100) // 100 ns ticks, one processor
		c.times.Total += ticks
		c.times.Idle += ticks * uint64(100-c.busyAt(c.last)) / 100
	}
	c.last = now
	return c.times, nil
}

var t0 = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

// runFor runs the loop until the fake clock passes d, and returns the
// delivered statements. Pick d just after a heartbeat, so the wake that
// crosses it is a load sample and the count does not depend on which of
// two ready channels select picks.
func runFor(t *testing.T, d time.Duration, cfg Config, src func(*fakeClock) sysload.Source) []*proof.Statement {
	t.Helper()
	tr := &fakeTransport{}
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{now: t0}
	clk.onWait = func(int) {
		if clk.Now().Sub(t0) >= d {
			cancel()
			clk.stop()
		}
	}
	cfg.Dir, cfg.Clock = t.TempDir(), clk
	if src != nil {
		cfg.Conditions = src(clk)
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
	for _, env := range tr.posted {
		_, st := decode(t, env)
		out = append(out, st)
	}
	for i, st := range out {
		if st.Seq != uint32(i+1) {
			t.Fatalf("statement %d has seq %d: a heartbeat was skipped or reordered", i, st.Seq)
		}
	}
	return out
}

func TestOnBatteryTheIntervalDoublesAndHeavyChecksAreSkipped(t *testing.T) {
	unplugAt := t0.Add(time.Hour)
	sts := runFor(t, 3*time.Hour+time.Minute, Config{}, func(clk *fakeClock) sysload.Source {
		return &clockedLoad{clk: clk, busyAt: func(time.Time) int { return 5 },
			battery: func(now time.Time) (bool, error) { return !now.Before(unplugAt), nil }}
	})
	var mains, battery int
	for i, st := range sts {
		onBattery := !st.ObservedAt.Before(unplugAt)
		want := proof.Schedule{IntervalS: 900}
		if onBattery {
			want = proof.Schedule{IntervalS: 1800, HeavyChecksSkipped: true}
			battery++
			if st.Readings.BitLocker != proof.VolumeUnknown || st.Readings.MemoryIntegrity != proof.ToggleUnknown {
				t.Errorf("statement %d: heavy checks ran on battery", i)
			}
			if st.Readings.Defender.RealTime != proof.ToggleOn {
				t.Errorf("statement %d: light checks did not run on battery", i)
			}
		} else {
			mains++
			if st.Readings.BitLocker != proof.VolumeOn {
				t.Errorf("statement %d: heavy checks skipped on mains power", i)
			}
		}
		if st.Schedule != want {
			t.Errorf("statement %d at %v: schedule %+v, want %+v", i, st.ObservedAt.Sub(t0), st.Schedule, want)
		}
		if i > 0 {
			gap := st.ObservedAt.Sub(sts[i-1].ObservedAt)
			if gap != time.Duration(sts[i-1].Schedule.IntervalS)*time.Second {
				t.Errorf("statement %d came %v after the previous one, which announced %ds", i, gap, sts[i-1].Schedule.IntervalS)
			}
		}
	}
	if mains != 4 || battery != 5 { // 0, 15, 30, 45 min on mains; 60, 90, 120, 150, 180 on battery
		t.Errorf("%d statements on mains, %d on battery", mains, battery)
	}
}

func TestBatteryCanKeepHeavyChecks(t *testing.T) {
	sts := runFor(t, time.Hour+time.Minute, Config{Throttle: Throttle{KeepHeavyOnBattery: true, BatteryIntervalFactor: 3}}, func(clk *fakeClock) sysload.Source {
		return &clockedLoad{clk: clk, busyAt: func(time.Time) int { return 5 }, battery: func(time.Time) (bool, error) { return true, nil }}
	})
	for _, st := range sts {
		if st.Schedule != (proof.Schedule{IntervalS: 2700}) || st.Readings.BitLocker != proof.VolumeOn {
			t.Fatalf("schedule %+v bitlocker %s", st.Schedule, st.Readings.BitLocker)
		}
	}
}

func TestUnknownPowerNeverBacksOff(t *testing.T) {
	sts := runFor(t, time.Hour+time.Minute, Config{}, func(clk *fakeClock) sysload.Source {
		return &clockedLoad{clk: clk, busyAt: func(time.Time) int { return 5 },
			battery: func(time.Time) (bool, error) { return true, errors.New("no power status") }}
	})
	for _, st := range sts {
		if st.Schedule != (proof.Schedule{IntervalS: 900}) {
			t.Fatalf("unknown power changed the schedule: %+v", st.Schedule)
		}
	}
}

func TestBusyProcessorDefersButNeverSkips(t *testing.T) {
	sts := runFor(t, 2*time.Hour+time.Minute, Config{}, func(clk *fakeClock) sysload.Source {
		return &clockedLoad{clk: clk, busyAt: func(time.Time) int { return 95 }}
	})
	// The first heartbeat has no load history and goes at once. Every
	// later one is deferred as long as allowed (5 minutes), then made:
	// one every 20 minutes, none skipped.
	if len(sts) != 7 {
		t.Fatalf("%d heartbeats in two hours of full load, want 7", len(sts))
	}
	if sts[0].Schedule.DeferredS != 0 {
		t.Errorf("first heartbeat deferred %ds", sts[0].Schedule.DeferredS)
	}
	for i, st := range sts[1:] {
		if st.Schedule.DeferredS != 300 || st.Schedule.IntervalS != 900 {
			t.Errorf("heartbeat %d: schedule %+v, want 300s deferral of a 900s interval", i+1, st.Schedule)
		}
		if gap := st.ObservedAt.Sub(sts[i].ObservedAt); gap != 20*time.Minute {
			t.Errorf("heartbeat %d came %v after the previous one", i+1, gap)
		}
	}
}

func TestShortLoadSpikeDefersOnlyWhileBusy(t *testing.T) {
	// Busy from 13:30 to 17:00 after the start. The 15-minute heartbeat
	// waits until a whole load window (one minute) has been calm: at
	// 18:00, three minutes late.
	sts := runFor(t, 40*time.Minute, Config{}, func(clk *fakeClock) sysload.Source {
		return &clockedLoad{clk: clk, busyAt: func(at time.Time) int {
			if e := at.Sub(t0); e >= 13*time.Minute+30*time.Second && e < 17*time.Minute {
				return 99
			}
			return 10
		}}
	})
	if len(sts) < 2 || sts[1].Schedule.DeferredS != 180 || sts[1].ObservedAt.Sub(t0) != 18*time.Minute {
		t.Fatalf("second heartbeat: %+v at %v", sts[1].Schedule, sts[1].ObservedAt.Sub(t0))
	}
	// The interval restarts from the late heartbeat.
	if len(sts) < 3 || sts[2].ObservedAt.Sub(sts[1].ObservedAt) != 15*time.Minute || sts[2].Schedule.DeferredS != 0 {
		t.Fatalf("third heartbeat: %+v at %v", sts[2].Schedule, sts[2].ObservedAt.Sub(t0))
	}
}

func TestModerateLoadDoesNotDefer(t *testing.T) {
	sts := runFor(t, time.Hour+time.Minute, Config{}, func(clk *fakeClock) sysload.Source {
		return &clockedLoad{clk: clk, busyAt: func(time.Time) int { return 80 }} // at the threshold, not over
	})
	for _, st := range sts {
		if st.Schedule.DeferredS != 0 {
			t.Fatalf("deferred at 80%% load: %+v", st.Schedule)
		}
	}
}

func TestDeferralIsCappedAtAThirdOfTheInterval(t *testing.T) {
	th, _ := Throttle{}.withDefaults()
	if got := th.maxDefer(15 * time.Minute); got != 5*time.Minute {
		t.Errorf("15m interval: max defer %v", got)
	}
	if got := th.maxDefer(6 * time.Minute); got != 2*time.Minute {
		t.Errorf("6m interval: max defer %v", got)
	}
	// With a 2-minute interval the cap (40s) is below one defer step, so a
	// busy machine is never deferred at all.
	sts := runFor(t, 20*time.Minute+30*time.Second, Config{Interval: 2 * time.Minute}, func(clk *fakeClock) sysload.Source {
		return &clockedLoad{clk: clk, busyAt: func(time.Time) int { return 100 }}
	})
	if len(sts) != 11 {
		t.Fatalf("%d heartbeats in 20 minutes at a 2-minute interval", len(sts))
	}
}

func TestThrottleConfigIsValidated(t *testing.T) {
	for name, th := range map[string]Throttle{
		"factor 5":       {BatteryIntervalFactor: 5},
		"factor -1":      {BatteryIntervalFactor: -1},
		"busy 20":        {BusyPercent: 20},
		"busy 101":       {BusyPercent: 101},
		"window 1s":      {Window: time.Second},
		"window 1h":      {Window: time.Hour},
		"step 1s":        {DeferStep: time.Second},
		"max defer 2h":   {MaxDefer: 2 * time.Hour},
		"max defer -1ns": {MaxDefer: -1},
	} {
		if _, err := New(Config{Dir: t.TempDir(), Throttle: th}, newSigner(t), checks.NewRunner(checks.HealthyFake()), &fakeTransport{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	th, err := Throttle{}.withDefaults()
	if err != nil || th != (Throttle{BatteryIntervalFactor: 2, BusyPercent: 80, Window: time.Minute, DeferStep: time.Minute, MaxDefer: 5 * time.Minute}) {
		t.Fatalf("defaults %+v %v", th, err)
	}
}

func TestBatteryIntervalIsCappedAtTheSpecMaximum(t *testing.T) {
	sts := runFor(t, 3*time.Hour+time.Minute, Config{Interval: 45 * time.Minute}, func(clk *fakeClock) sysload.Source {
		return &clockedLoad{clk: clk, busyAt: func(time.Time) int { return 5 }, battery: func(time.Time) (bool, error) { return true, nil }}
	})
	if len(sts) != 4 { // 0, 60, 120, 180 minutes
		t.Fatalf("%d heartbeats", len(sts))
	}
	for _, st := range sts {
		if st.Schedule.IntervalS != proof.MaxIntervalS {
			t.Fatalf("interval %ds, want the %ds cap", st.Schedule.IntervalS, proof.MaxIntervalS)
		}
	}
}

// slowTransport takes a long time to deliver, moving the fake clock.
type slowTransport struct {
	fakeTransport
	clk   *fakeClock
	delay func(n int) time.Duration
	n     int
}

func (s *slowTransport) PostHeartbeat(ctx context.Context, env []byte) error {
	s.n++
	if d := s.delay(s.n); d > 0 {
		s.clk.mu.Lock()
		s.clk.now = s.clk.now.Add(d)
		s.clk.mu.Unlock()
	}
	return s.fakeTransport.PostHeartbeat(ctx, env)
}

// deferred_s means "put off because the processor was busy" (SPEC 6.5).
// A heartbeat that is late because an upload took long is not a
// deferral.
func TestLateHeartbeatIsNotReportedAsADeferral(t *testing.T) {
	clk := &fakeClock{now: t0}
	tr := &slowTransport{clk: clk, delay: func(n int) time.Duration {
		if n == 1 {
			return 20 * time.Minute // the first upload hangs past the next heartbeat
		}
		return 0
	}}
	ctx, cancel := context.WithCancel(context.Background())
	clk.onWait = func(int) {
		if clk.Now().Sub(t0) >= 30*time.Minute {
			cancel()
			clk.stop()
		}
	}
	src := &clockedLoad{clk: clk, busyAt: func(time.Time) int { return 5 }}
	a, err := New(Config{Dir: t.TempDir(), Clock: clk, Conditions: src}, newSigner(t), checks.NewRunner(checks.HealthyFake()), tr)
	if err != nil {
		t.Fatal(err)
	}
	a.Run(ctx)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.posted) < 2 {
		t.Fatalf("%d heartbeats", len(tr.posted))
	}
	_, st := decode(t, tr.posted[1])
	if st.ObservedAt.Sub(t0) != 20*time.Minute || st.Schedule.DeferredS != 0 {
		t.Fatalf("second heartbeat at %v with deferred_s %d; a slow upload is not a load deferral", st.ObservedAt.Sub(t0), st.Schedule.DeferredS)
	}
}

// busy looks back about one window: a sample only seconds old does not
// decide, so a short burst right before the heartbeat does not defer it.
func TestLoadIsJudgedOverTheWindowNotTheLastFewSeconds(t *testing.T) {
	f := &sysload.Fake{}
	m := &loadMonitor{src: f, window: time.Minute}
	m.observe(t0)
	f.Advance(55*10_000_000, 2) // 55 s nearly idle
	m.observe(t0.Add(55 * time.Second))
	f.Advance(5*10_000_000, 100) // then 5 s flat out
	pct, ok := m.busy(t0.Add(time.Minute))
	if !ok || pct > 20 {
		t.Fatalf("busy %d%% (%v): judged on the last 5 seconds, not the minute", pct, ok)
	}
	// With only a too-recent sample there is no judgement at all.
	m2 := &loadMonitor{src: f, window: time.Minute}
	m2.observe(t0)
	if _, ok := m2.busy(t0.Add(10 * time.Second)); ok {
		t.Fatal("judged load over 10 seconds")
	}
	// No source: never busy.
	var none *loadMonitor
	if _, ok := none.busy(t0); ok {
		t.Fatal("a missing monitor reported load")
	}
}
