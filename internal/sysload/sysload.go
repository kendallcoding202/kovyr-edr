// Package sysload reads, read-only, the two machine conditions the agent
// backs off under: running on battery, and a busy processor (CLAUDE.md
// section 2: "Back off on battery and under load. Never block the user's
// work.").
//
// The Windows source (sysload_windows.go) calls GetSystemPowerStatus and
// GetSystemTimes; elsewhere both are unknown, and unknown never causes a
// back-off. Fake drives the tests on any OS.
package sysload

import (
	"errors"
	"sync"
)

// ErrUnknown means the condition cannot be read on this machine.
var ErrUnknown = errors.New("not known on this machine")

// CPUTimes are cumulative processor times in 100-nanosecond ticks, summed
// over all processors, as GetSystemTimes reports them. Total includes
// Idle.
type CPUTimes struct {
	Idle, Total uint64
}

// Source reads the conditions. Both calls are cheap (one system call) and
// never block.
type Source interface {
	// OnBattery reports whether the machine runs on battery power now.
	OnBattery() (bool, error)
	// CPUTimes returns the cumulative processor times.
	CPUTimes() (CPUTimes, error)
}

// BusyPercent is the share of processor time that was not idle between
// two samples, 0 to 100. ok is false when it cannot be computed (no time
// passed, or the counters went backwards).
func BusyPercent(from, to CPUTimes) (pct int, ok bool) {
	if to.Total <= from.Total || to.Idle < from.Idle {
		return 0, false
	}
	total := to.Total - from.Total
	idle := to.Idle - from.Idle
	if idle > total {
		return 0, false
	}
	return int((total - idle) * 100 / total), true
}

// Fake is a Source for tests. Advance moves its processor counters as if
// the given share of time had been busy.
type Fake struct {
	mu         sync.Mutex
	Battery    bool
	BatteryErr error
	TimesErr   error
	times      CPUTimes
}

func (f *Fake) OnBattery() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Battery, f.BatteryErr
}

func (f *Fake) CPUTimes() (CPUTimes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.times, f.TimesErr
}

// SetBattery switches the fake to battery or mains power.
func (f *Fake) SetBattery(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Battery = on
}

// Advance adds ticks of processor time, busyPct percent of it busy.
func (f *Fake) Advance(ticks uint64, busyPct int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.times.Total += ticks
	f.times.Idle += ticks * uint64(100-busyPct) / 100
}
