// Package config is the agent service's settings file,
// <state dir>\agent-config.json. `kovyr-agent service install` writes it
// from its flags (every other value takes its default) and the service
// reads it when it starts. It lives in the state directory, which only
// SYSTEM and Administrators can open, so only an administrator can change
// how the agent behaves.
//
// It holds only the server URL and numbers. It is local configuration,
// not a command channel: nothing the server sends ever reaches it.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/agent"
	"github.com/kendallcoding202/kovyr-edr/internal/fsutil"
	"github.com/kendallcoding202/kovyr-edr/internal/logfile"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// FileName is the settings file in the state directory.
const FileName = "agent-config.json"

const maxFileBytes = 16 << 10

// Settings are the service's settings. Zero-valued fields read from a file
// keep their defaults.
type Settings struct {
	Server      string  `json:"server"`
	DevInsecure bool    `json:"dev_insecure"`
	IntervalS   int     `json:"interval_s"`
	Battery     Battery `json:"battery"`
	Load        Load    `json:"load"`
	Log         Log     `json:"log"`
}

// Battery is the back-off on battery power.
type Battery struct {
	IntervalFactor  int  `json:"interval_factor"`
	SkipHeavyChecks bool `json:"skip_heavy_checks"`
}

// Load is the back-off when the processor is busy.
type Load struct {
	BusyPercent int `json:"busy_percent"`
	WindowS     int `json:"window_s"`
	DeferStepS  int `json:"defer_step_s"`
	MaxDeferS   int `json:"max_defer_s"`
}

// Log caps the service's log files.
type Log struct {
	MaxFileBytes int `json:"max_file_bytes"`
	Files        int `json:"files"`
}

// Defaults are the safe defaults (Server must still be set).
func Defaults() Settings {
	return Settings{
		IntervalS: int(agent.DefaultInterval / time.Second),
		Battery:   Battery{IntervalFactor: agent.DefaultBatteryIntervalFactor, SkipHeavyChecks: true},
		Load: Load{BusyPercent: agent.DefaultBusyPercent, WindowS: int(agent.DefaultLoadWindow / time.Second),
			DeferStepS: int(agent.DefaultDeferStep / time.Second), MaxDeferS: int(agent.DefaultMaxDefer / time.Second)},
		Log: Log{MaxFileBytes: logfile.DefaultMaxBytes, Files: logfile.DefaultFiles},
	}
}

// Path is the settings file in dir.
func Path(dir string) string { return filepath.Join(dir, FileName) }

// Throttle is the back-off these settings ask for.
func (s Settings) Throttle() agent.Throttle {
	sec := func(n int) time.Duration { return time.Duration(n) * time.Second }
	return agent.Throttle{
		BatteryIntervalFactor: s.Battery.IntervalFactor,
		KeepHeavyOnBattery:    !s.Battery.SkipHeavyChecks,
		BusyPercent:           s.Load.BusyPercent,
		Window:                sec(s.Load.WindowS),
		DeferStep:             sec(s.Load.DeferStepS),
		MaxDefer:              sec(s.Load.MaxDeferS),
	}
}

// Interval is the heartbeat interval.
func (s Settings) Interval() time.Duration { return time.Duration(s.IntervalS) * time.Second }

// Validate checks every value against the same rules the agent applies.
func (s Settings) Validate() error {
	if _, err := agent.NewHTTPClient(s.Server, s.DevInsecure); err != nil {
		return err
	}
	if s.IntervalS < proof.MinIntervalS || s.IntervalS > proof.MaxIntervalS {
		return fmt.Errorf("interval_s must be %d to %d", proof.MinIntervalS, proof.MaxIntervalS)
	}
	if s.Load.MaxDeferS < 1 || s.Load.WindowS < 1 || s.Load.DeferStepS < 1 {
		return errors.New("load window_s, defer_step_s and max_defer_s must be positive")
	}
	if _, err := s.Throttle().WithDefaults(); err != nil {
		return err
	}
	if s.Log.MaxFileBytes < logfile.MinMaxBytes || s.Log.MaxFileBytes > logfile.MaxMaxBytes {
		return fmt.Errorf("log max_file_bytes must be %d to %d", logfile.MinMaxBytes, logfile.MaxMaxBytes)
	}
	if s.Log.Files < 1 || s.Log.Files > logfile.MaxFiles {
		return fmt.Errorf("log files must be 1 to %d", logfile.MaxFiles)
	}
	return nil
}

// Read reads and checks the settings file. Unknown fields are refused,
// so a typo cannot silently fall back to a default.
func Read(dir string) (Settings, error) {
	b, err := fsutil.ReadFileCapped(Path(dir), maxFileBytes)
	if err != nil {
		return Settings{}, err
	}
	s := Defaults()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", FileName, err)
	}
	if dec.More() {
		return Settings{}, fmt.Errorf("%s: unexpected data after the settings", FileName)
	}
	if err := s.Validate(); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", FileName, err)
	}
	return s, nil
}

// Write checks and writes the settings file atomically.
func Write(dir string, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(Path(dir), append(b, '\n'))
}
