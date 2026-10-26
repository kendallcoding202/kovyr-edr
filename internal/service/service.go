// Package service runs the agent as a Windows service and installs,
// starts, stops and removes it through the Service Control Manager
// (golang.org/x/sys/windows/svc and svc/mgr).
//
// The service:
//   - runs as LocalSystem, the account that can read every check (the
//     agent stays read-only: it changes no setting and runs no command);
//   - starts automatically, delayed, after the boot rush;
//   - is restarted by Windows after a failure: 1, 5, then 15 minutes, the
//     count resetting after a day, also when it exits with an error code;
//   - stops within StopGrace of a stop or shutdown request, well inside
//     Windows' limit. Everything it writes is crash-safe (atomic files, a
//     queue reconciled at start), so stopping mid-heartbeat loses nothing.
//
// The service binary must sit where only administrators can write
// (Program Files): a service running as LocalSystem from a folder a user
// can write to would let that user run code as SYSTEM.
package service

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Service identity.
const (
	Name        = "KovyrAgent"
	DisplayName = "Kovyr Protection Alarm"
	Description = "Reports this computer's protection status (antivirus, EDR, firewall, BitLocker) in signed heartbeats. " +
		"Read-only: it changes nothing on this computer and accepts no commands."
)

// Recovery: restart after these delays on the first, second and later
// failures; the failure count resets after ResetPeriod.
var RecoveryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}

// ResetPeriod is when Windows forgets earlier failures.
const ResetPeriod = 24 * time.Hour

// StopGrace is how long a stop or shutdown waits for the heartbeat loop
// to finish before the service reports stopped anyway. Windows allows a
// service several seconds at shutdown; this stays inside that.
const StopGrace = 3 * time.Second

// ErrWindowsOnly is returned on other operating systems.
var ErrWindowsOnly = errors.New("the service commands work only on Windows")

// ErrNotInstalled means the service is not installed.
var ErrNotInstalled = errors.New("the Kovyr service is not installed")

// Args is the service's command line after the executable.
func Args(stateDir string) []string { return []string{"service", "run", "--state-dir", stateDir} }

// Status describes the installed service.
type Status struct {
	State             string // stopped, start_pending, stop_pending, running, ...
	PID               uint32
	StartType         string // automatic, manual, disabled, ...
	Delayed           bool
	Account           string
	BinaryPath        string
	Recovery          []time.Duration
	ResetPeriod       time.Duration
	RecoverOnExitCode bool
	ExitCode          uint32 // Win32 exit code of the last stop
	ServiceExitCode   uint32 // service-specific exit code of the last stop
}

// String is the plain-English status for `kovyr-agent service status`.
func (s Status) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s): %s", DisplayName, Name, s.State)
	if s.PID != 0 {
		fmt.Fprintf(&b, ", pid %d", s.PID)
	}
	b.WriteString("\n")
	start := s.StartType
	if s.Delayed {
		start += " (delayed)"
	}
	fmt.Fprintf(&b, "  start:    %s\n", start)
	fmt.Fprintf(&b, "  account:  %s\n", s.Account)
	fmt.Fprintf(&b, "  binary:   %s\n", s.BinaryPath)
	var rec []string
	for _, d := range s.Recovery {
		rec = append(rec, d.String())
	}
	fmt.Fprintf(&b, "  recovery: restart after %s; reset after %s", strings.Join(rec, ", "), s.ResetPeriod)
	if s.RecoverOnExitCode {
		b.WriteString("; also when it exits with an error")
	}
	b.WriteString("\n")
	if s.State == "stopped" && (s.ExitCode != 0 || s.ServiceExitCode != 0) {
		fmt.Fprintf(&b, "  last exit: %d (service code %d)\n", s.ExitCode, s.ServiceExitCode)
	}
	return b.String()
}

// CheckBinaryPath refuses a service binary outside the protected roots
// (Program Files), compared the way Windows compares paths: case-blind,
// either slash, on whole path segments.
func CheckBinaryPath(exe string, protectedRoots []string) error {
	norm := func(p string) string {
		p = strings.ToLower(strings.ReplaceAll(p, "/", `\`))
		return strings.TrimRight(p, `\`)
	}
	e := norm(exe)
	for _, seg := range strings.Split(e, `\`) {
		if seg == ".." || seg == "." {
			return fmt.Errorf("service binary %q is not a clean path", exe)
		}
	}
	for _, root := range protectedRoots {
		if r := norm(root); r != "" && strings.HasPrefix(e, r+`\`) {
			return nil
		}
	}
	return fmt.Errorf("refusing to install %s: a service runs as SYSTEM, so its binary must sit where only administrators can write. "+
		"Copy kovyr-agent.exe to a folder under %s and run the install from there", exe, strings.Join(protectedRoots, " or "))
}
