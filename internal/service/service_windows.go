package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// Elevated reports whether this process runs with an elevated
// (administrator) token. Installing, removing, starting and stopping a
// service need one.
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// ProtectedRoots are the folders where only administrators can write.
func ProtectedRoots() []string {
	var out []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		if p, err := windows.KnownFolderPath(id, 0); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// IsService reports whether this process was started by the Service
// Control Manager.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Install registers the service: LocalSystem, automatic delayed start,
// restart on failure. exe must be under ProtectedRoots.
func Install(exe, stateDir string) error {
	if err := CheckBinaryPath(exe, ProtectedRoots()); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		return errors.New("the Kovyr service is already installed; run `kovyr-agent service uninstall` first")
	}
	s, err := m.CreateService(Name, exe, mgr.Config{
		DisplayName:      DisplayName,
		Description:      Description,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ErrorControl:     mgr.ErrorNormal,
		// ServiceStartName empty: LocalSystem. A per-service SID lets
		// ACLs name this service later.
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, Args(stateDir)...)
	if err != nil {
		return fmt.Errorf("create the service: %w", err)
	}
	defer s.Close()
	var actions []mgr.RecoveryAction
	for _, d := range RecoveryDelays {
		actions = append(actions, mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: d})
	}
	if err := s.SetRecoveryActions(actions, uint32(ResetPeriod/time.Second)); err != nil {
		s.Delete()
		return fmt.Errorf("set recovery actions: %w", err)
	}
	// Recovery applies also when the service stops itself with an error
	// code, not only when the process crashes.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		s.Delete()
		return fmt.Errorf("set recovery on error exits: %w", err)
	}
	return nil
}

// ReportError writes msg to the Windows Application event log, source
// KovyrAgent. It is for failures nobody would otherwise see: the MSI does
// not show the install step's output, and a state folder that is not safe
// cannot hold the agent's own log. Best effort; it registers nothing, so
// Event Viewer prefixes the text with a note that the source is unknown.
func ReportError(msg string) {
	l, err := eventlog.Open(Name)
	if err != nil {
		return
	}
	defer l.Close()
	l.Error(1, msg)
}

// Uninstall stops the service if it runs and removes it. The state
// directory (device key, chain, queue, settings, logs) is left in place.
func Uninstall(timeout time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return ErrNotInstalled
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if err := stop(s, timeout); err != nil {
			return err
		}
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete the service: %w", err)
	}
	return nil
}

// Start starts the service and waits until it runs.
func Start(timeout time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return ErrNotInstalled
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			return nil
		case svc.Stopped:
			return fmt.Errorf("the service stopped while starting (exit code %d, service code %d); see its log",
				st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the service did not start within %v (state %s)", timeout, stateName(st.State))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Stop stops the service and waits until it has stopped.
func Stop(timeout time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return ErrNotInstalled
	}
	defer s.Close()
	return stop(s, timeout)
}

func stop(s *mgr.Service, timeout time.Duration) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		if q, qerr := s.Query(); qerr == nil && q.State == svc.Stopped {
			return nil
		}
		return fmt.Errorf("stop: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("the service did not stop within %v (state %s)", timeout, stateName(st.State))
		}
		time.Sleep(100 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

// Query describes the installed service. It needs no elevation.
func Query() (Status, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Status{}, fmt.Errorf("connect to the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(h)
	name, _ := windows.UTF16PtrFromString(Name)
	sh, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return Status{}, ErrNotInstalled
		}
		return Status{}, err
	}
	s := &mgr.Service{Name: Name, Handle: sh}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return Status{}, err
	}
	cfg, err := s.Config()
	if err != nil {
		return Status{}, err
	}
	out := Status{
		State: stateName(st.State), PID: st.ProcessId,
		StartType: startName(cfg.StartType), Delayed: cfg.DelayedAutoStart,
		Account: cfg.ServiceStartName, BinaryPath: cfg.BinaryPathName,
		ExitCode: st.Win32ExitCode, ServiceExitCode: st.ServiceSpecificExitCode,
	}
	if acts, err := s.RecoveryActions(); err == nil {
		for _, a := range acts {
			if a.Type == mgr.ServiceRestart {
				out.Recovery = append(out.Recovery, a.Delay)
			}
		}
	}
	if p, err := s.ResetPeriod(); err == nil {
		out.ResetPeriod = time.Duration(p) * time.Second
	}
	if f, err := s.RecoveryActionsOnNonCrashFailures(); err == nil {
		out.RecoverOnExitCode = f
	}
	return out, nil
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start_pending"
	case svc.StopPending:
		return "stop_pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue_pending"
	case svc.PausePending:
		return "pause_pending"
	case svc.Paused:
		return "paused"
	}
	return fmt.Sprintf("state_%d", s)
}

func startName(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "automatic"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	}
	return fmt.Sprintf("start_type_%d", t)
}

// Run runs main as the service until Windows asks it to stop. It returns
// when the service has stopped.
func Run(main func(ctx context.Context) error, logf func(string, ...any)) error {
	return svc.Run(Name, &handler{main: main, logf: logf, grace: StopGrace})
}

// handler is the service control handler. It accepts only stop and
// shutdown (and answers interrogate): there is nothing else to control.
type handler struct {
	main  func(ctx context.Context) error
	logf  func(string, ...any)
	grace time.Duration
}

// Exit codes the service reports when it stops itself.
const exitAgentFailed = 1

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending, WaitHint: 10000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.main(ctx) }()
	running := svc.Status{State: svc.Running, Accepts: accepts}
	s <- running
	h.logf("service running")
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- running
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending, WaitHint: uint32((h.grace + time.Second) / time.Millisecond)}
				cancel()
				select {
				case <-done:
					h.logf("service stopped (%s)", cmdName(c.Cmd))
				case <-time.After(h.grace):
					// The loop is inside a heartbeat (a slow WMI query or
					// upload). Its files are crash-safe, so stop anyway.
					h.logf("service stopped (%s) without waiting for the current heartbeat", cmdName(c.Cmd))
				}
				return false, 0
			default:
				h.logf("ignored service control %d", c.Cmd)
			}
		case err := <-done:
			// The agent ended by itself (bad settings, no key): report a
			// failure, so the recovery actions restart it later.
			h.logf("agent stopped: %v", err)
			s <- svc.Status{State: svc.StopPending}
			return true, exitAgentFailed
		}
	}
}

func cmdName(c svc.Cmd) string {
	if c == svc.Shutdown {
		return "shutdown"
	}
	return "stop"
}
