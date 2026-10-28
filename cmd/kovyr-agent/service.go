package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/agent"
	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/config"
	"github.com/kendallcoding202/kovyr-edr/internal/keystore"
	"github.com/kendallcoding202/kovyr-edr/internal/logfile"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
	"github.com/kendallcoding202/kovyr-edr/internal/service"
	"github.com/kendallcoding202/kovyr-edr/internal/sysload"
)

// Replaced in tests: the service manager and the machine.
var (
	isElevated = service.Elevated
	executable = func() (string, error) {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(exe)
	}
	protectedRoots = service.ProtectedRoots
	svcQuery       = service.Query
	svcInstall     = service.Install
	svcStart       = service.Start
	svcUninstall   = service.Uninstall
)

const serviceUsage = `kovyr-agent service: run the agent as a Windows service

  service install --server URL [--interval 15m] [--dev-insecure]
                  [--watch DIR]... [--no-user-folders] [--state-dir DIR]
                  [--create-key] [--start]
                    register the service (LocalSystem, automatic delayed start,
                    restart on failure) and write DIR\agent-config.json;
                    --watch adds a data folder to the ransomware tripwire;
                    --create-key makes a device key if there is none (an
                    existing key is always kept); --start starts the service
                    and removes it again if it does not start (the installer
                    uses both)
  service uninstall stop and remove the service (the key and state stay)
  service start     start the service and wait until it runs
  service stop      stop the service and wait until it has stopped
  service status    show the service's state and configuration
  service run       what Windows starts; not for use in a console

install, uninstall, start and stop need an elevated (Run as administrator) prompt.
`

// opTimeout bounds waiting for the service manager.
const opTimeout = 30 * time.Second

func cmdService(args []string, defDir string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, serviceUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("kovyr-agent service "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", defDir, "directory for the device key, chain state, queue, settings and logs")
	var server *string
	var interval *time.Duration
	var insecure, noUser, createKey, start *bool
	var watch folderList
	if sub == "install" {
		server = fs.String("server", "", "receiver base URL (https://...)")
		interval = fs.Duration("interval", agent.DefaultInterval, "heartbeat interval (1m to 60m)")
		insecure = fs.Bool("dev-insecure", false, "DEV ONLY: allow plain http to localhost")
		fs.Var(&watch, "watch", "also watch this data folder with the ransomware tripwire (repeatable)")
		noUser = fs.Bool("no-user-folders", false, "do not watch each user's Desktop and Documents")
		createKey = fs.Bool("create-key", false, "make a device key if there is none (an existing key is always kept)")
		start = fs.Bool("start", false, "start the service after installing it (and remove it again if it does not start)")
	}
	if fs.Parse(rest) != nil {
		return 2
	}
	privileged := map[string]bool{"install": true, "uninstall": true, "start": true, "stop": true}
	if privileged[sub] && !isElevated() {
		fmt.Fprintf(stderr, "service %s needs administrator rights: open the prompt with \"Run as administrator\" and try again\n", sub)
		return 2
	}
	switch sub {
	case "install":
		return serviceInstall(installOptions{dir: *dir, server: *server, interval: *interval, insecure: *insecure,
			watch: watch, userFolders: !*noUser, createKey: *createKey, start: *start}, stdout, stderr)
	case "uninstall":
		if err := svcUninstall(opTimeout); err != nil {
			fmt.Fprintln(stderr, "uninstall:", err)
			return 1
		}
		fmt.Fprintf(stdout, "Removed the %s service. The device key and state in %s are kept.\n", service.Name, *dir)
		return 0
	case "start":
		if err := svcStart(opTimeout); err != nil {
			fmt.Fprintln(stderr, "start:", err)
			return 1
		}
		fmt.Fprintln(stdout, "The Kovyr service is running.")
		return 0
	case "stop":
		if err := service.Stop(opTimeout); err != nil {
			fmt.Fprintln(stderr, "stop:", err)
			return 1
		}
		fmt.Fprintln(stdout, "The Kovyr service is stopped.")
		return 0
	case "status":
		st, err := service.Query()
		switch {
		case errors.Is(err, service.ErrNotInstalled):
			fmt.Fprintln(stdout, err)
			return 3
		case err != nil:
			fmt.Fprintln(stderr, "status:", err)
			return 1
		}
		fmt.Fprint(stdout, st)
		return 0
	case "run":
		if !service.IsService() {
			fmt.Fprintln(stderr, "`service run` is started by Windows. In a console, use `kovyr-agent run --server URL`.")
			return 2
		}
		return runService(*dir)
	}
	fmt.Fprintf(stderr, "unknown service command %q\n\n%s", sub, serviceUsage)
	return 2
}

// installOptions are the flags of `service install`.
type installOptions struct {
	dir, server      string
	interval         time.Duration
	insecure         bool
	watch            []string
	userFolders      bool
	createKey, start bool
}

// serviceInstall checks everything it can before it writes anything, then
// makes the device key if asked and there is none, writes the settings,
// registers the service and, if asked, starts it. The MSI installer runs
// it as SYSTEM with --create-key --start, where nobody sees its output, so
// from the moment the state directory exists it also records each step in
// the agent's log.
func serviceInstall(o installOptions, stdout, stderr io.Writer) int {
	if o.server == "" {
		fmt.Fprintln(stderr, "service install needs --server URL")
		return 2
	}
	dir, err := filepath.Abs(o.dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if o.interval%time.Second != 0 {
		fmt.Fprintln(stderr, "the interval must be whole seconds")
		return 2
	}
	s := config.Defaults()
	s.Server, s.DevInsecure, s.IntervalS = o.server, o.insecure, int(o.interval/time.Second)
	s.Tripwire.Folders, s.Tripwire.UserFolders = append([]string{}, o.watch...), o.userFolders
	if err := s.Validate(); err != nil {
		fmt.Fprintln(stderr, "settings:", err)
		return 2
	}
	hasKey := keystore.Exists(dir)
	if !hasKey && !o.createKey {
		fmt.Fprintf(stderr, "no device key in %s: run `kovyr-agent keygen` and enroll the device first\n", dir)
		return 1
	}
	exe, err := executable()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// Refuse a replaceable binary before writing anything.
	if err := service.CheckBinaryPath(exe, protectedRoots()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// An installed service is never overwritten, not even its settings.
	if _, err := svcQuery(); err == nil {
		fmt.Fprintf(stderr, "the %s service is already installed; run `kovyr-agent service uninstall` first\n", service.Name)
		return 1
	}

	// The device key is the device's identity: its enrollment names it. So
	// an existing key is only ever opened, never replaced; one that cannot
	// be opened stops the install and stays as it is. Both paths first
	// check that only SYSTEM and Administrators control the state
	// directory (keystore.CheckDir): one someone else made or can change
	// stops the install before anything is read from it or written to it.
	var signer proof.Signer
	keyNote := "kept the existing device key"
	if hasKey {
		if signer, err = keystore.Load(dir); err != nil {
			if errors.Is(err, keystore.ErrUnsafeDir) {
				return refuseUnsafeDir("install", err, stderr)
			}
			fmt.Fprintf(stderr, "the device key in %s cannot be opened (%v); it is left as it is. "+
				"Delete it by hand only if you mean to re-enroll this device.\n", dir, err)
			return 1
		}
	} else {
		if signer, err = keystore.Generate(dir); err != nil {
			if errors.Is(err, keystore.ErrUnsafeDir) {
				return refuseUnsafeDir("install", err, stderr)
			}
			fmt.Fprintln(stderr, "keygen:", err)
			return 1
		}
		keyNote = "created a new device key"
	}
	// The state directory exists now, and only SYSTEM and Administrators
	// control it, so the log can go inside it.
	say := installLog(dir, stdout)
	defer say.close()
	fail := func(format string, a ...any) int {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintln(stderr, msg)
		say.log("install failed: " + msg)
		return 1
	}
	id := proof.DeviceID(signer.Public())
	say.both("Device %s: %s (in %s). Enroll it with: kovyr-agent enroll --print-pubkey", id, keyNote, dir)

	if err := config.Write(dir, s); err != nil {
		return fail("settings: %v", err)
	}
	say.both("Settings: %s (server %s, every %v; tripwire %s, %d extra folder(s)).",
		config.Path(dir), s.Server, s.Interval(), onOff(s.Tripwire.Enabled), len(s.Tripwire.Folders))
	if err := svcInstall(exe, dir); err != nil {
		return fail("install: %v", err)
	}
	say.both("Installed the %s service (%s): LocalSystem, automatic delayed start, restarts on failure.", service.Name, service.DisplayName)
	say.out("Logs: %s.", filepath.Join(dir, "logs"))
	if !o.start {
		say.out("Start it now with: kovyr-agent service start")
		return 0
	}
	if err := svcStart(opTimeout); err != nil {
		// Leave nothing half done: a service that cannot start is removed
		// again. The key and settings stay for the next try.
		if uerr := svcUninstall(opTimeout); uerr != nil {
			return fail("start: %v; removing the service again also failed: %v", err, uerr)
		}
		return fail("start: %v; the service was removed again", err)
	}
	say.both("The %s service is running.", service.Name)
	return 0
}

// refuseUnsafeDir reports a state directory the agent will not use. Its
// own log is in that directory, so the reason also goes to the Windows
// event log, where an administrator finds it after a failed MSI install.
func refuseUnsafeDir(step string, err error, stderr io.Writer) int {
	fmt.Fprintf(stderr, "%s: %v\n", step, err)
	service.ReportError(fmt.Sprintf("Kovyr Protection Alarm %s refused: %v", step, err))
	return 1
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// installRecorder writes install steps to the console and, when it could
// be opened, the agent's log. What it logs is the agent's own business:
// the device ID, its state directory, the server URL and outcomes.
type installRecorder struct {
	stdout io.Writer
	lf     *logfile.Writer
	logger *log.Logger
}

// installLog opens the agent's log in dir. A log that cannot be opened
// never stops the install: the console still gets everything.
func installLog(dir string, stdout io.Writer) *installRecorder {
	r := &installRecorder{stdout: stdout}
	lc := config.Defaults().Log
	if lf, err := logfile.Open(filepath.Join(dir, "logs"), int64(lc.MaxFileBytes), lc.Files); err == nil {
		r.lf, r.logger = lf, log.New(lf, "kovyr-agent: ", log.LstdFlags|log.LUTC)
	}
	return r
}

func (r *installRecorder) out(format string, a ...any) { fmt.Fprintf(r.stdout, format+"\n", a...) }

func (r *installRecorder) log(msg string) {
	if r.logger != nil {
		r.logger.Print("service install: " + msg)
	}
}

func (r *installRecorder) both(format string, a ...any) {
	r.out(format, a...)
	r.log(fmt.Sprintf(format, a...))
}

func (r *installRecorder) close() {
	if r.lf != nil {
		r.lf.Close()
	}
}

// runService is the process Windows starts. The state directory is
// checked first (keystore.CheckDir: only SYSTEM and Administrators may
// control it, and a loose access list is repaired), before its settings,
// log or key are touched. Then the log is opened, so every later failure
// is recorded.
func runService(dir string) int {
	if err := keystore.CheckDir(dir); err != nil {
		// Nowhere safe to log: the reason goes to the event log, and the
		// service reports a failed start, so Windows' recovery actions
		// try again later.
		service.ReportError(fmt.Sprintf("The Kovyr Protection Alarm service did not start: %v", err))
		service.Run(func(context.Context) error { return err }, func(string, ...any) {})
		return 1
	}
	s, serr := config.Read(dir)
	lc := config.Defaults().Log
	if serr == nil {
		lc = s.Log
	}
	lf, err := logfile.Open(filepath.Join(dir, "logs"), int64(lc.MaxFileBytes), lc.Files)
	if err != nil {
		return 1 // nowhere to log; the exit code reaches the service manager
	}
	defer lf.Close()
	logger := log.New(lf, "kovyr-agent: ", log.LstdFlags|log.LUTC)
	err = service.Run(func(ctx context.Context) error {
		if serr != nil {
			return serr
		}
		return serviceMain(ctx, dir, s, logger)
	}, logger.Printf)
	if err != nil {
		logger.Printf("service: %v", err)
		return 1
	}
	return 0
}

// serviceMain is the heartbeat loop the service runs, until ctx ends.
func serviceMain(ctx context.Context, dir string, s config.Settings, logger *log.Logger) error {
	client, err := agent.NewHTTPClient(s.Server, s.DevInsecure)
	if err != nil {
		return err
	}
	signer, err := keystore.Load(dir)
	if err != nil {
		return err
	}
	trip, stopTrip := startTripwire(s.Tripwire, logger.Printf)
	defer stopTrip()
	a, err := agent.New(agent.Config{Dir: dir, Interval: s.Interval(), Throttle: s.Throttle(),
		Conditions: sysload.System(), Tripwire: trip, Logf: logger.Printf}, signer, checks.NewRunner(systemProbes()), client)
	if err != nil {
		return err
	}
	logger.Printf("device %s (agent %d.%d.%d) reporting to %s every %v (read-only; accepts no commands)",
		proof.DeviceID(signer.Public()), agent.Version.Major, agent.Version.Minor, agent.Version.Patch, s.Server, s.Interval())
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
