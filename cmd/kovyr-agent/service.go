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

// Replaced in tests.
var (
	isElevated = service.Elevated
	executable = func() (string, error) {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(exe)
	}
)

const serviceUsage = `kovyr-agent service: run the agent as a Windows service

  service install --server URL [--interval 15m] [--dev-insecure]
                  [--watch DIR]... [--no-user-folders] [--state-dir DIR]
                    register the service (LocalSystem, automatic delayed start,
                    restart on failure) and write DIR\agent-config.json;
                    --watch adds a data folder to the ransomware tripwire
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
	var insecure, noUser *bool
	var watch folderList
	if sub == "install" {
		server = fs.String("server", "", "receiver base URL (https://...)")
		interval = fs.Duration("interval", agent.DefaultInterval, "heartbeat interval (1m to 60m)")
		insecure = fs.Bool("dev-insecure", false, "DEV ONLY: allow plain http to localhost")
		fs.Var(&watch, "watch", "also watch this data folder with the ransomware tripwire (repeatable)")
		noUser = fs.Bool("no-user-folders", false, "do not watch each user's Desktop and Documents")
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
		return serviceInstall(*dir, *server, *interval, *insecure, watch, !*noUser, stdout, stderr)
	case "uninstall":
		if err := service.Uninstall(opTimeout); err != nil {
			fmt.Fprintln(stderr, "uninstall:", err)
			return 1
		}
		fmt.Fprintf(stdout, "Removed the %s service. The device key and state in %s are kept.\n", service.Name, *dir)
		return 0
	case "start":
		if err := service.Start(opTimeout); err != nil {
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

func serviceInstall(dir, server string, interval time.Duration, insecure bool, watch []string, userFolders bool, stdout, stderr io.Writer) int {
	if server == "" {
		fmt.Fprintln(stderr, "service install needs --server URL")
		return 2
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	dir = abs
	if interval%time.Second != 0 {
		fmt.Fprintln(stderr, "the interval must be whole seconds")
		return 2
	}
	s := config.Defaults()
	s.Server, s.DevInsecure, s.IntervalS = server, insecure, int(interval/time.Second)
	s.Tripwire.Folders, s.Tripwire.UserFolders = append([]string{}, watch...), userFolders
	if err := s.Validate(); err != nil {
		fmt.Fprintln(stderr, "settings:", err)
		return 2
	}
	if !keystore.Exists(dir) {
		fmt.Fprintf(stderr, "no device key in %s: run `kovyr-agent keygen` and enroll the device first\n", dir)
		return 1
	}
	exe, err := executable()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// Refuse a replaceable binary before writing anything.
	if err := service.CheckBinaryPath(exe, service.ProtectedRoots()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := config.Write(dir, s); err != nil {
		fmt.Fprintln(stderr, "settings:", err)
		return 1
	}
	if err := service.Install(exe, dir); err != nil {
		fmt.Fprintln(stderr, "install:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Installed the %s service (%s): LocalSystem, automatic delayed start, restarts on failure.\n", service.Name, service.DisplayName)
	fmt.Fprintf(stdout, "Settings: %s. Logs: %s.\n", config.Path(dir), filepath.Join(dir, "logs"))
	fmt.Fprintln(stdout, "Start it now with: kovyr-agent service start")
	return 0
}

// runService is the process Windows starts. Its log is opened first, so
// every later failure is recorded.
func runService(dir string) int {
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
