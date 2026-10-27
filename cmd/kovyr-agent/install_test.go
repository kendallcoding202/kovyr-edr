package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/agent"
	"github.com/kendallcoding202/kovyr-edr/internal/config"
	"github.com/kendallcoding202/kovyr-edr/internal/keystore"
	"github.com/kendallcoding202/kovyr-edr/internal/service"
)

// fakeSCM stands in for the service manager and the machine, so the
// install flow the MSI runs (`service install --create-key --start`) is
// tested on any OS.
type fakeSCM struct {
	installed bool
	startErr  error
	calls     []string
}

func useFakeSCM(t *testing.T) *fakeSCM {
	t.Helper()
	asAdmin(t, true)
	f := &fakeSCM{}
	oldExe, oldRoots, oldQ, oldI, oldS, oldU := executable, protectedRoots, svcQuery, svcInstall, svcStart, svcUninstall
	t.Cleanup(func() {
		executable, protectedRoots, svcQuery, svcInstall, svcStart, svcUninstall = oldExe, oldRoots, oldQ, oldI, oldS, oldU
	})
	executable = func() (string, error) { return `C:\Program Files\Kovyr\kovyr-agent.exe`, nil }
	protectedRoots = func() []string { return []string{`C:\Program Files`} }
	svcQuery = func() (service.Status, error) {
		if f.installed {
			return service.Status{State: "running"}, nil
		}
		return service.Status{}, service.ErrNotInstalled
	}
	svcInstall = func(exe, dir string) error {
		f.calls = append(f.calls, "install")
		f.installed = true
		return nil
	}
	svcStart = func(time.Duration) error {
		f.calls = append(f.calls, "start")
		return f.startErr
	}
	svcUninstall = func(time.Duration) error {
		f.calls = append(f.calls, "uninstall")
		f.installed = false
		return nil
	}
	return f
}

// skipWithoutKeyStore skips on a Windows test process that is not
// elevated, where the key store cannot set its ACL.
func skipWithoutKeyStore(t *testing.T, errs string) {
	t.Helper()
	if runtime.GOOS == "windows" && strings.Contains(errs, "administrator") {
		t.Skip("needs an elevated process on Windows")
	}
}

func installArgs(dir string, extra ...string) []string {
	return append([]string{"service", "install", "--server", "https://agent.example/api/agent", "--state-dir", dir}, extra...)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The MSI's install: a fresh machine gets a new key, a reinstall keeps
// the old one, so the device keeps its identity and its enrollment.
func TestInstallCreatesAKeyOnlyWhenThereIsNone(t *testing.T) {
	f := useFakeSCM(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	code, out, errs := runCLI(t, installArgs(dir, "--create-key", "--start")...)
	skipWithoutKeyStore(t, errs)
	if code != 0 {
		t.Fatalf("first install: exit %d\n%s%s", code, out, errs)
	}
	if !slices.Equal(f.calls, []string{"install", "start"}) {
		t.Fatalf("calls %v", f.calls)
	}
	key := readFile(t, keystore.Path(dir))
	s, err := config.Read(dir)
	if err != nil || s.Server != "https://agent.example/api/agent" || s.IntervalS != 900 {
		t.Fatalf("settings %+v %v", s, err)
	}
	_, pub, _ := runCLI(t, "enroll", "--print-pubkey", "--state-dir", dir)
	var id string
	for _, l := range strings.Split(pub, "\n") {
		if strings.Contains(l, `"device_id"`) {
			id = strings.Trim(strings.TrimSpace(strings.SplitN(l, ":", 2)[1]), `",`)
		}
	}
	if id == "" || !strings.Contains(out, id) || !strings.Contains(out, "created a new device key") {
		t.Fatalf("install output does not name the new device %q:\n%s", id, out)
	}
	logText := string(readFile(t, filepath.Join(dir, "logs", "agent.log")))
	for _, want := range []string{"service install: Device " + id + ": created a new device key",
		"service install: Installed the KovyrAgent service", "service install: The KovyrAgent service is running"} {
		if !strings.Contains(logText, want) {
			t.Errorf("agent log lacks %q:\n%s", want, logText)
		}
	}

	// Uninstall (the MSI's ServiceControl) and install again.
	f.installed, f.calls = false, nil
	code, out, errs = runCLI(t, installArgs(dir, "--create-key", "--start")...)
	if code != 0 {
		t.Fatalf("reinstall: exit %d\n%s%s", code, out, errs)
	}
	if !bytes.Equal(readFile(t, keystore.Path(dir)), key) {
		t.Fatal("the reinstall replaced the device key")
	}
	if !strings.Contains(out, id+": kept the existing device key") {
		t.Fatalf("reinstall output:\n%s", out)
	}
}

// A key that exists but cannot be opened is never replaced: the install
// stops and leaves the file as it is.
func TestInstallNeverReplacesAKeyItCannotOpen(t *testing.T) {
	f := useFakeSCM(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	if code, _, errs := runCLI(t, "keygen", "--state-dir", dir); code != 0 {
		skipWithoutKeyStore(t, errs)
		t.Fatal(errs)
	}
	broken := []byte(`{"type":"kovyr-device-key/v1","alg":"ES256"}` + "\n")
	if err := os.WriteFile(keystore.Path(dir), broken, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runCLI(t, installArgs(dir, "--create-key", "--start")...)
	if code != 1 || !strings.Contains(errs, "cannot be opened") || !strings.Contains(errs, "left as it is") {
		t.Fatalf("exit %d %q", code, errs)
	}
	if !bytes.Equal(readFile(t, keystore.Path(dir)), broken) {
		t.Fatal("the key file was changed")
	}
	if len(f.calls) != 0 {
		t.Fatalf("the service manager was called: %v", f.calls)
	}
}

// --start leaves nothing half done: a service that does not start is
// removed again, and the install fails.
func TestInstallRemovesAServiceThatDoesNotStart(t *testing.T) {
	f := useFakeSCM(t)
	f.startErr = errors.New("the service stopped while starting")
	dir := filepath.Join(t.TempDir(), "Kovyr")
	code, _, errs := runCLI(t, installArgs(dir, "--create-key", "--start")...)
	skipWithoutKeyStore(t, errs)
	if code != 1 || !strings.Contains(errs, "removed again") {
		t.Fatalf("exit %d %q", code, errs)
	}
	if !slices.Equal(f.calls, []string{"install", "start", "uninstall"}) || f.installed {
		t.Fatalf("calls %v, installed %v", f.calls, f.installed)
	}
	if !strings.Contains(string(readFile(t, filepath.Join(dir, "logs", "agent.log"))), "service install: install failed: start:") {
		t.Error("the failure is not in the agent log")
	}
}

// An installed service is left alone, settings included.
func TestInstallLeavesAnInstalledServiceAlone(t *testing.T) {
	f := useFakeSCM(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	if code, _, errs := runCLI(t, "keygen", "--state-dir", dir); code != 0 {
		skipWithoutKeyStore(t, errs)
		t.Fatal(errs)
	}
	s := config.Defaults()
	s.Server = "https://old.example"
	if err := config.Write(dir, s); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, config.Path(dir))
	f.installed = true
	code, _, errs := runCLI(t, installArgs(dir, "--create-key", "--start")...)
	if code != 1 || !strings.Contains(errs, "already installed") {
		t.Fatalf("exit %d %q", code, errs)
	}
	if !bytes.Equal(readFile(t, config.Path(dir)), before) || len(f.calls) != 0 {
		t.Fatalf("settings changed or service manager called (%v)", f.calls)
	}
}

// With --create-key, bad settings or a replaceable binary still stop the
// install before anything is written: no key, no state directory.
func TestInstallCreateKeyChecksBeforeWriting(t *testing.T) {
	useFakeSCM(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	if code, _, errs := runCLI(t, "service", "install", "--server", "http://agent.example", "--create-key", "--start", "--state-dir", dir); code != 2 || !strings.Contains(errs, "https") {
		t.Errorf("plain http: exit %d %q", code, errs)
	}
	executable = func() (string, error) { return `C:\Users\maria\Downloads\kovyr-agent.exe`, nil }
	if code, _, errs := runCLI(t, installArgs(dir, "--create-key", "--start")...); code != 1 || !strings.Contains(errs, "only administrators can write") {
		t.Errorf("binary in Downloads: exit %d %q", code, errs)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the state directory was created (%v)", err)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := runCLI(t, "version")
	if want := fmt.Sprintf("%d.%d.%d\n", agent.Version.Major, agent.Version.Minor, agent.Version.Patch); code != 0 || out != want {
		t.Fatalf("exit %d %q", code, out)
	}
}
