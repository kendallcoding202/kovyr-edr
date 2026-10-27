package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/config"
	"github.com/kendallcoding202/kovyr-edr/internal/receiver"
)

func asAdmin(t *testing.T, admin bool) {
	old := isElevated
	isElevated = func() bool { return admin }
	t.Cleanup(func() { isElevated = old })
}

func TestServiceCommandsNeedAnElevatedPrompt(t *testing.T) {
	asAdmin(t, false)
	for _, args := range [][]string{
		{"service", "install", "--server", "https://halden.example"},
		{"service", "uninstall"}, {"service", "start"}, {"service", "stop"},
	} {
		code, _, errs := runCLI(t, args...)
		if code != 2 || !strings.Contains(errs, "Run as administrator") {
			t.Errorf("%v without admin: exit %d, %q", args, code, errs)
		}
	}
}

func TestServiceInstallChecksBeforeWriting(t *testing.T) {
	asAdmin(t, true)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	if code, _, errs := runCLI(t, "service", "install", "--state-dir", dir); code != 2 || !strings.Contains(errs, "--server") {
		t.Errorf("no server: exit %d %q", code, errs)
	}
	if code, _, errs := runCLI(t, "service", "install", "--server", "http://halden.example", "--state-dir", dir); code != 2 || !strings.Contains(errs, "https") {
		t.Errorf("plain http: exit %d %q", code, errs)
	}
	if code, _, errs := runCLI(t, "service", "install", "--server", "https://halden.example", "--interval", "5s", "--state-dir", dir); code != 2 {
		t.Errorf("5s interval: exit %d %q", code, errs)
	}
	if code, _, errs := runCLI(t, "service", "install", "--server", "https://halden.example", "--state-dir", dir); code != 1 || !strings.Contains(errs, "keygen") {
		t.Errorf("no key: exit %d %q", code, errs)
	}
	if _, err := config.Read(dir); err == nil {
		t.Error("settings were written although the install was refused")
	}
}

func TestServiceInstallRefusesAReplaceableBinary(t *testing.T) {
	asAdmin(t, true)
	useHealthyFake(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	if code, _, errs := runCLI(t, "keygen", "--state-dir", dir); code != 0 {
		if runtime.GOOS == "windows" && strings.Contains(errs, "administrator") {
			t.Skip("needs an elevated process on Windows")
		}
		t.Fatal(errs)
	}
	old := executable
	executable = func() (string, error) { return `C:\Users\maria\Downloads\kovyr-agent.exe`, nil }
	t.Cleanup(func() { executable = old })
	code, _, errs := runCLI(t, "service", "install", "--server", "https://halden.example", "--state-dir", dir)
	if code != 1 || !strings.Contains(errs, "only administrators can write") {
		t.Fatalf("binary in Downloads: exit %d %q", code, errs)
	}
	if _, err := config.Read(dir); err == nil {
		t.Error("settings were written although the install was refused")
	}
}

func TestServiceRunIsOnlyForTheServiceManager(t *testing.T) {
	if code, _, errs := runCLI(t, "service", "run"); code != 2 || !strings.Contains(errs, "started by Windows") {
		t.Fatalf("exit %d %q", code, errs)
	}
	if code, _, _ := runCLI(t, "service"); code != 2 {
		t.Fatal("no subcommand")
	}
	if code, _, _ := runCLI(t, "service", "reboot"); code != 2 {
		t.Fatal("unknown subcommand accepted")
	}
}

func TestServiceStatusOutsideWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by the service CI step")
	}
	if code, _, errs := runCLI(t, "service", "status"); code != 1 || !strings.Contains(errs, "only on Windows") {
		t.Fatalf("exit %d %q", code, errs)
	}
}

// serviceMain is the service's heartbeat loop: it reports to the
// receiver with the installed settings and returns cleanly on stop.
func TestServiceMainReportsAndStopsCleanly(t *testing.T) {
	useHealthyFake(t)
	noUserFolders(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	if code, _, errs := runCLI(t, "keygen", "--state-dir", dir); code != 0 {
		if runtime.GOOS == "windows" && strings.Contains(errs, "administrator") {
			t.Skip("needs an elevated process on Windows")
		}
		t.Fatal(errs)
	}
	_, out, _ := runCLI(t, "enroll", "--print-pubkey", "--state-dir", dir)
	var dev receiver.Device
	json.Unmarshal([]byte(out), &dev)
	r, err := receiver.New(receiver.Config{}, []receiver.Device{dev}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()
	s := config.Defaults()
	s.Server, s.DevInsecure, s.IntervalS = srv.URL, true, 60
	s.Tripwire.Folders = []string{t.TempDir(), t.TempDir()}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serviceMain(ctx, dir, s, log.New(&logs, "", 0)) }()
	deadline := time.Now().Add(20 * time.Second)
	for r.Status().Devices[0].LastSeq < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("no heartbeat; log:\n%s", logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if l := r.Status().Devices[0].Latest; l == nil || l.IntervalS != 60 {
		t.Fatalf("latest %+v", l)
	}
	wantTripwire(t, r.Status().Devices[0].Latest, 2)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serviceMain returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serviceMain did not stop")
	}
	if !strings.Contains(logs.String(), "accepts no commands") {
		t.Errorf("log %q", logs.String())
	}
}
