package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
	"github.com/kendallcoding202/kovyr-edr/internal/receiver"
	"github.com/kendallcoding202/kovyr-edr/proof/canon"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func useHealthyFake(t *testing.T) {
	old := systemProbes
	systemProbes = func() checks.Probes { return checks.HealthyFake() }
	t.Cleanup(func() { systemProbes = old })
}

// noUserFolders keeps the tripwire off this machine's real user folders.
func noUserFolders(t *testing.T) {
	old := userFolders
	userFolders = func() []string { return nil }
	t.Cleanup(func() { userFolders = old })
}

// wantTripwire is the tripwire state a heartbeat watching n folders
// reports on this OS.
func wantTripwire(t *testing.T, l *receiver.Latest, n uint8) {
	t.Helper()
	switch {
	case l == nil:
		t.Fatal("no statement")
	case runtime.GOOS == "windows" && (l.TripwireState != "ok" || l.TripwireFolders != n):
		t.Fatalf("tripwire %s watching %d, want ok watching %d", l.TripwireState, l.TripwireFolders, n)
	case runtime.GOOS != "windows" && l.TripwireState != "not_applicable":
		t.Fatalf("tripwire %s, want not_applicable", l.TripwireState)
	}
}

func TestCheckPrintsATableAndAValidStatement(t *testing.T) {
	useHealthyFake(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	code, out, errs := runCLI(t, "check", "--state-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"Microsoft Defender", "real-time on", "3 of 3 profiles on", "microsoft_defender_endpoint running", "BitLocker (OS drive)", "Statement (preview"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "check", "--json", "--state-dir", dir)
	if code != 0 {
		t.Fatal(code)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("--json output is not JSON: %v", err)
	}
	b, _ := canon.Encode(toCanon(v))
	if _, err := proof.ValidateStatement(b); err != nil {
		t.Fatalf("printed statement does not validate: %v", err)
	}
}

// toCanon converts encoding/json floats back to integers.
func toCanon(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = toCanon(e)
		}
	case []any:
		for i, e := range x {
			x[i] = toCanon(e)
		}
	case float64:
		return int64(x)
	}
	return v
}

// The whole dev flow through the CLI: keygen, enroll, run --once against
// the dev receiver.
func TestKeygenEnrollRunOnce(t *testing.T) {
	useHealthyFake(t)
	noUserFolders(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	code, out, errs := runCLI(t, "keygen", "--state-dir", dir)
	if code != 0 {
		if runtime.GOOS == "windows" && strings.Contains(errs, "administrator") {
			t.Skip("needs an elevated process on Windows")
		}
		t.Fatalf("keygen exit %d: %s", code, errs)
	}
	if code, _, _ := runCLI(t, "keygen", "--state-dir", dir); code == 0 {
		t.Fatal("second keygen overwrote the key")
	}
	if runtime.GOOS != "windows" && !strings.Contains(out, "DEV ONLY") {
		t.Errorf("dev key not flagged: %s", out)
	}
	code, out, _ = runCLI(t, "enroll", "--print-pubkey", "--state-dir", dir)
	if code != 0 {
		t.Fatal("enroll failed")
	}
	var e struct {
		receiver.Device
		KeyProtection string `json:"key_protection"`
	}
	if err := json.Unmarshal([]byte(out), &e); err != nil || e.KeyProtection != "software" {
		t.Fatalf("enroll output %q: %v", out, err)
	}
	if code, _, _ := runCLI(t, "enroll", "--state-dir", dir); code != 2 {
		t.Error("enroll without --print-pubkey must explain the stub")
	}

	r, err := receiver.New(receiver.Config{}, []receiver.Device{e.Device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()
	if code, _, errs := runCLI(t, "run", "--server", srv.URL, "--state-dir", dir, "--once"); code != 2 || !strings.Contains(errs, "https") {
		t.Fatalf("plain http without --dev-insecure: exit %d %s", code, errs)
	}
	watched := t.TempDir()
	for i := 0; i < 2; i++ {
		code, _, errs := runCLI(t, "run", "--server", srv.URL, "--dev-insecure", "--state-dir", dir, "--once", "--usage",
			"--watch", watched, "--watch", filepath.Join(watched, "inside"), "--watch", filepath.Join(watched, "missing"))
		if code != 0 {
			t.Fatalf("run --once exit %d: %s", code, errs)
		}
		if !strings.Contains(errs, "kovyr-agent usage: cpu_ms=") {
			t.Fatalf("--usage printed nothing: %s", errs)
		}
		if strings.Contains(errs, watched) {
			t.Fatalf("the log names a watched folder: %s", errs)
		}
	}
	st := r.Status().Devices[0]
	if st.LastSeq != 2 || st.TamperEvents != 0 {
		t.Fatalf("receiver status %+v", st)
	}
	wantTripwire(t, st.Latest, 1) // "inside" is covered by its parent; "missing" does not exist
}

func TestUsage(t *testing.T) {
	if code, _, _ := runCLI(t); code != 2 {
		t.Error("no args")
	}
	if code, _, _ := runCLI(t, "isolate-host"); code != 2 {
		t.Error("unknown command accepted")
	}
	if code, _, _ := runCLI(t, "run"); code != 2 {
		t.Error("run without --server")
	}
	many := []string{"run", "--server", "https://halden.example"}
	for i := 0; i < 17; i++ {
		many = append(many, "--watch", filepath.Join(t.TempDir(), "f"))
	}
	if code, _, _ := runCLI(t, many...); code != 2 {
		t.Error("17 --watch folders accepted")
	}
	if code, _, _ := runCLI(t, "run", "--server", "https://halden.example", "--watch", ""); code != 2 {
		t.Error("an empty --watch folder accepted")
	}
}
