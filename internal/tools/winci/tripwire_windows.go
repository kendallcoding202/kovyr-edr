package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// dummyFiles is how many files the burst renames: above the default
// thresholds (100 changes, 50 extension changes in 60 s), and in the
// 100-999 bucket.
const dummyFiles = 300

// tripwireTest runs the agent's heartbeat loop (15-minute interval) with
// the tripwire on one temporary folder that holds only dummy files this
// test creates. Light editing must not trip it; renaming every file to a
// new extension must send an extra heartbeat at once, which the dev
// receiver shows as ransomware_suspected. No statement, receiver record or
// agent log line may carry a file or folder name.
func tripwireTest(agentExe, receiverExe string) error {
	work, err := os.MkdirTemp("", "kovyr-tripwire-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	state := filepath.Join(work, "state")
	if err := enroll(agentExe, state, work); err != nil {
		return err
	}
	const addr = "127.0.0.1:18789"
	rcv, err := startReceiver(receiverExe, work, addr, defaultInterval)
	if err != nil {
		return err
	}
	defer rcv.stop()
	watched := filepath.Join(work, "Client Files")
	if err := os.Mkdir(watched, 0o700); err != nil {
		return err
	}
	name := func(i int) string { return filepath.Join(watched, fmt.Sprintf("kovyr-dummy-invoice-%03d.docx", i)) }
	for i := 0; i < dummyFiles; i++ {
		if err := os.WriteFile(name(i), []byte("Kovyr tripwire CI dummy file\n"), 0o600); err != nil {
			return err
		}
	}

	logPath := filepath.Join(work, "agent-tripwire.log")
	logf, err := os.Create(logPath)
	if err != nil {
		return err
	}
	cmd := exec.Command(agentExe, "run", "--server", "http://"+addr, "--dev-insecure", "--interval", "15m",
		"--state-dir", state, "--watch", watched, "--no-user-folders")
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return err
	}
	stopped := false
	stop := func() {
		if !stopped {
			cmd.Process.Kill()
			cmd.Wait()
			logf.Close()
			stopped = true
		}
	}
	defer stop()
	fail := func(format string, a ...any) error {
		stop()
		b, _ := os.ReadFile(logPath)
		return fmt.Errorf(format+"\nagent log:\n%s", append(a, b)...)
	}

	s, err := rcv.waitSeq(1, time.Minute)
	if err != nil {
		return fail("first heartbeat: %v", err)
	}
	if l := s.Latest; l == nil || l.TripwireState != "ok" || l.TripwireFolders != 1 || l.TripwireTriggered {
		return fail("first heartbeat tripwire: %+v", l)
	}
	fmt.Println("ok: the first heartbeat reports the tripwire watching 1 folder")

	// Light editing: twenty saves and a couple of renames. No trip.
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(name(i), []byte("edited\n"), 0o600); err != nil {
			return err
		}
	}
	os.Rename(name(20), filepath.Join(watched, "kovyr-dummy-invoice-020 final.docx"))
	os.Rename(name(21), filepath.Join(watched, "kovyr-dummy-invoice-021.pdf"))
	time.Sleep(10 * time.Second)
	if s, err = rcv.status(); err != nil || s.LastSeq != 1 {
		return fail("after light editing: seq %d (err %v), want no extra heartbeat", s.LastSeq, err)
	}
	fmt.Println("ok: light editing sends nothing")

	// The burst: every remaining file renamed to a new extension.
	t0 := time.Now()
	renamed := 0
	for i := 22; i < dummyFiles; i++ {
		if err := os.Rename(name(i), name(i)+".locked"); err != nil {
			return err
		}
		renamed++
	}
	burst := time.Since(t0)
	s, err = rcv.waitSeq(2, time.Minute)
	if err != nil {
		return fail("no tripwire heartbeat: %v", err)
	}
	delay := time.Since(t0)
	l := s.Latest
	if l == nil || !l.TripwireTriggered || l.TripwireReason != "mass_extension_change" ||
		l.TripwireCounts["extension_changed"] != "100_999" || l.TripwireCounts["renamed"] != "100_999" {
		return fail("tripwire heartbeat: %+v", l)
	}
	if l.IntervalS < 60 || l.IntervalS >= 900 {
		return fail("tripwire heartbeat announces interval %d, want the time left to the scheduled one", l.IntervalS)
	}
	if !slices.Contains(s.Signals, "ransomware_suspected:mass_extension_change") {
		return fail("status signals %v, want ransomware_suspected", s.Signals)
	}
	evt := false
	for _, e := range s.Events {
		evt = evt || e.Kind == "ransomware_suspected" && e.Seq == 2
	}
	if !evt {
		return fail("no ransomware_suspected event: %+v", s.Events)
	}
	fmt.Printf("ok: %d renames in %v; the tripwire heartbeat arrived %v after the burst began\n",
		renamed, burst.Round(time.Millisecond), delay.Round(time.Millisecond))

	// It only reported: the files are all still there.
	entries, err := os.ReadDir(watched)
	if err != nil || len(entries) != dummyFiles {
		return fail("watched folder has %d entries (err %v), want %d untouched", len(entries), err, dummyFiles)
	}

	// Privacy: no name in a statement, a receiver record or the log.
	stop()
	secret := []string{"kovyr-dummy", "invoice", "Client Files", ".locked", ".docx", filepath.Base(work)}
	payloads, err := storedPayloads(filepath.Join(work, "store.jsonl"))
	if err != nil {
		return err
	}
	logText, _ := os.ReadFile(logPath)
	for _, text := range append(payloads, string(logText)) {
		for _, n := range secret {
			if strings.Contains(strings.ToLower(text), strings.ToLower(n)) {
				return fmt.Errorf("a statement or log line names %q:\n%s", n, text)
			}
		}
	}
	if !strings.Contains(string(logText), "tripwire fired") {
		return fmt.Errorf("agent log does not record the trip:\n%s", logText)
	}
	fmt.Printf("ok: %d stored statements and the agent log name no file or folder\n", len(payloads))

	summary("### Ransomware tripwire (windows-latest)\n\n")
	summary("| Step | Result |\n|---|---|\n")
	summary("| watching a temporary folder of %d dummy files | `tripwire_state` ok, 1 folder |\n", dummyFiles)
	summary("| 20 saves and 2 renames | no extra heartbeat |\n")
	summary("| %d renames to `.locked` | took %v |\n", renamed, burst.Round(time.Millisecond))
	summary("| extra heartbeat at the receiver | %v after the burst began; `mass_extension_change`, `extension_changed` 100_999, `interval_s` %d |\n",
		delay.Round(time.Millisecond), l.IntervalS)
	summary("| receiver | `ransomware_suspected:mass_extension_change` signal and event |\n")
	summary("| files touched by the agent | none |\n")
	summary("| names in statements, receiver store, agent log | none |\n\n")
	return nil
}

// storedPayloads returns the statement JSON of every accepted record in
// the receiver's store.
func storedPayloads(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var rec struct {
			Envelope string `json:"envelope"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, err
		}
		if rec.Envelope == "" {
			continue
		}
		var env struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(rec.Envelope), &env); err != nil {
			return nil, err
		}
		p, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			return nil, err
		}
		out = append(out, sc.Text(), string(p))
	}
	return out, sc.Err()
}
