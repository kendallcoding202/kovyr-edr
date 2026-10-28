package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/kendallcoding202/kovyr-edr/internal/config"
	"github.com/kendallcoding202/kovyr-edr/internal/keystore"
	"github.com/kendallcoding202/kovyr-edr/internal/service"
)

// msiTest installs the MSI silently, as an administrator would, against
// the dev receiver on loopback, on a runner where Kovyr was never
// installed. upgrade is a second build of the same MSI (another product
// code, as each new test kit has), agentExe the plain agent binary.
//
//  1. an install with a bad server URL fails and rolls back completely,
//     and SERVER or DEV_INSECURE values that could change the SYSTEM
//     install step's command line are refused by a launch condition;
//  2. an install puts the binary in Program Files, makes a device key in a
//     locked-down state directory, writes the settings, and registers and
//     starts the service with the agent's own install code; the agent is
//     refused (403) until it is enrolled, then reports;
//  3. the founder's test kit (scripts/test, from the artifact) works
//     against that service: status.ps1 shows it, check-in-now.ps1 makes a
//     check-in, tripwire-test.ps1 trips the tripwire and cleans up;
//  4. the second build installs over the first: it replaces it, keeps the
//     device, and the chain continues;
//  5. an uninstall removes the service, the binary and its folder, and
//     keeps the device key and settings;
//  6. a reinstall keeps the same device identity, and its chain continues;
//     a last uninstall leaves no service and no binary;
//  7. the MSI refuses to install over a service set up by hand, and
//     leaves that service alone.
func msiTest(msi, upgrade, kit, receiverExe, agentExe string) error {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	installDir := filepath.Join(pf, "Kovyr")
	exe := filepath.Join(installDir, "kovyr-agent.exe")
	state := filepath.Join(pd, "Kovyr")
	if _, err := service.Query(); !errors.Is(err, service.ErrNotInstalled) {
		return fmt.Errorf("the Kovyr service must not be installed before this test (%v)", err)
	}
	if exists(state) || exists(installDir) {
		return fmt.Errorf("%s or %s exists: run this test on a fresh runner", state, installDir)
	}
	work, err := os.MkdirTemp("", "kovyr-msi-")
	if err != nil {
		return err
	}
	msiLog := func(name string) string { return filepath.Join(work, name+".log") }
	// Leave the runner clean if a step fails.
	defer msiexec("/x", upgrade, "/qn")
	defer msiexec("/x", msi, "/qn")

	// 1. A bad setting fails the install, and nothing is left behind.
	code, d := msiexec("/i", msi, "/qn", "/l*v", msiLog("msi-bad-install"), "SERVER=http://agent.example")
	if code != 1603 {
		return msiFail(msiLog("msi-bad-install"), "install with a plain-http server: exit %d, want 1603 (failed, rolled back)", code)
	}
	if _, err := service.Query(); !errors.Is(err, service.ErrNotInstalled) || exists(exe) || exists(state) {
		return msiFail(msiLog("msi-bad-install"), "after the failed install: service %v, binary %v, state directory %v",
			err, exists(exe), exists(state))
	}
	fmt.Printf("ok: an install with a bad server fails (%v) and leaves no service, binary or key\n", d.Round(time.Second))
	// A backslash could end the quotes around [SERVER] in that command
	// line; DEV_INSECURE may only pick one of two fixed command lines.
	for i, bad := range []struct{ prop, msg string }{
		{`SERVER=https://agent.example\`, "SERVER must be a plain https:// address"},
		{"DEV_INSECURE=2", "DEV_INSECURE must be 0 or 1"},
	} {
		name := msiLog(fmt.Sprintf("msi-bad-property-%d", i+1))
		code, _ := msiexec("/i", msi, "/qn", "/l*v", name, bad.prop)
		b, _ := os.ReadFile(name)
		if code != 1603 || !strings.Contains(decodeUTF16(b), bad.msg) {
			return msiFail(name, "install with %s: exit %d, want 1603 from the launch condition %q", bad.prop, code, bad.msg)
		}
		if _, err := service.Query(); !errors.Is(err, service.ErrNotInstalled) || exists(exe) || exists(state) {
			return msiFail(name, "after %s: service %v, binary %v, state directory %v", bad.prop, err, exists(exe), exists(state))
		}
		fmt.Printf("ok: %s is refused by a launch condition and leaves nothing\n", bad.prop)
	}

	// The receiver runs with no device enrolled yet; it re-reads its
	// devices file when an unknown device calls.
	const addr = "127.0.0.1:18790"
	rcv, err := startReceiver(receiverExe, work, addr, defaultInterval)
	if err != nil {
		return err
	}
	defer rcv.stop()
	server := "http://" + addr
	props := []string{"SERVER=" + server, "DEV_INSECURE=1"}
	install := func(what, path string) (time.Duration, error) {
		code, d := msiexec(append([]string{"/i", path, "/qn", "/l*v", msiLog("msi-" + what)}, props...)...)
		if code != 0 {
			return d, msiFail(msiLog("msi-"+what), "%s: exit %d", what, code)
		}
		if err := checkInstalled(exe, state, server); err != nil {
			return d, msiFail(msiLog("msi-"+what), "%s: %v", what, err)
		}
		fmt.Printf("ok: %s (%v)\n", what, d.Round(time.Second))
		return d, nil
	}
	uninstall := func(what, path string) (time.Duration, error) {
		code, d := msiexec("/x", path, "/qn", "/l*v", msiLog("msi-"+what))
		if code != 0 {
			return d, msiFail(msiLog("msi-"+what), "%s: exit %d", what, code)
		}
		if err := checkRemoved(exe, installDir); err != nil {
			return d, msiFail(msiLog("msi-"+what), "%s: %v", what, err)
		}
		return d, nil
	}
	// sameDevice checks that the device kept its identity across an
	// install and that its chain continues at the receiver.
	sameDevice := func(id string, after uint32, keptLines int) (devStatus, error) {
		if err := waitLog(state, id+": kept the existing device key", keptLines, 5*time.Second); err != nil {
			return devStatus{}, err
		}
		if id2, err := deviceID(exe); err != nil || id2 != id {
			return devStatus{}, fmt.Errorf("device after the install: %q (%v), want %s", id2, err, id)
		}
		s, err := rcv.waitSeq(after+1, 2*time.Minute)
		if err != nil {
			return s, err
		}
		for _, e := range s.Events {
			if e.Kind == "chain_broken" || e.Kind == "replay_old_seq" || e.Kind == "bad_signature" {
				return s, fmt.Errorf("after the install the receiver saw %s", e.Kind)
			}
		}
		if s.Refused != 0 {
			return s, fmt.Errorf("after the install the receiver refused %d statement(s)", s.Refused)
		}
		return s, nil
	}

	// 2. Install.
	installTime, err := install("install", msi)
	if err != nil {
		return err
	}
	if err := waitLog(state, "created a new device key", 1, 5*time.Second); err != nil {
		return err
	}
	// Not enrolled: the receiver refuses the challenge, and the agent
	// says so in its log (docs/testing-on-your-pc.md quotes this line).
	if err := waitLog(state, "challenge: HTTP 403", 1, 60*time.Second); err != nil {
		return err
	}
	fmt.Println("ok: before enrollment the agent logs the receiver's 403 and keeps trying")
	id, err := enrollInstalled(exe, work)
	if err != nil {
		return err
	}
	s1, err := rcv.waitSeq(1, 3*time.Minute)
	if err != nil {
		return err
	}
	if s1.DeviceID != id || s1.Refused != 0 || s1.Latest == nil || s1.Latest.IntervalS != 900 {
		return fmt.Errorf("receiver after enrollment: %+v", s1)
	}
	fmt.Printf("ok: once enrolled, %s reports (seq %d, interval 900 s)\n", id, s1.LastSeq)

	// 3. The test kit.
	kitResult, err := kitTest(kit, id, rcv)
	if err != nil {
		return err
	}

	// 4. A newer build over the installed one.
	before, err := rcv.status()
	if err != nil {
		return err
	}
	upgradeTime, err := install("upgrade", upgrade)
	if err != nil {
		return err
	}
	s2, err := sameDevice(id, before.LastSeq, 1)
	if err != nil {
		return err
	}
	if code, _ := msiexec("/x", msi, "/qn"); code != 1605 {
		return fmt.Errorf("after the upgrade the first build is still installed (uninstalling it: exit %d, want 1605)", code)
	}
	fmt.Printf("ok: the second build replaced the first, kept %s, and its chain continues (seq %d)\n", id, s2.LastSeq)

	// 5. Uninstall: service, binary and folder go; key and settings stay.
	key, err := os.ReadFile(keystore.Path(state))
	if err != nil {
		return err
	}
	uninstallTime, err := uninstall("uninstall", upgrade)
	if err != nil {
		return err
	}
	after, err := os.ReadFile(keystore.Path(state))
	if err != nil || string(after) != string(key) {
		return fmt.Errorf("the uninstall did not keep the device key (%v)", err)
	}
	if _, err := config.Read(state); err != nil {
		return fmt.Errorf("the uninstall did not keep the settings: %v", err)
	}
	fmt.Printf("ok: uninstall (%v) removed the service, the binary and %s, and kept the device key\n",
		uninstallTime.Round(time.Second), installDir)

	// 6. Reinstall: same device, the chain continues. Then uninstall.
	before, err = rcv.status()
	if err != nil {
		return err
	}
	reinstallTime, err := install("reinstall", msi)
	if err != nil {
		return err
	}
	s3, err := sameDevice(id, before.LastSeq, 2)
	if err != nil {
		return err
	}
	fmt.Printf("ok: reinstall kept device %s; its chain continues at seq %d\n", id, s3.LastSeq)
	if _, err := uninstall("uninstall-2", msi); err != nil {
		return err
	}
	fmt.Println("ok: gone after the second uninstall")

	// 7. A service set up by hand: the MSI refuses, and must not remove or
	// change it (a rollback may only undo what this installer made).
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	if err := copyFile(agentExe, exe); err != nil {
		return err
	}
	if code, out := run(exe, "service", "install", "--server", server, "--dev-insecure"); code != 0 {
		return fmt.Errorf("installing the service by hand: exit %d:\n%s", code, out)
	}
	byHand, err := service.Query()
	if err != nil {
		return err
	}
	code, _ = msiexec(append([]string{"/i", msi, "/qn", "/l*v", msiLog("msi-over-hand-install")}, props...)...)
	if code != 1603 {
		return msiFail(msiLog("msi-over-hand-install"), "MSI over a hand-installed service: exit %d, want 1603", code)
	}
	if q, err := service.Query(); err != nil || q.BinaryPath != byHand.BinaryPath || !exists(exe) {
		return msiFail(msiLog("msi-over-hand-install"), "the hand-installed service changed: %+v %v (binary there: %v)", q, err, exists(exe))
	}
	if code, out := run(exe, "service", "uninstall"); code != 0 {
		return fmt.Errorf("removing the hand-installed service: exit %d:\n%s", code, out)
	}
	if err := os.RemoveAll(installDir); err != nil {
		return err
	}
	fmt.Println("ok: the MSI refuses to install over a hand-installed service and leaves it alone")

	summary("### MSI installer (windows-latest)\n\n")
	summary("| Step | Result |\n|---|---|\n")
	summary("| install with a bad server URL | fails (1603), rolls back: no service, binary or key |\n")
	summary("| `SERVER` with a backslash, `DEV_INSECURE=2` | refused by a launch condition (1603), nothing installed |\n")
	summary("| silent install | %v: binary in Program Files, service running (LocalSystem, delayed automatic, recovery), key in a locked-down `ProgramData\\Kovyr` |\n", installTime.Round(time.Second))
	summary("| before enrollment | receiver answers 403, agent logs it and retries |\n")
	summary("| after enrollment | heartbeats arrive (seq %d) |\n", s1.LastSeq)
	summary("| test kit: `status.ps1`, `check-in-now.ps1`, `tripwire-test.ps1` | %s |\n", kitResult)
	summary("| a second build over the first | %v: replaces it, same device ID, chain continues (seq %d) |\n", upgradeTime.Round(time.Second), s2.LastSeq)
	summary("| uninstall | %v: service, binary and folder removed; device key and settings kept |\n", uninstallTime.Round(time.Second))
	summary("| reinstall, uninstall | %v: same device ID, chain continues (seq %d), nothing refused; then removed |\n", reinstallTime.Round(time.Second), s3.LastSeq)
	summary("| MSI over a hand-installed service | refused (1603); that service left as it was |\n\n")
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// msiexec runs Windows Installer and returns its exit code. It waits out
// another install in progress (1618).
func msiexec(args ...string) (int, time.Duration) {
	t0 := time.Now()
	for i := 0; ; i++ {
		err := exec.Command("msiexec", args...).Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			return -1, time.Since(t0)
		}
		if code != 1618 || i == 10 {
			return code, time.Since(t0)
		}
		time.Sleep(3 * time.Second)
	}
}

// msiFail returns an error with the end of a verbose MSI log, where
// Windows Installer says which action failed.
func msiFail(logPath, format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	b, err := os.ReadFile(logPath)
	if err != nil {
		return fmt.Errorf("%s (no MSI log: %v)", msg, err)
	}
	// Verbose MSI logs are UTF-16LE.
	text := decodeUTF16(b)
	lines := strings.Split(text, "\n")
	var keep []string
	for _, l := range lines {
		if strings.Contains(l, "Kovyr") || strings.Contains(l, "Return value 3") || strings.Contains(l, "Error ") ||
			strings.Contains(l, "error code") || strings.Contains(l, "CustomAction") {
			keep = append(keep, strings.TrimRight(l, "\r"))
		}
	}
	if len(keep) > 80 {
		keep = keep[len(keep)-80:]
	}
	return fmt.Errorf("%s\nfrom %s:\n%s", msg, filepath.Base(logPath), strings.Join(keep, "\n"))
}

func decodeUTF16(b []byte) string {
	if len(b) < 2 || b[0] != 0xff || b[1] != 0xfe {
		return string(b)
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 2; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return windows.UTF16ToString(u)
}

// checkInstalled checks what the MSI and the agent's install code set up.
func checkInstalled(exe, state, server string) error {
	if !exists(exe) {
		return fmt.Errorf("%s is missing", exe)
	}
	q, err := service.Query()
	if err != nil {
		return fmt.Errorf("service: %v", err)
	}
	// Quoted the way the service manager package quotes it.
	wantBin := windows.EscapeArg(exe) + " service run --state-dir " + windows.EscapeArg(state)
	if q.State != "running" || !strings.EqualFold(q.BinaryPath, wantBin) || q.StartType != "automatic" || !q.Delayed ||
		q.Account != "LocalSystem" || len(q.Recovery) != 3 || !q.RecoverOnExitCode {
		return fmt.Errorf("service after install:\n%swant running, binary %s", q, wantBin)
	}
	s, err := config.Read(state)
	if err != nil {
		return fmt.Errorf("settings: %v", err)
	}
	if s.Server != server || !s.DevInsecure || s.IntervalS != 900 || !s.Tripwire.Enabled || !s.Tripwire.UserFolders {
		return fmt.Errorf("settings after install: %+v", s)
	}
	if !keystore.Exists(state) {
		return errors.New("no device key after install")
	}
	sddl, err := dirSDDL(state)
	if err != nil {
		return err
	}
	// Protected (no inheritance from ProgramData, which every user can
	// read) and open only to SYSTEM and Administrators.
	if !strings.Contains(sddl, "D:P") {
		return fmt.Errorf("state directory ACL is not protected: %s", sddl)
	}
	for _, ace := range regexp.MustCompile(`\(([^)]*)\)`).FindAllStringSubmatch(sddl, -1) {
		f := strings.Split(ace[1], ";")
		if who := f[len(f)-1]; who != "SY" && who != "BA" {
			return fmt.Errorf("state directory ACL grants %s access: %s", who, sddl)
		}
	}
	fmt.Printf("ok: installed: %s running as %s from %s; state directory ACL %s\n", service.Name, q.Account, exe, sddl)
	return nil
}

func dirSDDL(dir string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", fmt.Errorf("read the ACL of %s: %w", dir, err)
	}
	return sd.String(), nil
}

func checkRemoved(exe, installDir string) error {
	if _, err := service.Query(); !errors.Is(err, service.ErrNotInstalled) {
		return fmt.Errorf("the service is still there after uninstall (%v)", err)
	}
	if exists(exe) || exists(installDir) {
		return fmt.Errorf("%s is still there after uninstall", installDir)
	}
	return nil
}

// waitLog waits until the agent's log holds want at least n times.
func waitLog(state, want string, n int, timeout time.Duration) error {
	path := filepath.Join(state, "logs", "agent.log")
	deadline := time.Now().Add(timeout)
	for {
		b, _ := os.ReadFile(path)
		if strings.Count(string(b), want) >= n {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the agent log has %q fewer than %d times after %v:\n%s", want, n, timeout, b)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// deviceID asks the installed agent for its device ID.
func deviceID(exe string) (string, error) {
	out, err := exec.Command(exe, "enroll", "--print-pubkey").Output()
	if err != nil {
		return "", fmt.Errorf("enroll --print-pubkey: %v", err)
	}
	var d struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		return "", err
	}
	return d.DeviceID, nil
}

// enrollInstalled adds the installed agent's key to the dev receiver's
// devices file, as the founder pastes it into the admin page.
func enrollInstalled(exe, work string) (string, error) {
	out, err := exec.Command(exe, "enroll", "--print-pubkey").Output()
	if err != nil {
		return "", fmt.Errorf("enroll --print-pubkey: %v", err)
	}
	var d struct {
		DeviceID  string `json:"device_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{"devices": []any{map[string]string{
		"device_id": d.DeviceID, "public_key": d.PublicKey, "label": "CI runner (MSI)"}}})
	return d.DeviceID, os.WriteFile(filepath.Join(work, "devices.json"), b, 0o600)
}

// kitTest runs the founder's scripts (docs/testing-on-your-pc.md) the way
// he will, in Windows PowerShell, against the installed service.
func kitTest(kit, id string, rcv *receiver) (string, error) {
	ps := func(script string, args ...string) (int, string) {
		return run("powershell.exe", append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-File", filepath.Join(kit, script)}, args...)...)
	}
	// status.ps1 is read-only: it shows the service and the enrollment.
	code, out := ps("status.ps1")
	if code != 0 || !strings.Contains(out, ": running") || !strings.Contains(out, `"device_id": "`+id+`"`) {
		return "", fmt.Errorf("status.ps1: exit %d:\n%s", code, out)
	}
	fmt.Println("ok: status.ps1 shows the running service and the enrollment text")

	// check-in-now.ps1 restarts the service, which checks in at once.
	before, err := rcv.status()
	if err != nil {
		return "", err
	}
	if code, out := ps("check-in-now.ps1"); code != 0 {
		return "", fmt.Errorf("check-in-now.ps1: exit %d:\n%s", code, out)
	}
	s, err := rcv.waitSeq(before.LastSeq+1, time.Minute)
	if err != nil {
		return "", fmt.Errorf("no check-in after check-in-now.ps1: %v", err)
	}
	if s.Latest == nil || s.Latest.TripwireState != "ok" || s.Latest.TripwireFolders < 1 {
		return "", fmt.Errorf("after the restart the tripwire is not watching the user folders: %+v", s.Latest)
	}
	fmt.Printf("ok: check-in-now.ps1 made a check-in (seq %d); the tripwire watches %d folder(s)\n", s.LastSeq, s.Latest.TripwireFolders)

	// tripwire-test.ps1 trips the tripwire in this user's Documents and
	// leaves the folder as it found it.
	docs := filepath.Join(os.Getenv("USERPROFILE"), "Documents")
	beforeEntries, err := os.ReadDir(docs)
	if err != nil {
		return "", fmt.Errorf("the runner user's Documents: %v", err)
	}
	t0 := time.Now()
	code, out = ps("tripwire-test.ps1", "-WaitSeconds", "5")
	if code != 0 {
		return "", fmt.Errorf("tripwire-test.ps1: exit %d:\n%s", code, out)
	}
	fmt.Print(out)
	tripped, err := rcv.waitSeq(s.LastSeq+1, time.Minute)
	if err != nil {
		return "", fmt.Errorf("no tripwire heartbeat after tripwire-test.ps1: %v", err)
	}
	l := tripped.Latest
	if l == nil || !l.TripwireTriggered || l.TripwireReason != "mass_extension_change" ||
		!slices.Contains(tripped.Signals, "ransomware_suspected:mass_extension_change") {
		return "", fmt.Errorf("after tripwire-test.ps1: latest %+v, signals %v", l, tripped.Signals)
	}
	delay := time.Since(t0)
	afterEntries, err := os.ReadDir(docs)
	if err != nil || len(afterEntries) != len(beforeEntries) {
		return "", fmt.Errorf("tripwire-test.ps1 left Documents with %d entries, had %d (err %v)", len(afterEntries), len(beforeEntries), err)
	}
	fmt.Printf("ok: tripwire-test.ps1 tripped the installed agent (seq %d, extension_changed %s) and cleaned up after itself\n",
		tripped.LastSeq, l.TripwireCounts["extension_changed"])
	return fmt.Sprintf("all pass; the trip reached the receiver within %v of starting the script", delay.Round(time.Second)), nil
}
