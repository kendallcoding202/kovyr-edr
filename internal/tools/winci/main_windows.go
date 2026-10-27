// Command winci runs the Windows-only CI checks against the real
// binaries on a windows-latest runner (elevated):
//
//	winci budget   --agent dist\kovyr-agent.exe --receiver dist\kovyr-receiver-dev.exe
//	winci service  --agent dist\kovyr-agent.exe --receiver dist\kovyr-receiver-dev.exe
//	winci tripwire --agent dist\kovyr-agent.exe --receiver dist\kovyr-receiver-dev.exe
//	winci msi      --msi kit\kovyr-protection-alarm-x64.msi --upgrade-msi rebuild\kovyr-protection-alarm-x64.msi
//	               --kit kit --agent dist\kovyr-agent.exe --receiver dist\kovyr-receiver-dev.exe
//
// budget measures CPU and memory of a `run --once` loop and of the
// running heartbeat loop, and fails over budget (CLAUDE.md section 2:
// under 1% CPU on average, under 50 MB RAM). service installs, starts,
// queries, stops, crash-restarts and uninstalls the real Windows service
// against the dev receiver on loopback. tripwire runs the agent with the
// ransomware tripwire on a temporary folder of dummy files it creates,
// renames them all, and checks that the trip reaches the receiver at once
// (tripwire_windows.go). msi installs, checks, uninstalls and reinstalls
// the MSI silently on a fresh runner (msi_windows.go).
//
// This is a test tool. It starts processes (os/exec), which the agent
// itself never does; it is not part of the agent binary.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/kendallcoding202/kovyr-edr/internal/service"
	"github.com/kendallcoding202/kovyr-edr/internal/usage"
)

// Budget (CLAUDE.md section 2).
const (
	maxWorkingSet = 50 << 20
	// "Well under 1%": the agent's own average CPU at the default
	// 15-minute interval must stay under half a percent...
	maxAvgCPUPercentDefault = 0.5
	// ...and even at a 1-minute interval (15 times more often) under 1%.
	maxCPUPercentFastLoop = 1.0
	defaultInterval       = 15 * time.Minute
)

// queryAccess is what usage.Of needs on another process.
const queryAccess = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_VM_READ

// enableDebugPrivilege lets this elevated test tool open the SYSTEM
// service's process (and the WMI provider hosts) to read their counters.
func enableDebugPrivilege() {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return
	}
	defer tok.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid); err != nil {
		return
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

func main() {
	enableDebugPrivilege()
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: winci budget|service|tripwire --agent EXE --receiver EXE, or winci msi --msi MSI --upgrade-msi MSI --kit DIR --agent EXE --receiver EXE")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	agentExe := fs.String("agent", `dist\kovyr-agent.exe`, "kovyr-agent.exe to test")
	receiverExe := fs.String("receiver", `dist\kovyr-receiver-dev.exe`, "kovyr-receiver-dev.exe")
	msiPath := fs.String("msi", `kit\kovyr-protection-alarm-x64.msi`, "msi: the installer to test")
	kitDir := fs.String("kit", `kit`, "msi: the folder with the test kit's PowerShell scripts")
	upgradeMSI := fs.String("upgrade-msi", `rebuild\kovyr-protection-alarm-x64.msi`, "msi: a second build of the installer, to install over the first")
	runs := fs.Int("runs", 20, "budget: how many run --once heartbeats")
	loop := fs.Duration("loop", 3*time.Minute, "budget: how long to measure the running loop at a 1-minute interval")
	fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "budget":
		err = budget(abs(*agentExe), abs(*receiverExe), *runs, *loop)
	case "service":
		err = serviceTest(abs(*agentExe), abs(*receiverExe))
	case "tripwire":
		err = tripwireTest(abs(*agentExe), abs(*receiverExe))
	case "msi":
		err = msiTest(abs(*msiPath), abs(*upgradeMSI), abs(*kitDir), abs(*receiverExe), abs(*agentExe))
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("PASS")
}

func abs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// summary appends to the GitHub step summary when there is one.
func summary(format string, a ...any) {
	fmt.Printf(format, a...)
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
			fmt.Fprintf(f, format, a...)
			f.Close()
		}
	}
}

// run runs a command and returns its exit code and combined output.
func run(exe string, args ...string) (int, string) {
	out, err := exec.Command(exe, args...).CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		return -1, err.Error()
	}
	return code, string(out)
}

func must(code int, out string, want int, what string) error {
	if code != want {
		return fmt.Errorf("%s: exit %d, want %d:\n%s", what, code, want, out)
	}
	fmt.Printf("ok: %s\n", what)
	return nil
}

// receiver is the dev receiver running on loopback.
type receiver struct {
	cmd  *exec.Cmd
	addr string
}

type devStatus struct {
	DeviceID       string   `json:"device_id"`
	LastSeq        uint32   `json:"last_seq"`
	Accepted       int      `json:"accepted"`
	Refused        int      `json:"refused"`
	LostStatements int      `json:"lost_statements"`
	Signals        []string `json:"tamper_signals_active"`
	Events         []struct {
		Kind   string `json:"kind"`
		Detail string `json:"detail"`
		Seq    uint32 `json:"seq"`
	} `json:"events"`
	Latest *struct {
		IntervalS          int               `json:"interval_s"`
		HeavyChecksSkipped bool              `json:"heavy_checks_skipped"`
		TripwireState      string            `json:"tripwire_state"`
		TripwireTriggered  bool              `json:"tripwire_triggered"`
		TripwireReason     string            `json:"tripwire_reason"`
		TripwireFolders    int               `json:"tripwire_folders_watched"`
		TripwireCounts     map[string]string `json:"tripwire_counts"`
	} `json:"latest"`
}

func startReceiver(exe, work, addr string, interval time.Duration) (*receiver, error) {
	cmd := exec.Command(exe, "--addr", addr, "--devices", filepath.Join(work, "devices.json"),
		"--store", filepath.Join(work, "store.jsonl"), "--interval", interval.String())
	logf, err := os.Create(filepath.Join(work, "receiver.log"))
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	r := &receiver{cmd: cmd, addr: addr}
	for i := 0; i < 50; i++ {
		if _, err := r.status(); err == nil {
			return r, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	r.stop()
	return nil, errors.New("the dev receiver did not come up")
}

func (r *receiver) stop() { r.cmd.Process.Kill(); r.cmd.Wait() }

func (r *receiver) status() (devStatus, error) {
	resp, err := http.Get("http://" + r.addr + "/v0/status")
	if err != nil {
		return devStatus{}, err
	}
	defer resp.Body.Close()
	var s struct {
		Devices []devStatus `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return devStatus{}, err
	}
	if len(s.Devices) != 1 {
		return devStatus{}, fmt.Errorf("%d devices enrolled", len(s.Devices))
	}
	return s.Devices[0], nil
}

func (r *receiver) waitSeq(seq uint32, timeout time.Duration) (devStatus, error) {
	deadline := time.Now().Add(timeout)
	for {
		s, err := r.status()
		if err == nil && s.LastSeq >= seq {
			return s, nil
		}
		if time.Now().After(deadline) {
			return s, fmt.Errorf("receiver has seq %d after %v, want %d (err %v)", s.LastSeq, timeout, seq, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// enroll makes the device key in state and writes the receiver's devices
// file.
func enroll(agentExe, state, work string) error {
	if code, out := run(agentExe, "keygen", "--state-dir", state); code != 0 {
		return fmt.Errorf("keygen: exit %d:\n%s", code, out)
	}
	cmd := exec.Command(agentExe, "enroll", "--print-pubkey", "--state-dir", state)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("enroll: %v", err)
	}
	var d struct {
		DeviceID  string `json:"device_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]any{"devices": []any{map[string]string{
		"device_id": d.DeviceID, "public_key": d.PublicKey, "label": "CI runner"}}})
	return os.WriteFile(filepath.Join(work, "devices.json"), b, 0o600)
}

var usageLine = regexp.MustCompile(`usage: cpu_ms=(\d+) peak_working_set_kb=(\d+) peak_private_kb=(\d+)`)

// processCPU sums the CPU time of every running process with this image
// name (the WMI provider host does the agent's WMI work).
func processCPU(image string) time.Duration {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var total time.Duration
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if !strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), image) {
			continue
		}
		h, err := windows.OpenProcess(queryAccess, false, e.ProcessID)
		if err != nil {
			continue
		}
		if u, err := usage.Of(h); err == nil {
			total += u.CPU
		}
		windows.CloseHandle(h)
	}
	return total
}

func budget(agentExe, receiverExe string, runs int, loop time.Duration) error {
	work, err := os.MkdirTemp("", "kovyr-budget-")
	if err != nil {
		return err
	}
	state := filepath.Join(work, "state")
	if err := enroll(agentExe, state, work); err != nil {
		return err
	}
	const addr = "127.0.0.1:18787"
	rcv, err := startReceiver(receiverExe, work, addr, defaultInterval)
	if err != nil {
		return err
	}
	defer rcv.stop()

	// 1. A run --once loop: one full heartbeat per process.
	wmi0 := processCPU("WmiPrvSE.exe")
	var cpuTotal, cpuMax time.Duration
	var wsMax, privMax uint64
	var wallTotal time.Duration
	for i := 1; i <= runs; i++ {
		t0 := time.Now()
		code, out := run(agentExe, "run", "--once", "--server", "http://"+addr, "--dev-insecure", "--state-dir", state, "--usage")
		wall := time.Since(t0)
		if code != 0 {
			return fmt.Errorf("run --once %d: exit %d:\n%s", i, code, out)
		}
		m := usageLine.FindStringSubmatch(out)
		if m == nil {
			return fmt.Errorf("run --once %d printed no usage:\n%s", i, out)
		}
		cpuMS, _ := strconv.ParseInt(m[1], 10, 64)
		wsKB, _ := strconv.ParseUint(m[2], 10, 64)
		privKB, _ := strconv.ParseUint(m[3], 10, 64)
		cpu := time.Duration(cpuMS) * time.Millisecond
		cpuTotal += cpu
		wallTotal += wall
		cpuMax, wsMax, privMax = max(cpuMax, cpu), max(wsMax, wsKB<<10), max(privMax, privKB<<10)
		fmt.Printf("run --once %2d: cpu %4d ms, peak working set %5.1f MB, peak private %5.1f MB, wall %v\n",
			i, cpuMS, mb(wsKB<<10), mb(privKB<<10), wall.Round(time.Millisecond))
	}
	wmiCPU := processCPU("WmiPrvSE.exe") - wmi0
	st, err := rcv.status()
	if err != nil {
		return err
	}
	if st.LastSeq != uint32(runs) || st.Refused != 0 {
		return fmt.Errorf("receiver: last seq %d refused %d after %d heartbeats", st.LastSeq, st.Refused, runs)
	}
	meanCPU := cpuTotal / time.Duration(runs)
	avgDefault := 100 * float64(meanCPU) / float64(defaultInterval)
	wmiPerBeat := time.Duration(0)
	if wmiCPU > 0 {
		wmiPerBeat = wmiCPU / time.Duration(runs)
	}

	// 2. The running loop at a 1-minute interval, measured from outside.
	cmd := exec.Command(agentExe, "run", "--server", "http://"+addr, "--dev-insecure", "--interval", "1m", "--state-dir", state)
	logf, _ := os.Create(filepath.Join(work, "agent-loop.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return err
	}
	h, err := windows.OpenProcess(queryAccess, false, uint32(cmd.Process.Pid))
	if err != nil {
		cmd.Process.Kill()
		return err
	}
	defer windows.CloseHandle(h)
	start := time.Now()
	time.Sleep(loop)
	u, err := usage.Of(h)
	elapsed := time.Since(start)
	cmd.Process.Kill()
	cmd.Wait()
	if err != nil {
		return err
	}
	loopPct := 100 * float64(u.CPU) / float64(elapsed)
	st2, _ := rcv.status()
	beats := int(st2.LastSeq) - runs

	summary("### Resource budget (windows-latest)\n\n")
	summary("| Measurement | Result | Budget |\n|---|---|---|\n")
	summary("| `run --once` x %d: agent CPU per heartbeat | mean %d ms, max %d ms | |\n", runs, meanCPU.Milliseconds(), cpuMax.Milliseconds())
	summary("| Average agent CPU at the default 15-minute interval | %.4f%% | < %.1f%% |\n", avgDefault, maxAvgCPUPercentDefault)
	summary("| WMI provider host CPU during those heartbeats (shared, not the agent's own) | %d ms total, about %d ms per heartbeat | report only |\n", wmiCPU.Milliseconds(), wmiPerBeat.Milliseconds())
	summary("| `run --once`: peak working set / peak private bytes | %.1f MB / %.1f MB | < 50 MB |\n", mb(wsMax), mb(privMax))
	summary("| `run --once`: mean wall time | %v | |\n", (wallTotal / time.Duration(runs)).Round(time.Millisecond))
	summary("| Running loop at a 1-minute interval for %v (%d heartbeats): agent CPU | %d ms = %.3f%% | < %.1f%% |\n",
		elapsed.Round(time.Second), beats, u.CPU.Milliseconds(), loopPct, maxCPUPercentFastLoop)
	summary("| Running loop: peak working set / now / peak private | %.1f MB / %.1f MB / %.1f MB | < 50 MB |\n\n",
		mb(u.PeakWorkingSet), mb(u.CurrentWorkSet), mb(u.PeakPrivate))

	var fails []string
	if wsMax >= maxWorkingSet || u.PeakWorkingSet >= maxWorkingSet {
		fails = append(fails, fmt.Sprintf("peak working set %.1f MB / %.1f MB is over 50 MB", mb(wsMax), mb(u.PeakWorkingSet)))
	}
	if avgDefault >= maxAvgCPUPercentDefault {
		fails = append(fails, fmt.Sprintf("average CPU %.3f%% at the default interval is over %.1f%%", avgDefault, maxAvgCPUPercentDefault))
	}
	if loopPct >= maxCPUPercentFastLoop {
		fails = append(fails, fmt.Sprintf("running loop CPU %.3f%% at a 1-minute interval is over %.1f%%", loopPct, maxCPUPercentFastLoop))
	}
	if beats < int(loop/time.Minute) {
		fails = append(fails, fmt.Sprintf("the running loop made only %d heartbeats in %v", beats, elapsed.Round(time.Second)))
	}
	if len(fails) > 0 {
		return errors.New("over budget: " + strings.Join(fails, "; "))
	}
	return nil
}

func mb(b uint64) float64 { return float64(b) / (1 << 20) }

func serviceTest(agentSrc, receiverExe string) error {
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
	work, err := os.MkdirTemp("", "kovyr-service-")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	if err := copyFile(agentSrc, exe); err != nil {
		return err
	}
	defer os.RemoveAll(installDir)
	if err := enroll(agentSrc, state, work); err != nil {
		return err
	}
	const addr = "127.0.0.1:8787"
	rcv, err := startReceiver(receiverExe, work, addr, time.Minute)
	if err != nil {
		return err
	}
	defer rcv.stop()
	defer run(exe, "service", "uninstall") // leave the runner clean if a step fails

	server := "http://" + addr
	if code, out := run(exe, "service", "status"); code != 3 {
		return fmt.Errorf("status before install: exit %d, want 3 (not installed):\n%s", code, out)
	}
	fmt.Println("ok: not installed before install")
	if code, out := run(agentSrc, "service", "install", "--server", server, "--dev-insecure", "--interval", "1m", "--state-dir", state); code != 1 ||
		!strings.Contains(out, "only administrators can write") {
		return fmt.Errorf("install from outside Program Files: exit %d:\n%s", code, out)
	}
	fmt.Println("ok: install refused for a binary outside Program Files")

	timed := func(what string, args ...string) (time.Duration, error) {
		t0 := time.Now()
		code, out := run(exe, args...)
		d := time.Since(t0)
		return d, must(code, out, 0, fmt.Sprintf("%s (%v)", what, d.Round(time.Millisecond)))
	}
	if _, err := timed("service install", "service", "install", "--server", server, "--dev-insecure", "--interval", "1m", "--state-dir", state); err != nil {
		return err
	}
	code, out := run(exe, "service", "status")
	if code != 0 {
		return fmt.Errorf("status after install: exit %d:\n%s", code, out)
	}
	for _, want := range []string{": stopped", "automatic (delayed)", "LocalSystem", "restart after 1m0s, 5m0s, 15m0s; reset after 24h0m0s", "also when it exits with an error", `service run --state-dir`} {
		if !strings.Contains(out, want) {
			return fmt.Errorf("status after install lacks %q:\n%s", want, out)
		}
	}
	fmt.Print(out)
	startTime, err := timed("service start", "service", "start")
	if err != nil {
		return err
	}
	q, err := service.Query()
	if err != nil || q.State != "running" || q.PID == 0 {
		return fmt.Errorf("query after start: %+v %v", q, err)
	}
	h, err := windows.OpenProcess(queryAccess, false, q.PID)
	if err != nil {
		return fmt.Errorf("open the service process: %w", err)
	}
	s1, err := rcv.waitSeq(1, 60*time.Second)
	if err != nil {
		return err
	}
	u1, _ := usage.Of(h)
	t1 := time.Now()
	s3, err := rcv.waitSeq(s1.LastSeq+2, 200*time.Second)
	if err != nil {
		windows.CloseHandle(h)
		return err
	}
	u3, _ := usage.Of(h)
	window := time.Since(t1)
	windows.CloseHandle(h)
	if s3.Refused != 0 || s3.Latest == nil || s3.Latest.IntervalS != 60 {
		return fmt.Errorf("receiver after three service heartbeats: %+v", s3)
	}
	svcPct := 100 * float64(u3.CPU-u1.CPU) / float64(window)
	fmt.Printf("ok: the service reports (seq %d); CPU %.3f%% over %v, peak working set %.1f MB\n",
		s3.LastSeq, svcPct, window.Round(time.Second), mb(u3.PeakWorkingSet))

	stopTime, err := timed("service stop", "service", "stop")
	if err != nil {
		return err
	}
	if stopTime > 10*time.Second {
		return fmt.Errorf("stop took %v", stopTime)
	}
	if q, _ := service.Query(); q.State != "stopped" {
		return fmt.Errorf("state after stop: %s", q.State)
	}
	logText, err := os.ReadFile(filepath.Join(state, "logs", "agent.log"))
	if err != nil {
		return fmt.Errorf("service log: %w", err)
	}
	for _, want := range []string{"service running", "accepts no commands", "service stopped (stop)"} {
		if !strings.Contains(string(logText), want) {
			return fmt.Errorf("service log lacks %q:\n%s", want, logText)
		}
	}
	fmt.Println("ok: the service log records start and a clean stop")

	// Crash recovery: kill the process; Windows restarts it after the
	// first recovery delay (1 minute).
	if _, err := timed("service start (again)", "service", "start"); err != nil {
		return err
	}
	q, _ = service.Query()
	before, _ := rcv.status()
	recovered := "not tested"
	if hk, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, q.PID); err != nil {
		fmt.Printf("note: cannot open the service process to kill it (%v); recovery not tested\n", err)
	} else {
		windows.TerminateProcess(hk, 99)
		windows.CloseHandle(hk)
		killed := time.Now()
		deadline := killed.Add(150 * time.Second)
		for {
			q2, err := service.Query()
			if err == nil && q2.State == "running" && q2.PID != 0 && q2.PID != q.PID {
				recovered = fmt.Sprintf("restarted %v after a kill", time.Since(killed).Round(time.Second))
				fmt.Println("ok: recovery", recovered)
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("the service was not restarted within 150 s after a kill (state %s)", q2.State)
			}
			time.Sleep(time.Second)
		}
		after, err := rcv.waitSeq(before.LastSeq+1, 90*time.Second)
		if err != nil {
			return err
		}
		for _, e := range after.Events {
			if e.Kind == "chain_broken" || e.Kind == "replay_old_seq" {
				return fmt.Errorf("after the restart the receiver saw %s", e.Kind)
			}
		}
		fmt.Printf("ok: after the restart the chain continues (seq %d)\n", after.LastSeq)
	}
	uninstallTime, err := timed("service uninstall (while running)", "service", "uninstall")
	if err != nil {
		return err
	}
	if code, out := run(exe, "service", "status"); code != 3 {
		return fmt.Errorf("status after uninstall: exit %d:\n%s", code, out)
	}
	fmt.Println("ok: gone after uninstall")

	summary("### Windows service (windows-latest)\n\n")
	summary("| Step | Result |\n|---|---|\n")
	summary("| install, status (LocalSystem, automatic delayed, recovery 1m/5m/15m) | ok |\n")
	summary("| start | %v |\n", startTime.Round(time.Millisecond))
	summary("| heartbeats from the service | seq %d, interval_s %d, none refused |\n", s3.LastSeq, s3.Latest.IntervalS)
	summary("| service CPU at a 1-minute interval | %.3f%% over %v |\n", svcPct, window.Round(time.Second))
	summary("| service peak working set / peak private | %.1f MB / %.1f MB |\n", mb(u3.PeakWorkingSet), mb(u3.PeakPrivate))
	summary("| stop | %v |\n", stopTime.Round(time.Millisecond))
	summary("| crash recovery | %s |\n", recovered)
	summary("| uninstall while running | %v |\n\n", uninstallTime.Round(time.Millisecond))
	if svcPct >= maxCPUPercentFastLoop || u3.PeakWorkingSet >= maxWorkingSet {
		return fmt.Errorf("service over budget: CPU %.3f%%, peak working set %.1f MB", svcPct, mb(u3.PeakWorkingSet))
	}
	return nil
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, bufio.NewReader(in)); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
