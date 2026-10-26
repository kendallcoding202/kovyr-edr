package service

import (
	"strings"
	"testing"
	"time"
)

func TestCheckBinaryPath(t *testing.T) {
	roots := []string{`C:\Program Files`, `C:\Program Files (x86)`}
	for _, ok := range []string{
		`C:\Program Files\Kovyr\kovyr-agent.exe`,
		`c:\program files\kovyr\KOVYR-AGENT.EXE`,
		`C:/Program Files/Kovyr/kovyr-agent.exe`,
		`C:\Program Files (x86)\Kovyr\kovyr-agent.exe`,
	} {
		if err := CheckBinaryPath(ok, roots); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`C:\Users\maria\Downloads\kovyr-agent.exe`,  // a user can replace it
		`C:\Program Files Evil\kovyr-agent.exe`,     // prefix, not a path segment
		`C:\Program Files\..\Users\kovyr-agent.exe`, // climbs out
		`C:\Program Files\.\Kovyr\kovyr-agent.exe`,
		`C:\Program Files`,               // the root itself
		`kovyr-agent.exe`,                // relative
		`\\server\share\kovyr-agent.exe`, // network share
		`C:\Temp\kovyr-agent.exe`,
	} {
		if err := CheckBinaryPath(bad, roots); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := CheckBinaryPath(`C:\Program Files\Kovyr\kovyr-agent.exe`, nil); err == nil {
		t.Error("accepted with no protected roots")
	}
}

func TestServiceCommandLineAndPlan(t *testing.T) {
	if got := strings.Join(Args(`C:\ProgramData\Kovyr`), " "); got != `service run --state-dir C:\ProgramData\Kovyr` {
		t.Fatalf("args %q", got)
	}
	if len(RecoveryDelays) != 3 || RecoveryDelays[0] != time.Minute || RecoveryDelays[2] != 15*time.Minute || ResetPeriod != 24*time.Hour {
		t.Fatalf("recovery plan %v / %v", RecoveryDelays, ResetPeriod)
	}
	// Windows gives services about five seconds at shutdown.
	if StopGrace >= 5*time.Second {
		t.Fatalf("stop grace %v is not inside the shutdown limit", StopGrace)
	}
}

func TestStatusText(t *testing.T) {
	s := Status{State: "running", PID: 42, StartType: "automatic", Delayed: true, Account: "LocalSystem",
		BinaryPath: `"C:\Program Files\Kovyr\kovyr-agent.exe" service run`, Recovery: RecoveryDelays,
		ResetPeriod: ResetPeriod, RecoverOnExitCode: true}
	out := s.String()
	for _, want := range []string{"running, pid 42", "automatic (delayed)", "LocalSystem", "restart after 1m0s, 5m0s, 15m0s", "also when it exits with an error"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
}
