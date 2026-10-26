package checks

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

func outcomes(reps []CheckReport) map[string]Outcome {
	m := map[string]Outcome{}
	for _, r := range reps {
		m[r.Name] = r.Outcome
	}
	return m
}

func TestRunnerHealthy(t *testing.T) {
	r := NewRunner(HealthyFake())
	got, reps := r.Run()
	if len(reps) != len(CheckNames()) {
		t.Fatalf("got %d reports, want %d", len(reps), len(CheckNames()))
	}
	for name, oc := range outcomes(reps) {
		if oc != OutcomeOK {
			t.Errorf("%s: %s", name, oc)
		}
	}
	if got.Defender.RealTime != proof.ToggleOn || got.FirewallProfilesOn != 3 || got.BitLocker != proof.VolumeOn ||
		got.MemoryIntegrity != proof.ToggleOn || got.DriverBlocklist != proof.BlocklistDefault ||
		len(got.EDR.Agents) != 1 || got.SecurityCenter.Enabled != 1 {
		t.Errorf("unexpected readings %+v", got)
	}
}

// A probe that hangs (WMI can) must not hold up the heartbeat, and must not
// be started again while it is still stuck.
func TestRunnerTimeoutAndNoPileUp(t *testing.T) {
	release := make(chan struct{})
	f := HealthyFake()
	var calls atomic.Int32
	f.Hook = func(probe string) {
		if probe == "defender" {
			calls.Add(1)
			<-release
		}
	}
	r := NewRunner(f)
	r.Timeout = 50 * time.Millisecond
	start := time.Now()
	got, reps := r.Run()
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Run blocked for %v", took)
	}
	if outcomes(reps)["defender"] != OutcomeTimeout {
		t.Errorf("defender outcome %s, want timeout", outcomes(reps)["defender"])
	}
	if got.Defender != proof.UnknownDefender(proof.AvailUnknown) {
		t.Errorf("timed-out check must be unknown, got %+v", got.Defender)
	}
	if got.FirewallProfilesOn != 3 {
		t.Error("other checks must still report")
	}
	// Second run while the first defender probe is still stuck.
	_, reps = r.Run()
	if outcomes(reps)["defender"] != OutcomeBusy {
		t.Errorf("second run: defender outcome %s, want busy", outcomes(reps)["defender"])
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("stuck probe was started %d times", n)
	}
	close(release)
	time.Sleep(20 * time.Millisecond) // let the stuck goroutine finish
	f.Hook = nil
	r.Probes = f
	_, reps = r.Run()
	if outcomes(reps)["defender"] != OutcomeOK {
		t.Errorf("after release: defender outcome %s", outcomes(reps)["defender"])
	}
}

func TestRunnerRecoversPanics(t *testing.T) {
	f := HealthyFake()
	f.Hook = func(probe string) {
		if probe == "memory_integrity" || probe == "bitlocker" {
			panic("library bug")
		}
	}
	got, reps := NewRunner(f).Run()
	oc := outcomes(reps)
	if oc["memory_integrity"] != OutcomePanic || oc["bitlocker"] != OutcomePanic {
		t.Errorf("outcomes %v", oc)
	}
	if got.MemoryIntegrity != proof.ToggleUnknown || got.BitLocker != proof.VolumeUnknown {
		t.Errorf("panicked checks must be unknown: %+v", got)
	}
	if got.Defender.State != proof.AvailOK {
		t.Error("other checks must still report")
	}
}

func TestRunnerErrorsAreUnknownNotFatal(t *testing.T) {
	f := Fake{
		AVErr: ErrNotApplicable, DefenderErr: ErrAccessDenied, ServicesErr: errBoom,
		BitLockerErr: ErrAccessDenied, FirewallErr: errBoom, BlocklistErr: ErrAccessDenied,
		DeviceGuardErr: ErrNotApplicable,
	}
	got, reps := NewRunner(f).Run()
	want := proof.UnknownReadings()
	want.SecurityCenter = proof.UnknownSecurityCenter(proof.AvailNotApplicable)
	if got.SecurityCenter != want.SecurityCenter || got.Defender != want.Defender || got.EDR.State != proof.AvailUnknown ||
		got.BitLocker != proof.VolumeUnknown || got.FirewallProfilesOn != proof.UnknownCount ||
		got.DriverBlocklist != proof.BlocklistUnknown || got.MemoryIntegrity != proof.ToggleUnknown {
		t.Errorf("got %+v", got)
	}
	oc := outcomes(reps)
	if oc["security_center"] != OutcomeNotApplicable || oc["defender"] != OutcomeAccessDenied || oc["edr"] != OutcomeError {
		t.Errorf("outcomes %v", oc)
	}
	// And the all-unknown result still builds a valid statement.
	k, _ := proof.GenerateSoftwareKey()
	s, _ := proof.NewSoftwareSigner(k)
	h := proof.Header{Seq: 1, NonceSource: proof.NonceAgent, ObservedAt: time.Now(), HeartbeatIntervalS: 900}
	h.Nonce[0], h.Salt[0] = 1, 1
	if _, err := proof.BuildSensorHealth(s.Public(), s.Protection(), h, got); err != nil {
		t.Fatalf("unknown readings do not build: %v", err)
	}
}

func TestSystemProbesNeverFailTheRun(t *testing.T) {
	// On Linux every probe is not applicable; on Windows this runs the
	// real probes. Either way Run must return a buildable result.
	got, reps := NewRunner(SystemProbes()).Run()
	if len(reps) != len(CheckNames()) {
		t.Fatalf("got %d reports", len(reps))
	}
	k, _ := proof.GenerateSoftwareKey()
	s, _ := proof.NewSoftwareSigner(k)
	h := proof.Header{Seq: 1, NonceSource: proof.NonceAgent, ObservedAt: time.Now(), HeartbeatIntervalS: 900}
	h.Nonce[0], h.Salt[0] = 1, 1
	if _, err := proof.BuildSensorHealth(s.Public(), s.Protection(), h, got); err != nil {
		t.Fatalf("system readings do not build: %v (%+v)", err, got)
	}
}
