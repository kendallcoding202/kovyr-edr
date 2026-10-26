package checks

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// TestRealWindowsChecks runs the real probes on this Windows machine (in
// CI: a GitHub windows-latest runner, which is Windows Server). Values may
// be unknown or not_applicable there; what must hold is that every check
// completes without a panic, in bounded time, and that the result signs
// into a statement that verifies and validates. The readings are logged so
// CI shows what the runner reported.
func TestRealWindowsChecks(t *testing.T) {
	v := windows.RtlGetVersion()
	t.Logf("Windows %d.%d build %d, product type %d (1 = workstation, 3 = server), elevated %v",
		v.MajorVersion, v.MinorVersion, v.BuildNumber, v.ProductType, windows.GetCurrentProcessToken().IsElevated())
	r := NewRunner(SystemProbes())
	start := time.Now()
	readings, reports := r.Run()
	took := time.Since(start)
	if v.ProductType != verNTWorkstation && readings.SecurityCenter.State != proof.AvailNotApplicable {
		t.Errorf("Security Center on a server edition must be not_applicable, got %v", readings.SecurityCenter.State)
	}
	if took > DefaultTimeout+5*time.Second {
		t.Errorf("checks took %v", took)
	}
	if len(reports) != len(CheckNames()) {
		t.Fatalf("got %d reports, want %d", len(reports), len(CheckNames()))
	}
	for _, rep := range reports {
		t.Logf("check %-17s outcome %-20s %v", rep.Name, rep.Outcome, rep.Duration.Round(time.Millisecond))
		if rep.Outcome == OutcomePanic {
			t.Errorf("check %s panicked", rep.Name)
		}
	}
	t.Logf("security_center: %+v", readings.SecurityCenter)
	t.Logf("defender:        %+v", readings.Defender)
	t.Logf("edr:             %+v", readings.EDR)
	t.Logf("bitlocker:       %v", readings.BitLocker)
	t.Logf("firewall on:     %d of 3", readings.FirewallProfilesOn)
	t.Logf("driver blocklist %v", readings.DriverBlocklist)
	t.Logf("memory integrity %v", readings.MemoryIntegrity)
	t.Logf("total            %v", took.Round(time.Millisecond))

	k, err := proof.GenerateSoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	s, _ := proof.NewSoftwareSigner(k)
	h := proof.Header{Seq: 1, ObservedAt: time.Now(), AgentVersion: proof.Version{Minor: 1}}
	h.Salt, _ = proof.NewSalt()
	n, _ := proof.NewSalt()
	copy(h.Nonce[:], n[:])
	payload, err := proof.BuildStatement(s.Public(), h, proof.SensorHealth{SensorRunning: true}, readings)
	if err != nil {
		t.Fatalf("real readings do not build a statement: %v (%+v)", err, readings)
	}
	env, err := proof.SignEnvelope(payload, s)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := proof.ParseEnvelope(env.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(s.Public()); err != nil {
		t.Fatalf("signature: %v", err)
	}
	st, err := proof.ValidateStatement(parsed.Payload)
	if err != nil {
		t.Fatalf("statement does not validate: %v", err)
	}
	if st.Readings.SecurityCenter != readings.SecurityCenter || st.Readings.Defender != readings.Defender {
		t.Error("readings did not survive the round trip")
	}
	t.Logf("statement %d bytes, envelope %d bytes", len(payload), len(env.Canonical()))
}
