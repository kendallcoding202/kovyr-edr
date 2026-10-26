// Package checks reads the machine's protection status, read-only.
//
// Each OS-specific read sits behind the Probes interface: probes_windows.go
// talks to WMI, the registry and the service manager; probes_other.go
// reports "not applicable" elsewhere; Fake drives the tests. The mapping
// from raw values to the statement vocabulary (mapping.go) is pure and
// tested on every OS.
//
// Rules (CLAUDE.md section 2): checks never change anything, never error
// out (a failed check is "unknown") and never block. Runner gives every
// check a deadline, recovers panics and never starts a second copy of a
// check whose previous run is still stuck.
package checks

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Probe error classes. Probes wrap or return these so the mapping can tell
// "this feature does not exist here" from "we could not read it".
var (
	ErrNotApplicable = errors.New("not applicable on this machine")
	ErrAccessDenied  = errors.New("access denied")
	ErrNotFound      = errors.New("not found")
	// ErrEncryptionRequired is WMI's WBEM_E_ENCRYPTED_CONNECTION_REQUIRED.
	ErrEncryptionRequired = errors.New("namespace requires an encrypted connection")
)

// DefenderStatus is the raw MSFT_MpComputerStatus instance. Nil fields
// were NULL or missing.
type DefenderStatus struct {
	AMServiceEnabled          *bool
	AntivirusEnabled          *bool
	RealTimeProtectionEnabled *bool
	BehaviorMonitorEnabled    *bool
	IsTamperProtected         *bool
	AntivirusSignatureAge     *uint32
	AMRunningMode             *string
}

// Service is an installed service. Name stays inside this package: only
// the vendor enum and running flag reach a statement.
type Service struct {
	Name    string
	Running bool
}

// FirewallProfile holds the EnableFirewall registry values for one
// profile. Policy is the Group Policy value, Local the local setting; nil
// means absent.
type FirewallProfile struct {
	Policy *uint32
	Local  *uint32
}

// FirewallSettings covers the three profiles.
type FirewallSettings struct {
	Domain, Private, Public FirewallProfile
}

// Probes are the raw, OS-specific reads. Implementations may block or
// panic; Runner contains both.
type Probes interface {
	// AVProductStates returns productState of each SecurityCenter2
	// AntiVirusProduct.
	AVProductStates() ([]uint32, error)
	// DefenderStatus returns MSFT_MpComputerStatus.
	DefenderStatus() (DefenderStatus, error)
	// Services returns installed services whose names are on the EDR
	// allowlist (implementations may return more; the mapping filters).
	Services() ([]Service, error)
	// OSVolumeProtectionStatus returns Win32_EncryptableVolume
	// ProtectionStatus of the OS volume.
	OSVolumeProtectionStatus() (uint32, error)
	// Firewall returns the EnableFirewall registry values.
	Firewall() (FirewallSettings, error)
	// DriverBlocklist returns VulnerableDriverBlocklistEnable, or
	// ErrNotFound when it is absent.
	DriverBlocklist() (uint32, error)
	// DeviceGuardServicesRunning returns Win32_DeviceGuard
	// SecurityServicesRunning.
	DeviceGuardServicesRunning() ([]uint32, error)
}

// Outcome is how a check went. It is local diagnostics for the `check`
// table and logs, never part of a statement.
type Outcome string

const (
	OutcomeOK                 Outcome = "ok"
	OutcomeNotApplicable      Outcome = "not_applicable"
	OutcomeAccessDenied       Outcome = "access_denied"
	OutcomeNotFound           Outcome = "not_found"
	OutcomeEncryptionRequired Outcome = "encryption_required"
	OutcomeError              Outcome = "error"
	OutcomeTimeout            Outcome = "timeout"
	OutcomeBusy               Outcome = "busy" // the previous run of this check is still stuck
	OutcomePanic              Outcome = "panic"
)

func outcomeOf(err error) Outcome {
	switch {
	case err == nil:
		return OutcomeOK
	case errors.Is(err, ErrNotApplicable):
		return OutcomeNotApplicable
	case errors.Is(err, ErrAccessDenied):
		return OutcomeAccessDenied
	case errors.Is(err, ErrNotFound):
		return OutcomeNotFound
	case errors.Is(err, ErrEncryptionRequired):
		return OutcomeEncryptionRequired
	}
	return OutcomeError
}

// CheckReport is the diagnostics for one check.
type CheckReport struct {
	Name     string
	Outcome  Outcome
	Duration time.Duration
}

// DefaultTimeout bounds one Run. WMI queries are serialized by the WMI
// library, so the budget covers all of them.
const DefaultTimeout = 20 * time.Second

// Runner runs every check with a deadline. It is safe for one caller at a
// time (the heartbeat loop).
type Runner struct {
	Probes  Probes
	Timeout time.Duration

	mu   sync.Mutex
	busy map[string]bool
}

// NewRunner returns a runner over p.
func NewRunner(p Probes) *Runner { return &Runner{Probes: p, Timeout: DefaultTimeout} }

type checkFn struct {
	name string
	run  func() (func(*proof.Readings), Outcome)
}

func (r *Runner) checks() []checkFn {
	p := r.Probes
	return []checkFn{
		{"security_center", func() (func(*proof.Readings), Outcome) {
			s, err := p.AVProductStates()
			v := SecurityCenterFrom(s, err)
			return func(o *proof.Readings) { o.SecurityCenter = v }, outcomeOf(err)
		}},
		{"defender", func() (func(*proof.Readings), Outcome) {
			s, err := p.DefenderStatus()
			v := DefenderFrom(s, err)
			return func(o *proof.Readings) { o.Defender = v }, outcomeOf(err)
		}},
		{"edr", func() (func(*proof.Readings), Outcome) {
			s, err := p.Services()
			v := EDRFrom(s, err)
			return func(o *proof.Readings) { o.EDR = v }, outcomeOf(err)
		}},
		{"bitlocker", func() (func(*proof.Readings), Outcome) {
			s, err := p.OSVolumeProtectionStatus()
			v := BitLockerFrom(s, err)
			return func(o *proof.Readings) { o.BitLocker = v }, outcomeOf(err)
		}},
		{"firewall", func() (func(*proof.Readings), Outcome) {
			s, err := p.Firewall()
			v := FirewallFrom(s, err)
			return func(o *proof.Readings) { o.FirewallProfilesOn = v }, outcomeOf(err)
		}},
		{"driver_blocklist", func() (func(*proof.Readings), Outcome) {
			s, err := p.DriverBlocklist()
			v := DriverBlocklistFrom(s, err)
			oc := outcomeOf(err)
			if errors.Is(err, ErrNotFound) {
				oc = OutcomeOK // absent means "Windows default", a real answer
			}
			return func(o *proof.Readings) { o.DriverBlocklist = v }, oc
		}},
		{"memory_integrity", func() (func(*proof.Readings), Outcome) {
			s, err := p.DeviceGuardServicesRunning()
			v := MemoryIntegrityFrom(s, err)
			return func(o *proof.Readings) { o.MemoryIntegrity = v }, outcomeOf(err)
		}},
	}
}

// CheckNames lists the checks in display order.
func CheckNames() []string {
	var out []string
	for _, c := range (&Runner{Probes: Fake{}}).checks() {
		out = append(out, c.name)
	}
	return out
}

// Run runs all checks concurrently and returns within Timeout. Checks that
// fail, panic or miss the deadline report unknown.
func (r *Runner) Run() (proof.Readings, []CheckReport) {
	out := proof.UnknownReadings()
	type result struct {
		name    string
		set     func(*proof.Readings)
		outcome Outcome
		took    time.Duration
	}
	list := r.checks()
	ch := make(chan result, len(list)) // buffered: a late check never blocks
	pending := map[string]bool{}
	var reports []CheckReport
	start := time.Now()
	for _, c := range list {
		if !r.acquire(c.name) {
			reports = append(reports, CheckReport{Name: c.name, Outcome: OutcomeBusy})
			continue
		}
		pending[c.name] = true
		go func(c checkFn) {
			t0 := time.Now()
			res := result{name: c.name, outcome: OutcomePanic}
			defer r.release(c.name)
			defer func() {
				if recover() != nil {
					res.set, res.outcome = nil, OutcomePanic
				}
				res.took = time.Since(t0)
				ch <- res
			}()
			res.set, res.outcome = c.run()
		}(c)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for len(pending) > 0 {
		select {
		case res := <-ch:
			delete(pending, res.name)
			if res.set != nil {
				res.set(&out)
			}
			reports = append(reports, CheckReport{Name: res.name, Outcome: res.outcome, Duration: res.took})
		case <-timer.C:
			for name := range pending {
				reports = append(reports, CheckReport{Name: name, Outcome: OutcomeTimeout, Duration: time.Since(start)})
			}
			pending = nil
		}
	}
	order := map[string]int{}
	for i, c := range list {
		order[c.name] = i
	}
	sort.Slice(reports, func(i, j int) bool { return order[reports[i].Name] < order[reports[j].Name] })
	return out, reports
}

func (r *Runner) acquire(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy == nil {
		r.busy = map[string]bool{}
	}
	if r.busy[name] {
		return false
	}
	r.busy[name] = true
	return true
}

func (r *Runner) release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.busy, name)
}
