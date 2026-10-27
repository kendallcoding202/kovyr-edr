//go:build !windows

package checks

// SystemProbes returns the probes for this machine. The agent's checks are
// Windows checks; elsewhere every probe is not applicable, so `check` and
// the dev loop still run (and report not_applicable/unknown) on Linux.
func SystemProbes() Probes { return otherProbes{} }

type otherProbes struct{}

func (otherProbes) AVProductStates() ([]uint32, error) { return nil, ErrNotApplicable }
func (otherProbes) DefenderStatus() (DefenderStatus, error) {
	return DefenderStatus{}, ErrNotApplicable
}
func (otherProbes) Services() ([]Service, error)              { return nil, ErrNotApplicable }
func (otherProbes) OSVolumeProtectionStatus() (uint32, error) { return 0, ErrNotApplicable }
func (otherProbes) Firewall() (FirewallSettings, error)       { return FirewallSettings{}, ErrNotApplicable }
func (otherProbes) DriverBlocklist() (uint32, error)          { return 0, ErrNotApplicable }
func (otherProbes) DeviceGuardServicesRunning() ([]uint32, error) {
	return nil, ErrNotApplicable
}
