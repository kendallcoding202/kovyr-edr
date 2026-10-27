package checks

// Fake is a Probes implementation for tests on any OS. Each probe returns
// the matching fields; Hook, if set, runs first with the probe name so a
// test can block or panic inside a probe.
type Fake struct {
	AVStates       []uint32
	AVErr          error
	Defender       DefenderStatus
	DefenderErr    error
	ServiceList    []Service
	ServicesErr    error
	BitLocker      uint32
	BitLockerErr   error
	FirewallValues FirewallSettings
	FirewallErr    error
	Blocklist      uint32
	BlocklistErr   error
	DeviceGuard    []uint32
	DeviceGuardErr error
	Hook           func(probe string)
}

func (f Fake) hook(name string) {
	if f.Hook != nil {
		f.Hook(name)
	}
}

func (f Fake) AVProductStates() ([]uint32, error) {
	f.hook("security_center")
	return f.AVStates, f.AVErr
}
func (f Fake) DefenderStatus() (DefenderStatus, error) {
	f.hook("defender")
	return f.Defender, f.DefenderErr
}
func (f Fake) Services() ([]Service, error) { f.hook("edr"); return f.ServiceList, f.ServicesErr }
func (f Fake) OSVolumeProtectionStatus() (uint32, error) {
	f.hook("bitlocker")
	return f.BitLocker, f.BitLockerErr
}
func (f Fake) Firewall() (FirewallSettings, error) {
	f.hook("firewall")
	return f.FirewallValues, f.FirewallErr
}
func (f Fake) DriverBlocklist() (uint32, error) {
	f.hook("driver_blocklist")
	return f.Blocklist, f.BlocklistErr
}
func (f Fake) DeviceGuardServicesRunning() ([]uint32, error) {
	f.hook("memory_integrity")
	return f.DeviceGuard, f.DeviceGuardErr
}

func ptr[T any](v T) *T { return &v }

// HealthyFake is a well-protected Windows 11 machine: Defender active with
// Defender for Endpoint, BitLocker on, all firewall profiles on, memory
// integrity on.
func HealthyFake() Fake {
	on := ptr(uint32(1))
	return Fake{
		AVStates: []uint32{0x061100},
		Defender: DefenderStatus{
			AMServiceEnabled: ptr(true), AntivirusEnabled: ptr(true), RealTimeProtectionEnabled: ptr(true),
			BehaviorMonitorEnabled: ptr(true), IsTamperProtected: ptr(true),
			AntivirusSignatureAge: ptr(uint32(0)), AMRunningMode: ptr("Normal"),
		},
		ServiceList:    []Service{{Name: "Sense", Running: true}, {Name: "Spooler", Running: true}},
		BitLocker:      1,
		FirewallValues: FirewallSettings{Domain: FirewallProfile{Local: on}, Private: FirewallProfile{Local: on}, Public: FirewallProfile{Local: on}},
		BlocklistErr:   ErrNotFound,
		DeviceGuard:    []uint32{2},
	}
}
