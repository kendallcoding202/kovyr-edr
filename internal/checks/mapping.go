package checks

import (
	"errors"
	"strings"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Pure mappings from raw probe values to the statement vocabulary. Every
// function returns a value for every input; errors become unknown (or
// not_applicable where the vocabulary has it).

// DecodeProductState decodes a SecurityCenter2 productState.
//
// productState is undocumented by Microsoft. The widely used decoding,
// which this follows, reads it as three bytes: provider type (bits 16-23),
// scanner state (bits 8-15) and signature state (bits 0-7). Scanner 0x10 or
// 0x11 means real-time scanning is on, 0x00 or 0x01 off; signatures 0x00
// mean up to date, 0x10 out of date. Anything else is unknown.
//
//	0x061100 (397568) Defender on,  up to date
//	0x060100 (393472) Defender off, up to date
//	0x061110 (397584) on, out of date
//	0x041000 (266240) third-party on, up to date
func DecodeProductState(state uint32) (enabled, upToDate proof.Toggle) {
	if state == unknownProductState {
		return proof.ToggleUnknown, proof.ToggleUnknown
	}
	switch (state >> 8) & 0xFF {
	case 0x10, 0x11:
		enabled = proof.ToggleOn
	case 0x00, 0x01:
		enabled = proof.ToggleOff
	}
	switch state & 0xFF {
	case 0x00:
		upToDate = proof.ToggleOn
	case 0x10:
		upToDate = proof.ToggleOff
	}
	return enabled, upToDate
}

// unknownProductState marks a product whose productState was NULL.
const unknownProductState = 0xFFFFFFFF

// SecurityCenterFrom summarizes the registered antivirus products. Windows
// Server has no Security Center (ErrNotApplicable).
func SecurityCenterFrom(states []uint32, err error) proof.SecurityCenter {
	if err != nil {
		if errors.Is(err, ErrNotApplicable) {
			return proof.UnknownSecurityCenter(proof.AvailNotApplicable)
		}
		return proof.UnknownSecurityCenter(proof.AvailUnknown)
	}
	if len(states) > proof.MaxAVProducts {
		states = states[:proof.MaxAVProducts]
	}
	out := proof.SecurityCenter{State: proof.AvailOK, Products: int16(len(states))}
	for _, s := range states {
		en, up := DecodeProductState(s)
		if en == proof.ToggleOn {
			out.Enabled++
		}
		if up == proof.ToggleOn {
			out.UpToDate++
		}
	}
	return out
}

// MapRunningMode maps AMRunningMode text to the enum. The text never
// leaves this function.
func MapRunningMode(s string) proof.RunningMode {
	switch strings.Join(strings.Fields(strings.ToLower(s)), " ") {
	case "normal":
		return proof.ModeNormal
	case "passive", "passive mode":
		return proof.ModePassive
	case "edr block mode", "edr block":
		return proof.ModeEDRBlock
	case "sxs passive mode", "sxs passive":
		return proof.ModeSxSPassive
	}
	return proof.ModeUnknown
}

func toggle(b *bool) proof.Toggle {
	switch {
	case b == nil:
		return proof.ToggleUnknown
	case *b:
		return proof.ToggleOn
	}
	return proof.ToggleOff
}

// DefenderFrom maps MSFT_MpComputerStatus. A missing Defender namespace
// (Defender removed, or not a Windows machine) is not applicable.
func DefenderFrom(s DefenderStatus, err error) proof.Defender {
	if err != nil {
		if errors.Is(err, ErrNotApplicable) {
			return proof.UnknownDefender(proof.AvailNotApplicable)
		}
		return proof.UnknownDefender(proof.AvailUnknown)
	}
	out := proof.Defender{
		State:            proof.AvailOK,
		AMService:        toggle(s.AMServiceEnabled),
		Antivirus:        toggle(s.AntivirusEnabled),
		RealTime:         toggle(s.RealTimeProtectionEnabled),
		BehaviorMonitor:  toggle(s.BehaviorMonitorEnabled),
		TamperProtection: toggle(s.IsTamperProtected),
		SignatureAgeDays: proof.UnknownCount,
		RunningMode:      proof.ModeUnknown,
	}
	if s.AntivirusSignatureAge != nil {
		age := *s.AntivirusSignatureAge
		if age > proof.MaxSignatureAgeDays {
			age = proof.MaxSignatureAgeDays // 65535 is also what Defender reports for "never updated"
		}
		out.SignatureAgeDays = int32(age)
	}
	if s.AMRunningMode != nil {
		out.RunningMode = MapRunningMode(*s.AMRunningMode)
	}
	return out
}

// edrServices maps service names (lowercase; service names are
// case-insensitive) to vendors. Names marked "unverified" come from vendor
// documentation or field reports and have not been confirmed on a real
// install; confirm them before relying on a "not installed" answer.
var edrServices = map[string]proof.Vendor{
	"sense":                           proof.VendorDefenderForEndpoint, // Windows Defender Advanced Threat Protection Service
	"csfalconservice":                 proof.VendorCrowdStrike,
	"sentinelagent":                   proof.VendorSentinelOne,
	"huntressagent":                   proof.VendorHuntress,
	"huntressrio":                     proof.VendorHuntress,    // unverified: Huntress EDR sensor
	"sophos endpoint defense service": proof.VendorSophos,      // unverified: Sophos Endpoint Defense (the service name has spaces)
	"savservice":                      proof.VendorSophos,      // unverified: Sophos Anti-Virus (older)
	"epsecurityservice":               proof.VendorBitdefender, // unverified: GravityZone Endpoint Security
	"epprotectedservice":              proof.VendorBitdefender, // unverified
	"vsserv":                          proof.VendorBitdefender, // unverified: consumer Bitdefender
	"ekrn":                            proof.VendorESET,
	"mbamservice":                     proof.VendorMalwarebytes,
	"mbendpointagent":                 proof.VendorMalwarebytes, // unverified: ThreatDown/Malwarebytes endpoint agent
	"wrsvc":                           proof.VendorWebroot,
	"wrcoreservice":                   proof.VendorWebroot,     // unverified
	"cbdefense":                       proof.VendorCarbonBlack, // unverified: Carbon Black Cloud sensor
	"carbonblack":                     proof.VendorCarbonBlack, // unverified: Carbon Black EDR
	"cyserver":                        proof.VendorCortexXDR,   // unverified: Cortex XDR
	"ntrtscan":                        proof.VendorTrendMicro,  // unverified: Apex One / OfficeScan real-time scan
	"sepmasterservice":                proof.VendorSymantec,    // unverified: Symantec Endpoint Protection
}

// VendorForService returns the vendor for an allowlisted service name.
func VendorForService(name string) (proof.Vendor, bool) {
	v, ok := edrServices[strings.ToLower(strings.TrimSpace(name))]
	return v, ok
}

// EDRServiceNames lists the allowlisted service names (for probes that look
// services up by name).
func EDRServiceNames() []string {
	out := make([]string, 0, len(edrServices))
	for n := range edrServices {
		out = append(out, n)
	}
	return out
}

// EDRFrom reduces services to {vendor, running}, one entry per vendor
// (running if any of its services runs). Names not on the allowlist are
// dropped here and never stored.
func EDRFrom(services []Service, err error) proof.EDR {
	if err != nil {
		if errors.Is(err, ErrNotApplicable) {
			return proof.EDR{State: proof.AvailNotApplicable}
		}
		return proof.EDR{State: proof.AvailUnknown}
	}
	running := map[proof.Vendor]bool{}
	for _, s := range services {
		v, ok := VendorForService(s.Name)
		if !ok {
			continue
		}
		running[v] = running[v] || s.Running
	}
	out := proof.EDR{State: proof.AvailOK}
	for v := range running {
		out.Agents = append(out.Agents, proof.EDRAgent{Vendor: v, Running: running[v]})
	}
	return out
}

// BitLockerFrom maps Win32_EncryptableVolume.ProtectionStatus of the OS
// volume: 0 off, 1 on, 2 unknown (volume locked). Access denied (the agent
// is not elevated) is unknown; no BitLocker on this edition is not
// applicable.
func BitLockerFrom(status uint32, err error) proof.VolumeProtection {
	if err != nil {
		if errors.Is(err, ErrNotApplicable) {
			return proof.VolumeNotApplicable
		}
		return proof.VolumeUnknown
	}
	switch status {
	case 0:
		return proof.VolumeOff
	case 1:
		return proof.VolumeOn
	}
	return proof.VolumeUnknown
}

// effectiveProfile applies Group Policy precedence: a policy value, when
// present, overrides the local setting.
func effectiveProfile(p FirewallProfile) (on, known bool) {
	switch {
	case p.Policy != nil:
		return *p.Policy != 0, true
	case p.Local != nil:
		return *p.Local != 0, true
	}
	return false, false
}

// FirewallFrom counts profiles that are on (0-3), or UnknownCount if any
// profile cannot be determined.
func FirewallFrom(s FirewallSettings, err error) int8 {
	if err != nil {
		return proof.UnknownCount
	}
	var n int8
	for _, p := range []FirewallProfile{s.Domain, s.Private, s.Public} {
		on, known := effectiveProfile(p)
		if !known {
			return proof.UnknownCount
		}
		if on {
			n++
		}
	}
	return n
}

// DriverBlocklistFrom maps VulnerableDriverBlocklistEnable: 1 on, 0 off,
// absent default (Windows decides; on by default since Windows 11 22H2).
func DriverBlocklistFrom(v uint32, err error) proof.BlocklistState {
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return proof.BlocklistDefault
		}
		return proof.BlocklistUnknown
	}
	switch v {
	case 0:
		return proof.BlocklistOff
	case 1:
		return proof.BlocklistOn
	}
	return proof.BlocklistUnknown
}

// hvciService is the SecurityServicesRunning value of memory integrity
// (hypervisor-enforced code integrity).
const hvciService = 2

// MemoryIntegrityFrom maps Win32_DeviceGuard SecurityServicesRunning.
func MemoryIntegrityFrom(running []uint32, err error) proof.Toggle {
	if err != nil {
		return proof.ToggleUnknown
	}
	for _, s := range running {
		if s == hvciService {
			return proof.ToggleOn
		}
	}
	return proof.ToggleOff
}
