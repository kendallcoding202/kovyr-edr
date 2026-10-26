package proof

import "fmt"

// The vocabulary of a sensor_health statement.
//
// Every enum is a small unsigned integer with a fixed name table, never a
// Go string, so a check cannot hand the builder text it read from the
// machine: there is no string-typed field to put it in, and an integer
// outside the table is refused. Where an enum has "unknown", it is the
// zero value, so a reading a check forgot to fill reports unknown, never a
// false "on".
//
// Integers use -1 (UnknownCount) for "unknown or not applicable".

// UnknownCount is the integer value for "unknown or not applicable".
const UnknownCount = -1

// Availability says whether a multi-value check could run here.
type Availability uint8

const (
	AvailUnknown       Availability = iota // the check failed (timeout, access denied, error)
	AvailOK                                // the check ran and its values are real
	AvailNotApplicable                     // the feature does not exist here (e.g. Security Center on Windows Server)
)

var availabilityNames = []string{"unknown", "ok", "not_applicable"}

// Toggle is an on/off setting.
type Toggle uint8

const (
	ToggleUnknown Toggle = iota
	ToggleOn
	ToggleOff
)

var toggleNames = []string{"unknown", "on", "off"}

// BlocklistState is the Microsoft vulnerable driver blocklist setting.
// Default means the registry value is absent and Windows' own default
// applies (on by default since Windows 11 22H2).
type BlocklistState uint8

const (
	BlocklistUnknown BlocklistState = iota
	BlocklistOn
	BlocklistOff
	BlocklistDefault
)

var blocklistNames = []string{"unknown", "on", "off", "default"}

// VolumeProtection is BitLocker protection of the OS volume.
type VolumeProtection uint8

const (
	VolumeUnknown VolumeProtection = iota
	VolumeOn
	VolumeOff
	VolumeNotApplicable
)

var volumeNames = []string{"unknown", "on", "off", "not_applicable"}

// RunningMode is Microsoft Defender Antivirus' AMRunningMode.
type RunningMode uint8

const (
	ModeUnknown    RunningMode = iota
	ModeNormal                 // active antivirus
	ModePassive                // another antivirus is primary
	ModeEDRBlock               // passive, with EDR in block mode
	ModeSxSPassive             // side-by-side passive (limited periodic scanning)
)

var runningModeNames = []string{"unknown", "normal", "passive", "edr_block", "sxs_passive"}

// Vendor is a known third-party EDR/antivirus agent. Zero is not a
// vendor; the builder refuses it.
type Vendor uint8

const (
	vendorInvalid Vendor = iota
	VendorDefenderForEndpoint
	VendorCrowdStrike
	VendorSentinelOne
	VendorHuntress
	VendorSophos
	VendorBitdefender
	VendorESET
	VendorMalwarebytes
	VendorWebroot
	VendorCarbonBlack
	VendorCortexXDR
	VendorTrendMicro
	VendorSymantec
	vendorCount // keep last
)

var vendorNames = []string{
	"", "microsoft_defender_endpoint", "crowdstrike", "sentinelone", "huntress", "sophos",
	"bitdefender", "eset", "malwarebytes", "webroot", "carbon_black", "cortex_xdr",
	"trend_micro", "symantec",
}

// MaxEDRAgents caps the EDR list; there is one entry per vendor.
const MaxEDRAgents = int(vendorCount) - 1

// KeyProtection is where the device private key lives: the evidence
// strength of the statement's signature.
type KeyProtection uint8

const (
	keyProtectionInvalid KeyProtection = iota
	KeySoftware                        // v0: a software key (DPAPI on Windows)
	KeyTPM2                            // later: a TPM key via the Platform Crypto Provider
)

var keyProtectionNames = []string{"", "software", "tpm2"}

// NonceSource says where the statement's nonce came from.
type NonceSource uint8

const (
	nonceSourceInvalid NonceSource = iota
	// NonceServer: a one-time challenge from GET /v0/challenge. The
	// statement was made after the server issued it.
	NonceServer
	// NonceAgent: the challenge could not be fetched (offline), so the
	// agent used a random nonce. Freshness then rests on the hash chain:
	// the statement sits between the challenged statements around it.
	NonceAgent
)

var nonceSourceNames = []string{"", "server", "agent"}

// attesterKindNames has one value: this agent is a device agent.
var attesterKindNames = []string{"device_agent"}

func enumName(table []string, v uint8) (string, error) {
	if int(v) >= len(table) || table[v] == "" {
		return "", fmt.Errorf("value %d is not in the vocabulary", v)
	}
	return table[v], nil
}

func enumValue(table []string, name string) (uint8, bool) {
	for i, n := range table {
		if n != "" && n == name {
			return uint8(i), true
		}
	}
	return 0, false
}

// String methods, for the plain-English table and logs.
func (v Availability) String() string     { return nameOr(availabilityNames, uint8(v)) }
func (v Toggle) String() string           { return nameOr(toggleNames, uint8(v)) }
func (v BlocklistState) String() string   { return nameOr(blocklistNames, uint8(v)) }
func (v VolumeProtection) String() string { return nameOr(volumeNames, uint8(v)) }
func (v RunningMode) String() string      { return nameOr(runningModeNames, uint8(v)) }
func (v Vendor) String() string           { return nameOr(vendorNames, uint8(v)) }
func (v KeyProtection) String() string    { return nameOr(keyProtectionNames, uint8(v)) }
func (v NonceSource) String() string      { return nameOr(nonceSourceNames, uint8(v)) }

func nameOr(table []string, v uint8) string {
	if n, err := enumName(table, v); err == nil {
		return n
	}
	return fmt.Sprintf("invalid(%d)", v)
}
