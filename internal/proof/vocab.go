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

// KeyProtection is where the device private key lives: its evidence
// strength. Per SPEC section 6.3 it belongs in the attester enrollment
// record (key_protection), not in each statement; enroll --print-pubkey
// reports it.
type KeyProtection uint8

const (
	keyProtectionInvalid KeyProtection = iota
	KeySoftware                        // v0: a software key (DPAPI on Windows)
	KeyTPM2                            // later: a TPM key via the Platform Crypto Provider
)

var keyProtectionNames = []string{"", "software", "tpm2"}

// TripReason is which tripwire rule fired (SPEC 6.5 tripwire.reason).
type TripReason uint8

const (
	TripNone                TripReason = iota // not triggered
	TripMassExtensionChange                   // many renames, most to a new extension
	TripRansomNotes                           // ransom-note or random names during a burst
)

var tripReasonNames = []string{"none", "mass_extension_change", "ransom_notes"}

// TripWindow is the tripwire's sliding window. Zero is not a window; the
// builder refuses it when the tripwire is watching.
type TripWindow uint8

const (
	tripWindowInvalid TripWindow = iota
	TripWindow10s
	TripWindow30s
	TripWindow60s
	TripWindow120s
	TripWindow300s
)

var tripWindowNames = []string{"", "10s", "30s", "60s", "120s", "300s"}

// TripBucket is a bucketed count, so a statement never shows exactly how
// many files someone changed.
type TripBucket uint8

const (
	Bucket0 TripBucket = iota
	Bucket1to9
	Bucket10to99
	Bucket100to999
	Bucket1000Plus
)

var bucketNames = []string{"0", "1_9", "10_99", "100_999", "1000_plus"}

// BucketOf buckets a count.
func BucketOf(n uint32) TripBucket {
	switch {
	case n == 0:
		return Bucket0
	case n < 10:
		return Bucket1to9
	case n < 100:
		return Bucket10to99
	case n < 1000:
		return Bucket100to999
	}
	return Bucket1000Plus
}

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
func (v TripReason) String() string       { return nameOr(tripReasonNames, uint8(v)) }
func (v TripWindow) String() string       { return nameOr(tripWindowNames, uint8(v)) }
func (v TripBucket) String() string       { return nameOr(bucketNames, uint8(v)) }

func nameOr(table []string, v uint8) string {
	if n, err := enumName(table, v); err == nil {
		return n
	}
	return fmt.Sprintf("invalid(%d)", v)
}
