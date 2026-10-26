package proof

// The sensor_health statement: what the agent signs every heartbeat.
//
// Privacy rule (CLAUDE.md section 3): a statement carries only booleans,
// integers, enums and timestamps, plus fixed-format protocol values (the
// key-derived device ID, hex digests, the nonce and the salt). This file
// cannot see anything else: BuildSensorHealth takes only the typed values
// below (no string, byte slice, map or interface fields, enforced by
// structure_test.go), and this package imports nothing that reads files,
// the network or OS state.
//
// Format (proof spec, as implemented by proof-of-protection/engine):
// in-toto Statement v1, one subject (the device ID, with the key's keyid
// as its sha256 digest), canonical JSON, DSSE envelope, ES256 signature.
// The chain rule is the engine's: prev is the SHA-256 of the previous
// statement's exact payload bytes.
//
// TODO(spec): the proof spec (SPEC.md) does not define a sensor_health
// predicate yet. This one follows the engine's posture/v1 header fields
// (attester, attester_kind, seq, prev, nonce, salt, observed_at) and must
// be added to the spec before halden accepts it.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// InTotoStatementType is the in-toto Statement v1 type URI.
const InTotoStatementType = "https://in-toto.io/Statement/v1"

// PredicateSensorHealth is the predicate type of a heartbeat statement.
// "v0" marks it as a draft until the proof spec defines it.
const PredicateSensorHealth = "https://kovyr.com/attestation/sensor_health/v0"

// DevicePrefix starts every device ID.
const DevicePrefix = "dev_"

// TimeLayout is the only timestamp format in signed data: UTC, seconds.
const TimeLayout = "2006-01-02T15:04:05Z"

// Heartbeat interval bounds, in seconds (1 to 60 minutes).
const (
	MinIntervalS = 60
	MaxIntervalS = 3600
)

// Range caps for counts.
const (
	MaxAVProducts       = 32
	MaxSignatureAgeDays = 65535
)

// Digest, Nonce and Salt are fixed-size protocol values.
type (
	Digest [32]byte
	Nonce  [16]byte
	Salt   [32]byte
)

// GenesisPrev is prev for seq 1. The spec links seq 1 to the device's
// enrollment record; enrollment is a stub in v0, so v0 uses all zeros.
var GenesisPrev Digest

// PayloadDigest is the chain hash: SHA-256 of a statement's exact payload
// bytes. Each statement's prev is the PayloadDigest of the one before.
func PayloadDigest(payload []byte) Digest { return sha256.Sum256(payload) }

// Version is the agent version as three integers (no free-text string).
type Version struct {
	Major, Minor, Patch uint16
}

// Header holds the protocol fields of a statement.
type Header struct {
	Seq                uint32
	Prev               Digest
	Nonce              Nonce
	NonceSource        NonceSource
	Salt               Salt
	ObservedAt         time.Time
	AgentVersion       Version
	HeartbeatIntervalS uint16
}

// Readings are the results of the protection checks. Use UnknownReadings
// as the starting point: its integers are UnknownCount, not 0.
type Readings struct {
	SecurityCenter     SecurityCenter
	Defender           Defender
	EDR                EDR
	BitLocker          VolumeProtection
	FirewallProfilesOn int8 // 0..3 profiles on, or UnknownCount
	DriverBlocklist    BlocklistState
	MemoryIntegrity    Toggle
}

// SecurityCenter is the Windows Security Center antivirus summary.
type SecurityCenter struct {
	State    Availability
	Products int16 // registered antivirus products
	Enabled  int16 // of those, real-time scanning on
	UpToDate int16 // of those, signatures up to date
}

// Defender is the Microsoft Defender Antivirus status.
type Defender struct {
	State            Availability
	AMService        Toggle
	Antivirus        Toggle
	RealTime         Toggle
	BehaviorMonitor  Toggle
	TamperProtection Toggle
	SignatureAgeDays int32 // 0..MaxSignatureAgeDays, or UnknownCount
	RunningMode      RunningMode
}

// EDR lists known EDR agents found on the machine.
type EDR struct {
	State  Availability
	Agents []EDRAgent
}

// EDRAgent is one vendor's agent: present, and running or not.
type EDRAgent struct {
	Vendor  Vendor
	Running bool
}

// UnknownReadings returns readings where everything is unknown.
func UnknownReadings() Readings {
	return Readings{
		SecurityCenter:     UnknownSecurityCenter(AvailUnknown),
		Defender:           UnknownDefender(AvailUnknown),
		FirewallProfilesOn: UnknownCount,
	}
}

// UnknownSecurityCenter is a Security Center reading with no values.
func UnknownSecurityCenter(state Availability) SecurityCenter {
	return SecurityCenter{State: state, Products: UnknownCount, Enabled: UnknownCount, UpToDate: UnknownCount}
}

// UnknownDefender is a Defender reading with no values.
func UnknownDefender(state Availability) Defender {
	return Defender{State: state, SignatureAgeDays: UnknownCount}
}

// BuildSensorHealth returns the canonical payload of a sensor_health
// statement. The device ID and subject are derived from key, so they
// cannot be mistyped. The result is checked against the same schema the
// receiver uses before it is returned.
func BuildSensorHealth(key *PublicKey, protection KeyProtection, h Header, r Readings) ([]byte, error) {
	if key == nil {
		return nil, errors.New("statement needs the device public key")
	}
	if h.Seq == 0 {
		return nil, errors.New("seq starts at 1")
	}
	if h.ObservedAt.IsZero() {
		return nil, errors.New("statement needs ObservedAt")
	}
	if h.Salt == (Salt{}) {
		return nil, errors.New("statement needs a random salt (see NewSalt)")
	}
	if h.Nonce == (Nonce{}) {
		return nil, errors.New("statement needs a nonce")
	}
	var e enc
	agents := append([]EDRAgent(nil), r.EDR.Agents...)
	// Sorted by vendor name, as the schema requires (the receiver rejects
	// unsorted or repeated vendors).
	sort.Slice(agents, func(i, j int) bool { return agents[i].Vendor.String() < agents[j].Vendor.String() })
	agentList := make([]any, 0, len(agents))
	for _, a := range agents {
		agentList = append(agentList, map[string]any{
			"vendor":  e.name(vendorNames, uint8(a.Vendor)),
			"running": a.Running,
		})
	}
	sc, d := r.SecurityCenter, r.Defender
	checks := map[string]any{
		"security_center": map[string]any{
			"state":      e.name(availabilityNames, uint8(sc.State)),
			"products":   int64(sc.Products),
			"enabled":    int64(sc.Enabled),
			"up_to_date": int64(sc.UpToDate),
		},
		"defender": map[string]any{
			"state":                e.name(availabilityNames, uint8(d.State)),
			"am_service":           e.name(toggleNames, uint8(d.AMService)),
			"antivirus":            e.name(toggleNames, uint8(d.Antivirus)),
			"real_time_protection": e.name(toggleNames, uint8(d.RealTime)),
			"behavior_monitor":     e.name(toggleNames, uint8(d.BehaviorMonitor)),
			"tamper_protection":    e.name(toggleNames, uint8(d.TamperProtection)),
			"signature_age_days":   int64(d.SignatureAgeDays),
			"running_mode":         e.name(runningModeNames, uint8(d.RunningMode)),
		},
		"edr": map[string]any{
			"state":  e.name(availabilityNames, uint8(r.EDR.State)),
			"agents": agentList,
		},
		"bitlocker_os_volume":         e.name(volumeNames, uint8(r.BitLocker)),
		"firewall_profiles_on":        int64(r.FirewallProfilesOn),
		"vulnerable_driver_blocklist": e.name(blocklistNames, uint8(r.DriverBlocklist)),
		"memory_integrity":            e.name(toggleNames, uint8(r.MemoryIntegrity)),
	}
	pred := map[string]any{
		"attester":      key.DeviceID(),
		"attester_kind": attesterKindNames[0],
		"seq":           int64(h.Seq),
		"prev":          hex.EncodeToString(h.Prev[:]),
		"nonce":         hex.EncodeToString(h.Nonce[:]),
		"nonce_source":  e.name(nonceSourceNames, uint8(h.NonceSource)),
		"salt":          hex.EncodeToString(h.Salt[:]),
		"observed_at":   h.ObservedAt.UTC().Format(TimeLayout),
		"agent_version": map[string]any{
			"major": int64(h.AgentVersion.Major),
			"minor": int64(h.AgentVersion.Minor),
			"patch": int64(h.AgentVersion.Patch),
		},
		"key_protection":       e.name(keyProtectionNames, uint8(protection)),
		"heartbeat_interval_s": int64(h.HeartbeatIntervalS),
		"checks":               checks,
	}
	if e.err != nil {
		return nil, fmt.Errorf("builder refused statement: %w", e.err)
	}
	st := map[string]any{
		"_type":         InTotoStatementType,
		"predicateType": PredicateSensorHealth,
		"subject": []any{map[string]any{
			"name":   key.DeviceID(),
			"digest": map[string]any{"sha256": key.KeyID()},
		}},
		"predicate": pred,
	}
	if err := checkStatement(st); err != nil {
		return nil, fmt.Errorf("builder refused statement: %w", err)
	}
	return EncodeCanonical(st)
}

// enc collects the first enum that is outside its table.
type enc struct{ err error }

func (e *enc) name(table []string, v uint8) string {
	n, err := enumName(table, v)
	if err != nil && e.err == nil {
		e.err = err
	}
	return n
}

// Statement is a validated sensor_health statement, decoded back into the
// typed vocabulary.
type Statement struct {
	DeviceID           string
	KeyID              string
	Seq                uint32
	Prev               Digest
	Nonce              Nonce
	NonceSource        NonceSource
	Salt               Salt
	ObservedAt         time.Time
	AgentVersion       Version
	KeyProtection      KeyProtection
	HeartbeatIntervalS uint16
	Readings           Readings
}

// ValidateSensorHealth checks that payload is a canonical sensor_health
// statement that obeys the schema, and decodes it.
func ValidateSensorHealth(payload []byte) (*Statement, error) {
	obj, err := ParseCanonicalObject(payload)
	if err != nil {
		return nil, err
	}
	if err := checkStatement(obj); err != nil {
		return nil, err
	}
	return decodeStatement(obj), nil
}

// decodeStatement converts a statement that passed checkStatement; every
// type assertion below is guaranteed by the schema.
func decodeStatement(obj map[string]any) *Statement {
	p := obj["predicate"].(map[string]any)
	subj := obj["subject"].([]any)[0].(map[string]any)
	c := p["checks"].(map[string]any)
	sc := c["security_center"].(map[string]any)
	d := c["defender"].(map[string]any)
	e := c["edr"].(map[string]any)
	av := p["agent_version"].(map[string]any)
	at, _ := time.Parse(TimeLayout, p["observed_at"].(string))
	ev := func(table []string, v any) uint8 { n, _ := enumValue(table, v.(string)); return n }
	st := &Statement{
		DeviceID:           p["attester"].(string),
		KeyID:              subj["digest"].(map[string]any)["sha256"].(string),
		Seq:                uint32(p["seq"].(int64)),
		NonceSource:        NonceSource(ev(nonceSourceNames, p["nonce_source"])),
		ObservedAt:         at,
		KeyProtection:      KeyProtection(ev(keyProtectionNames, p["key_protection"])),
		HeartbeatIntervalS: uint16(p["heartbeat_interval_s"].(int64)),
		AgentVersion: Version{
			Major: uint16(av["major"].(int64)), Minor: uint16(av["minor"].(int64)), Patch: uint16(av["patch"].(int64)),
		},
		Readings: Readings{
			SecurityCenter: SecurityCenter{
				State:    Availability(ev(availabilityNames, sc["state"])),
				Products: int16(sc["products"].(int64)), Enabled: int16(sc["enabled"].(int64)),
				UpToDate: int16(sc["up_to_date"].(int64)),
			},
			Defender: Defender{
				State:            Availability(ev(availabilityNames, d["state"])),
				AMService:        Toggle(ev(toggleNames, d["am_service"])),
				Antivirus:        Toggle(ev(toggleNames, d["antivirus"])),
				RealTime:         Toggle(ev(toggleNames, d["real_time_protection"])),
				BehaviorMonitor:  Toggle(ev(toggleNames, d["behavior_monitor"])),
				TamperProtection: Toggle(ev(toggleNames, d["tamper_protection"])),
				SignatureAgeDays: int32(d["signature_age_days"].(int64)),
				RunningMode:      RunningMode(ev(runningModeNames, d["running_mode"])),
			},
			EDR:                EDR{State: Availability(ev(availabilityNames, e["state"]))},
			BitLocker:          VolumeProtection(ev(volumeNames, c["bitlocker_os_volume"])),
			FirewallProfilesOn: int8(c["firewall_profiles_on"].(int64)),
			DriverBlocklist:    BlocklistState(ev(blocklistNames, c["vulnerable_driver_blocklist"])),
			MemoryIntegrity:    Toggle(ev(toggleNames, c["memory_integrity"])),
		},
	}
	for _, a := range e["agents"].([]any) {
		ao := a.(map[string]any)
		st.Readings.EDR.Agents = append(st.Readings.EDR.Agents, EDRAgent{
			Vendor: Vendor(ev(vendorNames, ao["vendor"])), Running: ao["running"].(bool),
		})
	}
	hex.Decode(st.Prev[:], []byte(p["prev"].(string)))
	hex.Decode(st.Nonce[:], []byte(p["nonce"].(string)))
	hex.Decode(st.Salt[:], []byte(p["salt"].(string)))
	return st
}
