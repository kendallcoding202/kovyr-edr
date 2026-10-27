// Package posture defines what a statement may say, builds statements from
// typed values, and validates statements received from anywhere.
//
// The privacy rule is structural. Statements carry only booleans, integers,
// enums and timestamps, plus fixed-format protocol identifiers (key-derived
// IDs, hex digests and nonces, public keys). There is no field that can
// hold a file name, path, host name, user name, email content or any other
// free text, and both the builder and the validator reject anything the
// schema does not list.
//
// The builder (Build* functions) accepts only typed Go values, never a
// string, byte slice, map, file or path, and this package imports nothing
// that touches the file system, network or OS. Both properties are
// enforced by tests (structure_test.go), so the rule can be checked by
// tooling rather than reviewer diligence. Collectors that do see paths
// (for example an agent reading the registry) must classify into these
// types before calling the builder.
//
// The schema is data (Spec values) so that other verifiers can interpret
// exactly the same rules; SchemaJSON exports it.
package posture

import (
	"encoding/json"

	"github.com/kendallcoding202/kovyr-edr/proof/brand"
	"github.com/kendallcoding202/kovyr-edr/proof/canon"
)

// InTotoStatementType is the in-toto Statement v1 type URI.
const InTotoStatementType = "https://in-toto.io/Statement/v1"

// Spec describes one value. T is one of: bool, int, enum, timestamp, hex,
// id, spki, const, object, array, counted_list, result_list.
type Spec struct {
	T        string           `json:"t"`
	Min      *int64           `json:"min,omitempty"`
	Max      *int64           `json:"max,omitempty"`
	Values   []string         `json:"values,omitempty"`    // enum
	Len      int              `json:"len,omitempty"`       // hex: number of hex characters
	Prefixes []string         `json:"prefixes,omitempty"`  // id: allowed prefixes, then 16 hex
	Value    string           `json:"value,omitempty"`     // const
	Fields   map[string]*Spec `json:"fields,omitempty"`    // object: every field is required
	Switch   *Switch          `json:"switch,omitempty"`    // object: extra fields chosen by a tag
	LE       [][2]string      `json:"le,omitempty"`        // object: int field a <= int field b
	Of       *Spec            `json:"of,omitempty"`        // array element
	MinItems int              `json:"min_items,omitempty"` // array / counted_list
	MaxItems int              `json:"max_items,omitempty"` // array / counted_list
	Kinds    []string         `json:"kinds,omitempty"`     // counted_list
	MaxCount int64            `json:"max_count,omitempty"` // counted_list
	Key      string           `json:"key,omitempty"`       // result_list: items sorted and unique by this field
}

// Switch adds fields to an object depending on the enum value of field On.
type Switch struct {
	On    string                      `json:"on"`
	Cases map[string]map[string]*Spec `json:"cases"`
}

func i64(n int64) *int64 { return &n }

func boolean() *Spec               { return &Spec{T: "bool"} }
func integer(min, max int64) *Spec { return &Spec{T: "int", Min: i64(min), Max: i64(max)} }
func enum(v ...string) *Spec       { return &Spec{T: "enum", Values: v} }
func timestamp() *Spec             { return &Spec{T: "timestamp"} }
func hexN(n int) *Spec             { return &Spec{T: "hex", Len: n} }
func id(p ...string) *Spec         { return &Spec{T: "id", Prefixes: p} }
func constant(v string) *Spec      { return &Spec{T: "const", Value: v} }
func object(f map[string]*Spec) *Spec {
	return &Spec{T: "object", Fields: f}
}

// countedList is {"items":[{"count":n,"kind":k},...],"total":n,"truncated":b}:
// a capped list of enum+count pairs instead of prose. Items are sorted by
// kind and unique; if more kinds were observed than fit, the list keeps the
// most frequent and sets truncated (total stays exact).
func countedList(maxItems int, maxCount int64, kinds ...string) *Spec {
	return &Spec{T: "counted_list", Kinds: kinds, MaxItems: maxItems, MaxCount: maxCount}
}

// resultList is {"items":[{...},...],"total":n,"truncated":b}: a capped
// list of fixed-shape records (each matching of), sorted and unique by key.
// total is the true number of records; truncated says some were left out.
func resultList(maxItems int, key string, of *Spec) *Spec {
	return &Spec{T: "result_list", Of: of, Key: key, MaxItems: maxItems}
}

// Prefixes of key-derived identifiers.
const (
	PrefixTenant    = "tnt_"
	PrefixDevice    = "dev_"
	PrefixConnector = "con_"
	PrefixStaff     = "stf_"
	PrefixScanner   = "scn_"
)

// MaxCount bounds every count so no field can smuggle large numbers.
const maxCount = 100000

// Enumerations (read-only; exported through the schema). Values ending in
// "_approx" come from approximate classifications (for example IP
// geolocation) and must be shown as such.
var (
	attesterKinds       = []string{"cloud_connector", "device_agent", "external_scanner", "staff_attester"}
	diskEncryptionVals  = []string{"off", "on", "suspended", "unknown"}
	oSPatchVals         = []string{"current", "out_of_date", "unknown", "unsupported_os", "updates_pending"}
	eDRKindVals         = []string{"defender", "none", "third_party"}
	remoteToolKinds     = []string{"anydesk", "other_remote_tool", "rustdesk", "screenconnect", "splashtop", "teamviewer", "ultraviewer", "vnc"}
	mailboxAlertKinds   = []string{"forwarding_rule_external", "impossible_travel_approx", "new_admin_role", "new_auth_method", "signin_unusual_country_approx"}
	paymentRequestKinds = []string{"bank_detail_change", "payroll_change", "refund_redirect", "vendor_invoice_change", "wire_transfer"}
	staffEventKinds     = []string{"backup_restore_drill", "verify_before_pay"}
	drillResultVals     = []string{"failed", "partial", "success"}
	keyAlgVals          = []string{"ecdsa-p256-sha256", "ed25519"}
	keyProtectionVals   = []string{"secure_enclave", "software", "tpm2"}
	keyAttestationVals  = []string{"apple_mda", "none", "tpm2_quote"}
	enrollMethodVals    = []string{"enrollment_code", "owner_approval"}
	deviceClassVals     = []string{"desktop", "laptop", "not_a_device", "server"}
	platformVals        = []string{"macos", "microsoft_365", "mobile_app", "vendor_service", "windows"}
	// Stable IDs of the external checks the vendor's scanner runs against
	// a firm's own domain: the production scanner's catalog (SPEC 6.2),
	// plus the prototype TLS-xx and HTTP-xx IDs that only sample data uses.
	// New checks get new IDs; IDs are never reused.
	scanCheckIDs = []string{
		"BREACH-00", "BREACH-01", "BREACH-02", "BREACH-03", "BREACH-04", "CT-00", "CT-01", "DNS-01", "DNS-02",
		"EMAIL-01", "EMAIL-02", "EMAIL-03", "EMAIL-04", "EMAIL-05", "EMAIL-06", "EMAIL-07", "EMAIL-08", "EMAIL-09", "EMAIL-10",
		"HTTP-01", "HTTP-02", "HTTP-03", "TLS-01", "TLS-02", "TLS-03", "WEB-00", "WEB-01", "WEB-02", "WEB-03", "WEB-04",
	}
	scanStatusVals = []string{"error", "fail", "not_applicable", "pass", "warn"}
	severityVals   = []string{"critical", "high", "info", "low", "medium"}
	staffRoleVals  = []string{"bookkeeper", "none", "office_manager", "owner"}
)

// Caps for counted lists (small on purpose, so truncation is exercised).
const (
	RemoteToolsMaxItems   = 4
	MailboxAlertsMaxItems = 5
	PaymentKindsMaxItems  = 5
	ScanResultsMaxItems   = 32
)

func deviceSpec() *Spec {
	return object(map[string]*Spec{
		"disk_encryption":          enum(diskEncryptionVals...),
		"os_patch_status":          enum(oSPatchVals...),
		"firewall_on":              boolean(),
		"screen_lock_on":           boolean(),
		"screen_lock_max_idle_min": integer(0, 1440),
		"edr_running":              boolean(),
		"edr_kind":                 enum(eDRKindVals...),
		"local_admin_count":        integer(0, 64),
		"unapproved_remote_tools":  countedList(RemoteToolsMaxItems, 64, remoteToolKinds...),
		"heartbeat_interval_s":     integer(30, 3600),
		"heartbeats_24h":           integer(0, 2880),
	})
}

func tenantPostureSpec() *Spec {
	s := object(map[string]*Spec{
		"source":                      enum("microsoft_365"),
		"accounts_total":              integer(0, maxCount),
		"accounts_mfa":                integer(0, maxCount),
		"accounts_passkey":            integer(0, maxCount),
		"admin_accounts":              integer(0, maxCount),
		"devices_known":               integer(0, maxCount),
		"devices_enrolled":            integer(0, maxCount),
		"devices_unknown_seen":        integer(0, maxCount),
		"mailbox_alerts_24h":          countedList(MailboxAlertsMaxItems, maxCount, mailboxAlertKinds...),
		"mailbox_alerts_open":         integer(0, maxCount),
		"mailbox_alerts_resolved_24h": integer(0, maxCount),
	})
	s.LE = [][2]string{{"accounts_mfa", "accounts_total"}, {"accounts_passkey", "accounts_total"}, {"admin_accounts", "accounts_total"}}
	return s
}

func staffEventSpec() *Spec {
	vbp := object(map[string]*Spec{
		"requests":          integer(1, 1000),
		"callback_verified": integer(0, 1000),
		"second_approver":   integer(0, 1000),
		"blocked":           integer(0, 1000),
		"request_kinds":     countedList(PaymentKindsMaxItems, 1000, paymentRequestKinds...),
	})
	vbp.LE = [][2]string{{"callback_verified", "requests"}, {"second_approver", "requests"}, {"blocked", "requests"}}
	drill := object(map[string]*Spec{
		"performed_at":           timestamp(),
		"result":                 enum(drillResultVals...),
		"files_restored":         integer(0, 1000000),
		"minutes_to_restore":     integer(0, 10080),
		"second_person_verified": boolean(),
	})
	s := object(map[string]*Spec{"kind": enum(staffEventKinds...)})
	s.Switch = &Switch{On: "kind", Cases: map[string]map[string]*Spec{
		"verify_before_pay":    {"verify_before_pay": vbp},
		"backup_restore_drill": {"backup_restore_drill": drill},
	}}
	return s
}

// scanSpec is server-observed evidence: the vendor's scanner checking the
// firm's own domain from outside (email authentication, TLS, HTTP headers,
// breach exposure). The domain itself is never named: the tenant is.
func scanSpec() *Spec {
	return object(map[string]*Spec{
		"source": enum("external_scan"),
		"results": resultList(ScanResultsMaxItems, "check_id", object(map[string]*Spec{
			"check_id": enum(scanCheckIDs...),
			"status":   enum(scanStatusVals...),
			"severity": enum(severityVals...),
		})),
	})
}

// Endpoint (SPEC 6.5) vocabularies. Every enum sorts its values.
var (
	availabilityVals = []string{"not_applicable", "ok", "unknown"}
	toggleVals       = []string{"off", "on", "unknown"}
	runningModeVals  = []string{"edr_block", "normal", "passive", "sxs_passive", "unknown"}
	volumeVals       = []string{"not_applicable", "off", "on", "unknown"}
	blocklistVals    = []string{"default", "off", "on", "unknown"}
	// Known EDR and antivirus agents an endpoint agent may report. New
	// vendors get new values; values are never reused.
	edrVendorVals = []string{"bitdefender", "carbon_black", "cortex_xdr", "crowdstrike", "eset", "huntress",
		"malwarebytes", "microsoft_defender_endpoint", "sentinelone", "sophos", "symantec", "trend_micro", "webroot"}
	tripReasonVals = []string{"mass_extension_change", "none", "ransom_notes"}
	tripWindowVals = []string{"10s", "120s", "300s", "30s", "60s"}
	// Count buckets: 0, 1-9, 10-99, 100-999, 1000 or more.
	bucketVals = []string{"0", "1000_plus", "100_999", "10_99", "1_9"}
)

// Endpoint caps.
const (
	// EDRAgentsMaxItems caps protection.edr.agents (one record per vendor).
	EDRAgentsMaxItems = 8
	// MaxAVProducts caps the Security Center counts.
	MaxAVProducts = 32
	// MaxSignatureAgeDays caps Defender's signature age.
	MaxSignatureAgeDays = 65535
	// MaxVersionNumber caps the sensor_health version fields (2^53 - 1).
	MaxVersionNumber = 1<<53 - 1
	// unknownInt is the integer value for "unknown or not applicable".
	unknownInt = -1
	// MaxTripwireFolders caps tripwire.folders_watched.
	MaxTripwireFolders = 32
	// Heartbeat interval bounds for schedule.interval_s, in seconds.
	MinHeartbeatIntervalS = 60
	MaxHeartbeatIntervalS = 3600
)

// SensorHealthSpec is the sensor_health section (SPEC 6.4): the health of
// the endpoint agent itself.
func SensorHealthSpec() *Spec {
	return object(map[string]*Spec{
		"sensor_running":           boolean(),
		"tamper_detected":          boolean(),
		"driver_blocklist_version": integer(0, MaxVersionNumber),
		"policy_version":           integer(0, MaxVersionNumber),
	})
}

// byState is an object whose other fields depend on its "state": ok
// carries real values, and a check that did not run (unknown,
// not_applicable) claims none.
func byState(ok, notOK func() map[string]*Spec) *Spec {
	s := object(map[string]*Spec{"state": enum(availabilityVals...)})
	s.Switch = &Switch{On: "state", Cases: map[string]map[string]*Spec{
		"ok": ok(), "unknown": notOK(), "not_applicable": notOK(),
	}}
	return s
}

func protectionSpec() *Spec {
	sc := byState(func() map[string]*Spec {
		return map[string]*Spec{
			"products": integer(0, MaxAVProducts), "enabled": integer(0, MaxAVProducts), "up_to_date": integer(0, MaxAVProducts),
		}
	}, func() map[string]*Spec {
		return map[string]*Spec{
			"products": integer(unknownInt, unknownInt), "enabled": integer(unknownInt, unknownInt), "up_to_date": integer(unknownInt, unknownInt),
		}
	})
	sc.LE = [][2]string{{"enabled", "products"}, {"up_to_date", "products"}}
	toggles := []string{"am_service", "antivirus", "real_time_protection", "behavior_monitor", "tamper_protection"}
	defender := byState(func() map[string]*Spec {
		f := map[string]*Spec{
			"signature_age_days": integer(unknownInt, MaxSignatureAgeDays),
			"running_mode":       enum(runningModeVals...),
		}
		for _, k := range toggles {
			f[k] = enum(toggleVals...)
		}
		return f
	}, func() map[string]*Spec {
		f := map[string]*Spec{
			"signature_age_days": integer(unknownInt, unknownInt),
			"running_mode":       enum("unknown"),
		}
		for _, k := range toggles {
			f[k] = enum("unknown")
		}
		return f
	})
	edr := byState(func() map[string]*Spec {
		return map[string]*Spec{"agents": resultList(EDRAgentsMaxItems, "vendor", object(map[string]*Spec{
			"vendor":  enum(edrVendorVals...),
			"running": boolean(),
		}))}
	}, func() map[string]*Spec { return map[string]*Spec{} })
	return object(map[string]*Spec{
		"security_center":             sc,
		"defender":                    defender,
		"edr":                         edr,
		"bitlocker_os_volume":         enum(volumeVals...),
		"firewall_profiles_on":        integer(unknownInt, 3),
		"vulnerable_driver_blocklist": enum(blocklistVals...),
		"memory_integrity":            enum(toggleVals...),
	})
}

// tripwireSpec is the ransomware tripwire (SPEC 6.5): bucketed counts
// only. That reason is none exactly when triggered is false is checked in
// ValidateValue (the schema language cannot switch on a boolean).
func tripwireSpec() *Spec {
	return byState(func() map[string]*Spec {
		f := map[string]*Spec{
			"triggered":       boolean(),
			"reason":          enum(tripReasonVals...),
			"window":          enum(tripWindowVals...),
			"folders_watched": integer(0, MaxTripwireFolders),
		}
		for _, k := range []string{"renamed", "extension_changed", "modified", "deleted", "suspicious_created", "unknown_activity"} {
			f[k] = enum(bucketVals...)
		}
		return f
	}, func() map[string]*Spec { return map[string]*Spec{} })
}

// EndpointPredicateSpec is the schema of an endpoint/v1 predicate (SPEC
// 6.5): the posture common fields without tenant (it arrives with
// endpoint enrollment), the agent's version, its own health and the
// machine's protection checks.
func EndpointPredicateSpec() *Spec {
	return object(map[string]*Spec{
		"attester":      id(PrefixDevice),
		"attester_kind": enum("device_agent"),
		"seq":           integer(1, 1<<31-1),
		"prev":          hexN(64),
		"nonce":         hexN(32),
		"salt":          hexN(64),
		"observed_at":   timestamp(),
		"agent_version": object(map[string]*Spec{
			"major": integer(0, 65535), "minor": integer(0, 65535), "patch": integer(0, 65535),
		}),
		"sensor_health": SensorHealthSpec(),
		"schedule": object(map[string]*Spec{
			"interval_s":           integer(MinHeartbeatIntervalS, MaxHeartbeatIntervalS),
			"deferred_s":           integer(0, MaxHeartbeatIntervalS),
			"heavy_checks_skipped": boolean(),
		}),
		"protection": protectionSpec(),
		"tripwire":   tripwireSpec(),
	})
}

// PosturePredicateSpec is the schema of a posture/v1 predicate.
func PosturePredicateSpec() *Spec {
	s := object(map[string]*Spec{
		"tenant":        id(PrefixTenant),
		"attester":      id(PrefixDevice, PrefixConnector, PrefixStaff, PrefixScanner),
		"attester_kind": enum(attesterKinds...),
		"seq":           integer(1, 1<<31-1),
		"prev":          hexN(64),
		"nonce":         hexN(32),
		"salt":          hexN(64),
		"observed_at":   timestamp(),
	})
	s.Switch = &Switch{On: "attester_kind", Cases: map[string]map[string]*Spec{
		"device_agent":     {"device": deviceSpec()},
		"cloud_connector":  {"tenant_posture": tenantPostureSpec()},
		"staff_attester":   {"staff_event": staffEventSpec()},
		"external_scanner": {"scan": scanSpec()},
	}}
	return s
}

// EnrollmentPredicateSpec is the schema of an enrollment/v1 predicate.
func EnrollmentPredicateSpec() *Spec {
	s := object(map[string]*Spec{
		"kind":        enum("attester", "tenant_genesis"),
		"tenant":      id(PrefixTenant),
		"enrolled_at": timestamp(),
		"nonce":       hexN(32),
		"salt":        hexN(64),
	})
	s.Switch = &Switch{On: "kind", Cases: map[string]map[string]*Spec{
		"tenant_genesis": {
			"tenant_key":              {T: "spki"},
			"tenant_key_alg":          enum(keyAlgVals...),
			"display_name_commitment": hexN(64),
		},
		"attester": {
			"attester":          id(PrefixDevice, PrefixConnector, PrefixStaff, PrefixScanner),
			"attester_kind":     enum(attesterKinds...),
			"attester_key":      {T: "spki"},
			"attester_key_alg":  enum(keyAlgVals...),
			"key_protection":    enum(keyProtectionVals...),
			"key_attestation":   enum(keyAttestationVals...),
			"enrollment_method": enum(enrollMethodVals...),
			"device_class":      enum(deviceClassVals...),
			"platform":          enum(platformVals...),
			"device_number":     integer(0, 9999),
			"staff_role":        enum(staffRoleVals...),
		},
	}}
	return s
}

// StatementSpec wraps a predicate spec in the in-toto Statement v1 shape
// with exactly one subject: the attester (or tenant) the key belongs to.
func StatementSpec(predicateType string, predicate *Spec) *Spec {
	subject := object(map[string]*Spec{
		"name":   id(PrefixTenant, PrefixDevice, PrefixConnector, PrefixStaff, PrefixScanner),
		"digest": object(map[string]*Spec{"sha256": hexN(64)}),
	})
	return object(map[string]*Spec{
		"_type":         constant(InTotoStatementType),
		"subject":       {T: "array", Of: subject, MinItems: 1, MaxItems: 1},
		"predicateType": constant(predicateType),
		"predicate":     predicate,
	})
}

// Schemas returns the statement schema for each accepted predicate type.
func Schemas() map[string]*Spec {
	return map[string]*Spec{
		brand.PredicatePosture:    StatementSpec(brand.PredicatePosture, PosturePredicateSpec()),
		brand.PredicateEnrollment: StatementSpec(brand.PredicateEnrollment, EnrollmentPredicateSpec()),
		brand.PredicateEndpoint:   StatementSpec(brand.PredicateEndpoint, EndpointPredicateSpec()),
	}
}

// SchemaJSON exports the schemas plus the constants a verifier needs, for
// verifiers in other languages. The output is canonical-sorted JSON.
func SchemaJSON() ([]byte, error) {
	doc := map[string]any{
		"schema_version":         "posture-schema/v1",
		"canonicalization":       canon.Version,
		"in_toto_statement_type": InTotoStatementType,
		"predicate_types": map[string]string{
			"posture":    brand.PredicatePosture,
			"enrollment": brand.PredicateEnrollment,
			"endpoint":   brand.PredicateEndpoint,
		},
		"statements": Schemas(),
	}
	return json.MarshalIndent(doc, "", " ")
}
