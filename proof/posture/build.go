package posture

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/brand"
	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

const (
	brandPosture    = brand.PredicatePosture
	brandEnrollment = brand.PredicateEnrollment
)

// Typed enumerations. Values are checked against the schema at build time,
// so a converted arbitrary string is still rejected.
type (
	AttesterKind   string
	DiskEncryption string
	OSPatchStatus  string
	EDRKind        string
	RemoteTool     string
	MailboxAlert   string
	PaymentRequest string
	DrillResult    string
	ScanCheck      string
	ScanStatus     string
	Severity       string
	KeyProtection  string
	KeyAttestation string
	EnrollMethod   string
	DeviceClass    string
	Platform       string
	StaffRole      string
)

const (
	DeviceAgent    AttesterKind = "device_agent"
	CloudConnector AttesterKind = "cloud_connector"
	StaffAttester  AttesterKind = "staff_attester"
	// ExternalScanner is the vendor's own service checking a firm's domain
	// from outside. Its evidence strength is "scan-verified".
	ExternalScanner AttesterKind = "external_scanner"

	EncryptionOn        DiskEncryption = "on"
	EncryptionOff       DiskEncryption = "off"
	EncryptionSuspended DiskEncryption = "suspended"
	EncryptionUnknown   DiskEncryption = "unknown"

	PatchCurrent     OSPatchStatus = "current"
	PatchPending     OSPatchStatus = "updates_pending"
	PatchOutOfDate   OSPatchStatus = "out_of_date"
	PatchUnsupported OSPatchStatus = "unsupported_os"
	PatchUnknown     OSPatchStatus = "unknown"

	EDRDefender   EDRKind = "defender"
	EDRThirdParty EDRKind = "third_party"
	EDRNone       EDRKind = "none"

	DrillSuccess DrillResult = "success"
	DrillPartial DrillResult = "partial"
	DrillFailed  DrillResult = "failed"
)

// Digest is a SHA-256 digest; Nonce is a 128-bit server challenge; Salt is
// 256 random bits that make the statement's log commitment unguessable.
type (
	Digest [32]byte
	Nonce  [16]byte
	Salt   [32]byte
)

// NewSalt returns a fresh random salt. Every statement needs its own: the
// public log holds only SHA-256(envelope), and without a salt the few
// booleans and counts in a statement could be found by brute force.
func NewSalt() (Salt, error) {
	var s Salt
	_, err := rand.Read(s[:])
	return s, err
}

// PayloadDigest is the chain hash of a statement: SHA-256 of its exact
// payload bytes. Each statement's "prev" is the PayloadDigest of the
// attester's previous statement (or of its enrollment record for seq 1).
func PayloadDigest(payload []byte) Digest { return sha256.Sum256(payload) }

// TenantID derives the tenant identifier from the tenant key.
func TenantID(tenantKey *sigs.PublicKey) string { return PrefixTenant + tenantKey.KeyID()[:16] }

// AttesterID derives an attester identifier from its key and kind.
func AttesterID(kind AttesterKind, key *sigs.PublicKey) string {
	return prefixForKind(string(kind)) + key.KeyID()[:16]
}

// Count is one enum+count pair for a counted list.
type Count[K ~string] struct {
	Kind K
	N    uint32
}

// Header carries the fields every posture statement has. The attester ID
// and subject are derived from the key, so they cannot be mistyped.
type Header struct {
	TenantKey  *sigs.PublicKey
	Attester   *sigs.PublicKey
	Kind       AttesterKind
	Seq        uint32
	Prev       Digest
	Nonce      Nonce
	Salt       Salt
	ObservedAt time.Time
}

// DeviceChecks is what a device agent reports.
type DeviceChecks struct {
	DiskEncryption        DiskEncryption
	OSPatch               OSPatchStatus
	FirewallOn            bool
	ScreenLockOn          bool
	ScreenLockMaxIdleMin  uint16
	EDRRunning            bool
	EDRKind               EDRKind
	LocalAdminCount       uint16
	UnapprovedRemoteTools []Count[RemoteTool]
	HeartbeatIntervalS    uint16
	Heartbeats24h         uint16
}

// TenantPosture is what the cloud connector reads from Microsoft 365.
type TenantPosture struct {
	AccountsTotal            uint32
	AccountsMFA              uint32
	AccountsPasskey          uint32
	AdminAccounts            uint32
	DevicesKnown             uint32
	DevicesEnrolled          uint32
	DevicesUnknownSeen       uint32
	MailboxAlerts24h         []Count[MailboxAlert]
	MailboxAlertsOpen        uint32
	MailboxAlertsResolved24h uint32
}

// VerifyBeforePay records payment-change requests and how they were checked.
type VerifyBeforePay struct {
	Requests         uint32
	CallbackVerified uint32
	SecondApprover   uint32
	Blocked          uint32
	RequestKinds     []Count[PaymentRequest]
}

// RestoreDrill records a backup restore test.
type RestoreDrill struct {
	PerformedAt          time.Time
	Result               DrillResult
	FilesRestored        uint32
	MinutesToRestore     uint32
	SecondPersonVerified bool
}

// StaffEvent is exactly one of its fields.
type StaffEvent struct {
	VerifyBeforePay *VerifyBeforePay
	RestoreDrill    *RestoreDrill
}

// BuildDevice returns the canonical payload of a device posture statement.
func BuildDevice(h Header, c DeviceChecks) ([]byte, error) {
	if h.Kind != DeviceAgent {
		return nil, errors.New("device statements need attester kind device_agent")
	}
	return buildPosture(h, "device", map[string]any{
		"disk_encryption":          string(c.DiskEncryption),
		"os_patch_status":          string(c.OSPatch),
		"firewall_on":              c.FirewallOn,
		"screen_lock_on":           c.ScreenLockOn,
		"screen_lock_max_idle_min": int64(c.ScreenLockMaxIdleMin),
		"edr_running":              c.EDRRunning,
		"edr_kind":                 string(c.EDRKind),
		"local_admin_count":        int64(c.LocalAdminCount),
		"unapproved_remote_tools":  countedListValue(c.UnapprovedRemoteTools, RemoteToolsMaxItems),
		"heartbeat_interval_s":     int64(c.HeartbeatIntervalS),
		"heartbeats_24h":           int64(c.Heartbeats24h),
	})
}

// BuildTenantPosture returns the canonical payload of a connector statement.
func BuildTenantPosture(h Header, t TenantPosture) ([]byte, error) {
	if h.Kind != CloudConnector {
		return nil, errors.New("tenant posture statements need attester kind cloud_connector")
	}
	return buildPosture(h, "tenant_posture", map[string]any{
		"source":                      "microsoft_365",
		"accounts_total":              int64(t.AccountsTotal),
		"accounts_mfa":                int64(t.AccountsMFA),
		"accounts_passkey":            int64(t.AccountsPasskey),
		"admin_accounts":              int64(t.AdminAccounts),
		"devices_known":               int64(t.DevicesKnown),
		"devices_enrolled":            int64(t.DevicesEnrolled),
		"devices_unknown_seen":        int64(t.DevicesUnknownSeen),
		"mailbox_alerts_24h":          countedListValue(t.MailboxAlerts24h, MailboxAlertsMaxItems),
		"mailbox_alerts_open":         int64(t.MailboxAlertsOpen),
		"mailbox_alerts_resolved_24h": int64(t.MailboxAlertsResolved24h),
	})
}

// ScanResult is one external check.
type ScanResult struct {
	CheckID  ScanCheck
	Status   ScanStatus
	Severity Severity
}

// ScanResults is one run of the external scanner.
type ScanResults struct {
	Results []ScanResult
}

var severityRank = map[Severity]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// BuildScan returns the canonical payload of an external scan statement.
// Results are sorted by check ID; if there are more than fit, the most
// severe are kept and the list is marked truncated.
func BuildScan(h Header, r ScanResults) ([]byte, error) {
	if h.Kind != ExternalScanner {
		return nil, errors.New("scan statements need attester kind external_scanner")
	}
	res := append([]ScanResult(nil), r.Results...)
	seen := map[ScanCheck]bool{}
	for _, x := range res {
		if seen[x.CheckID] {
			return nil, fmt.Errorf("check %s reported twice", x.CheckID)
		}
		seen[x.CheckID] = true
	}
	total := len(res)
	truncated := total > ScanResultsMaxItems
	if truncated {
		sort.SliceStable(res, func(i, j int) bool { return severityRank[res[i].Severity] < severityRank[res[j].Severity] })
		res = res[:ScanResultsMaxItems]
	}
	sort.Slice(res, func(i, j int) bool { return res[i].CheckID < res[j].CheckID })
	items := make([]any, len(res))
	for i, x := range res {
		items[i] = map[string]any{"check_id": string(x.CheckID), "status": string(x.Status), "severity": string(x.Severity)}
	}
	return buildPosture(h, "scan", map[string]any{
		"source":  "external_scan",
		"results": map[string]any{"items": items, "total": int64(total), "truncated": truncated},
	})
}

// BuildStaffEvent returns the canonical payload of a staff attestation.
func BuildStaffEvent(h Header, e StaffEvent) ([]byte, error) {
	if h.Kind != StaffAttester {
		return nil, errors.New("staff events need attester kind staff_attester")
	}
	ev := map[string]any{}
	switch {
	case e.VerifyBeforePay != nil && e.RestoreDrill == nil:
		v := e.VerifyBeforePay
		ev["kind"] = "verify_before_pay"
		ev["verify_before_pay"] = map[string]any{
			"requests":          int64(v.Requests),
			"callback_verified": int64(v.CallbackVerified),
			"second_approver":   int64(v.SecondApprover),
			"blocked":           int64(v.Blocked),
			"request_kinds":     countedListValue(v.RequestKinds, PaymentKindsMaxItems),
		}
	case e.RestoreDrill != nil && e.VerifyBeforePay == nil:
		d := e.RestoreDrill
		ev["kind"] = "backup_restore_drill"
		ev["backup_restore_drill"] = map[string]any{
			"performed_at":           d.PerformedAt.UTC().Format(tsa.TimeLayout),
			"result":                 string(d.Result),
			"files_restored":         int64(d.FilesRestored),
			"minutes_to_restore":     int64(d.MinutesToRestore),
			"second_person_verified": d.SecondPersonVerified,
		}
	default:
		return nil, errors.New("a staff event must set exactly one event")
	}
	return buildPosture(h, "staff_event", ev)
}

func buildPosture(h Header, section string, body map[string]any) ([]byte, error) {
	if h.TenantKey == nil || h.Attester == nil {
		return nil, errors.New("header needs tenant and attester keys")
	}
	if h.ObservedAt.IsZero() {
		return nil, errors.New("header needs ObservedAt")
	}
	if h.Salt == (Salt{}) {
		return nil, errors.New("header needs a random Salt (see NewSalt)")
	}
	attester := AttesterID(h.Kind, h.Attester)
	pred := map[string]any{
		"tenant":        TenantID(h.TenantKey),
		"attester":      attester,
		"attester_kind": string(h.Kind),
		"seq":           int64(h.Seq),
		"prev":          hex.EncodeToString(h.Prev[:]),
		"nonce":         hex.EncodeToString(h.Nonce[:]),
		"salt":          hex.EncodeToString(h.Salt[:]),
		"observed_at":   h.ObservedAt.UTC().Format(tsa.TimeLayout),
		section:         body,
	}
	return finish(brandPosture, attester, h.Attester.KeyID(), pred)
}

// EnrollmentInfo describes an attester at enrollment time.
type EnrollmentInfo struct {
	Kind           AttesterKind
	KeyProtection  KeyProtection
	KeyAttestation KeyAttestation
	Method         EnrollMethod
	DeviceClass    DeviceClass
	Platform       Platform
	DeviceNumber   uint16
	StaffRole      StaffRole
}

// BuildTenantGenesis returns the payload that creates a tenant. The display
// name is not logged; only a salted commitment to it is (see package pack).
func BuildTenantGenesis(tenantKey *sigs.PublicKey, nameCommitment Digest, at time.Time, nonce Nonce, salt Salt) ([]byte, error) {
	if salt == (Salt{}) {
		return nil, errors.New("enrollment needs a random Salt")
	}
	tenant := TenantID(tenantKey)
	pred := map[string]any{
		"kind":                    "tenant_genesis",
		"tenant":                  tenant,
		"enrolled_at":             at.UTC().Format(tsa.TimeLayout),
		"nonce":                   hex.EncodeToString(nonce[:]),
		"salt":                    hex.EncodeToString(salt[:]),
		"tenant_key":              tenantKey.Base64(),
		"tenant_key_alg":          string(tenantKey.Alg),
		"display_name_commitment": hex.EncodeToString(nameCommitment[:]),
	}
	return finish(brandEnrollment, tenant, tenantKey.KeyID(), pred)
}

// BuildAttesterEnrollment returns the payload that binds an attester key to
// a tenant. It must be signed by the tenant key and then by the attester
// key (proof of possession).
func BuildAttesterEnrollment(tenantKey, attesterKey *sigs.PublicKey, info EnrollmentInfo, at time.Time, nonce Nonce, salt Salt) ([]byte, error) {
	if salt == (Salt{}) {
		return nil, errors.New("enrollment needs a random Salt")
	}
	attester := AttesterID(info.Kind, attesterKey)
	pred := map[string]any{
		"kind":              "attester",
		"tenant":            TenantID(tenantKey),
		"enrolled_at":       at.UTC().Format(tsa.TimeLayout),
		"nonce":             hex.EncodeToString(nonce[:]),
		"salt":              hex.EncodeToString(salt[:]),
		"attester":          attester,
		"attester_kind":     string(info.Kind),
		"attester_key":      attesterKey.Base64(),
		"attester_key_alg":  string(attesterKey.Alg),
		"key_protection":    string(info.KeyProtection),
		"key_attestation":   string(info.KeyAttestation),
		"enrollment_method": string(info.Method),
		"device_class":      string(info.DeviceClass),
		"platform":          string(info.Platform),
		"device_number":     int64(info.DeviceNumber),
		"staff_role":        string(info.StaffRole),
	}
	return finish(brandEnrollment, attester, attesterKey.KeyID(), pred)
}

// finish wraps a predicate in an in-toto statement, validates the result
// against the same schema every verifier uses, and encodes it canonically.
func finish(predicateType, subject, subjectDigest string, pred map[string]any) ([]byte, error) {
	st := map[string]any{
		"_type":         InTotoStatementType,
		"predicateType": predicateType,
		"subject": []any{map[string]any{
			"name":   subject,
			"digest": map[string]any{"sha256": subjectDigest},
		}},
		"predicate": pred,
	}
	if _, err := ValidateValue(st); err != nil {
		return nil, fmt.Errorf("builder refused statement: %w", err)
	}
	return canon.Encode(st)
}

// countedListValue sorts, caps and encodes enum+count pairs. Zero counts
// are dropped; repeated kinds are summed. When more kinds remain than fit,
// the most frequent are kept and truncated is set.
func countedListValue[K ~string](in []Count[K], maxItems int) map[string]any {
	sums := map[string]int64{}
	var total int64
	for _, c := range in {
		if c.N == 0 {
			continue
		}
		sums[string(c.Kind)] += int64(c.N)
		total += int64(c.N)
	}
	kinds := make([]string, 0, len(sums))
	for k := range sums {
		kinds = append(kinds, k)
	}
	truncated := len(kinds) > maxItems
	if truncated {
		sort.Slice(kinds, func(i, j int) bool {
			if sums[kinds[i]] != sums[kinds[j]] {
				return sums[kinds[i]] > sums[kinds[j]]
			}
			return kinds[i] < kinds[j]
		})
		kinds = kinds[:maxItems]
	}
	sort.Strings(kinds)
	items := make([]any, 0, len(kinds))
	for _, k := range kinds {
		items = append(items, map[string]any{"count": sums[k], "kind": k})
	}
	return map[string]any{"items": items, "total": total, "truncated": truncated}
}

// Sign wraps a payload in a DSSE envelope signed by the given signers.
func Sign(payload []byte, signers ...sigs.Signer) (*dsse.Envelope, error) {
	return dsse.Sign(dsse.PayloadTypeInToto, payload, signers...)
}
