package posture

import (
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

// Decoders turn collector output (JSON, already parsed strictly) into the
// typed values the builder accepts. Each one validates the input against
// the same schema section first, so anything that is not an allowed field
// with an allowed value is rejected before a typed value exists.

// DecodeDeviceChecks validates and converts a "device" section.
func DecodeDeviceChecks(v map[string]any) (DeviceChecks, error) {
	if err := Check(v, deviceSpec(), "device"); err != nil {
		return DeviceChecks{}, err
	}
	if err := noTruncation("device.unapproved_remote_tools", v["unapproved_remote_tools"]); err != nil {
		return DeviceChecks{}, err
	}
	return DeviceChecks{
		DiskEncryption:        DiskEncryption(v["disk_encryption"].(string)),
		OSPatch:               OSPatchStatus(v["os_patch_status"].(string)),
		FirewallOn:            v["firewall_on"].(bool),
		ScreenLockOn:          v["screen_lock_on"].(bool),
		ScreenLockMaxIdleMin:  uint16(v["screen_lock_max_idle_min"].(int64)),
		EDRRunning:            v["edr_running"].(bool),
		EDRKind:               EDRKind(v["edr_kind"].(string)),
		LocalAdminCount:       uint16(v["local_admin_count"].(int64)),
		UnapprovedRemoteTools: decodeCounts[RemoteTool](v["unapproved_remote_tools"]),
		HeartbeatIntervalS:    uint16(v["heartbeat_interval_s"].(int64)),
		Heartbeats24h:         uint16(v["heartbeats_24h"].(int64)),
	}, nil
}

// DecodeTenantPosture validates and converts a "tenant_posture" section.
func DecodeTenantPosture(v map[string]any) (TenantPosture, error) {
	if err := Check(v, tenantPostureSpec(), "tenant_posture"); err != nil {
		return TenantPosture{}, err
	}
	if err := noTruncation("tenant_posture.mailbox_alerts_24h", v["mailbox_alerts_24h"]); err != nil {
		return TenantPosture{}, err
	}
	u := func(k string) uint32 { return uint32(v[k].(int64)) }
	return TenantPosture{
		AccountsTotal: u("accounts_total"), AccountsMFA: u("accounts_mfa"),
		AccountsPasskey: u("accounts_passkey"), AdminAccounts: u("admin_accounts"),
		DevicesKnown: u("devices_known"), DevicesEnrolled: u("devices_enrolled"),
		DevicesUnknownSeen:       u("devices_unknown_seen"),
		MailboxAlerts24h:         decodeCounts[MailboxAlert](v["mailbox_alerts_24h"]),
		MailboxAlertsOpen:        u("mailbox_alerts_open"),
		MailboxAlertsResolved24h: u("mailbox_alerts_resolved_24h"),
	}, nil
}

// DecodeStaffEvent validates and converts a "staff_event" section.
func DecodeStaffEvent(v map[string]any) (StaffEvent, error) {
	if err := Check(v, staffEventSpec(), "staff_event"); err != nil {
		return StaffEvent{}, err
	}
	switch v["kind"] {
	case "verify_before_pay":
		o := v["verify_before_pay"].(map[string]any)
		if err := noTruncation("staff_event.verify_before_pay.request_kinds", o["request_kinds"]); err != nil {
			return StaffEvent{}, err
		}
		u := func(k string) uint32 { return uint32(o[k].(int64)) }
		return StaffEvent{VerifyBeforePay: &VerifyBeforePay{
			Requests: u("requests"), CallbackVerified: u("callback_verified"),
			SecondApprover: u("second_approver"), Blocked: u("blocked"),
			RequestKinds: decodeCounts[PaymentRequest](o["request_kinds"]),
		}}, nil
	default:
		o := v["backup_restore_drill"].(map[string]any)
		at, _ := tsa.ParseTime(o["performed_at"].(string))
		return StaffEvent{RestoreDrill: &RestoreDrill{
			PerformedAt: at.In(time.UTC), Result: DrillResult(o["result"].(string)),
			FilesRestored:        uint32(o["files_restored"].(int64)),
			MinutesToRestore:     uint32(o["minutes_to_restore"].(int64)),
			SecondPersonVerified: o["second_person_verified"].(bool),
		}}, nil
	}
}

// decodeCounts reads a validated counted list. Callers have already
// rejected truncated lists (see noTruncation): a collector must pass every
// count and let the builder apply the cap.
func decodeCounts[K ~string](v any) []Count[K] {
	var out []Count[K]
	for _, it := range v.(map[string]any)["items"].([]any) {
		io := it.(map[string]any)
		out = append(out, Count[K]{Kind: K(io["kind"].(string)), N: uint32(io["count"].(int64))})
	}
	return out
}

func noTruncation(path string, v any) error {
	if v.(map[string]any)["truncated"] == true {
		return fail(path, "collector input must not be truncated; pass every count and the builder applies the cap")
	}
	return nil
}
