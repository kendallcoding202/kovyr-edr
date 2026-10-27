package pack_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/pack"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
)

// SPEC 6.5: endpoint statements carry no tenant until endpoint enrollment
// ships, so nothing binds them to a firm. A pack holding one must fail,
// even when the enrolled device's own key signed it; it must never slip
// past the per-attester checks unexamined.
func TestEndpointStatementInAPackIsRefused(t *testing.T) {
	w, p := genuine(t)
	i := find(t, p, 3, "2026-10-10")
	dev, err := w.Keys.Firms[0].Devices[2].Signer() // laptop D03
	if err != nil {
		t.Fatal(err)
	}
	old, err := posture.Validate(p.Entries[i].Evidence.Envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	id := posture.AttesterID(posture.DeviceAgent, dev.Public())
	if old.Str("attester") != id {
		t.Fatalf("the test picked the wrong device: %s vs %s", old.Str("attester"), id)
	}
	st := map[string]any{
		"_type":         posture.InTotoStatementType,
		"predicateType": posture.EndpointPredicateType(),
		"subject":       []any{map[string]any{"name": id, "digest": map[string]any{"sha256": dev.Public().KeyID()}}},
		"predicate": map[string]any{
			"attester": id, "attester_kind": "device_agent", "seq": old.Int("seq"),
			"prev": old.Str("prev"), "nonce": old.Str("nonce"), "salt": hex.EncodeToString(make([]byte, 32)),
			"observed_at":   old.Str("observed_at"),
			"agent_version": map[string]any{"major": int64(0), "minor": int64(1), "patch": int64(0)},
			"sensor_health": map[string]any{"sensor_running": true, "tamper_detected": false,
				"driver_blocklist_version": int64(0), "policy_version": int64(0)},
			"protection": map[string]any{
				"security_center":     map[string]any{"state": "not_applicable", "products": int64(-1), "enabled": int64(-1), "up_to_date": int64(-1)},
				"defender":            map[string]any{"state": "unknown", "am_service": "unknown", "antivirus": "unknown", "real_time_protection": "unknown", "behavior_monitor": "unknown", "tamper_protection": "unknown", "signature_age_days": int64(-1), "running_mode": "unknown"},
				"edr":                 map[string]any{"state": "unknown"},
				"bitlocker_os_volume": "on", "firewall_profiles_on": int64(3),
				"vulnerable_driver_blocklist": "default", "memory_integrity": "on",
			},
		},
	}
	payload := canon.MustEncode(st)
	if _, err := posture.Validate(payload); err != nil {
		t.Fatalf("test statement is not a valid endpoint statement: %v", err)
	}
	env, err := posture.Sign(payload, dev)
	if err != nil {
		t.Fatal(err)
	}
	p.Entries[i].Evidence.Envelope = env
	r := pack.Verify(p, w.Trust)
	if r.Verified || r.Step("enrollment").Status != pack.Fail {
		t.Fatalf("a pack with an endpoint statement verified:\n%s", r.Text())
	}
	if !strings.Contains(strings.Join(r.Step("enrollment").Problems, " "), "heartbeat #") ||
		!strings.Contains(strings.Join(r.Step("enrollment").Problems, " "), "carry no tenant") {
		t.Fatalf("unexpected enrollment problems: %v", r.Step("enrollment").Problems)
	}
	if r.Step("content").Status != pack.Pass || r.Step("signatures").Status != pack.Pass {
		t.Fatalf("the endpoint statement itself should be valid and validly signed:\n%s", r.Text())
	}
}
