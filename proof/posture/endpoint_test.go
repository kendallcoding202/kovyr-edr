package posture

import (
	"strings"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

// endpointStatement is a healthy endpoint/v1 statement (SPEC 6.5) for the
// given device key, as a decoded value.
func endpointStatement(dev sigs.Signer) map[string]any {
	id := AttesterID(DeviceAgent, dev.Public())
	return map[string]any{
		"_type":         InTotoStatementType,
		"predicateType": EndpointPredicateType(),
		"subject":       []any{map[string]any{"name": id, "digest": map[string]any{"sha256": dev.Public().KeyID()}}},
		"predicate": map[string]any{
			"attester": id, "attester_kind": "device_agent", "seq": int64(4),
			"prev": strings.Repeat("ab", 32), "nonce": strings.Repeat("cd", 16), "salt": strings.Repeat("ef", 32),
			"observed_at":   "2026-10-26T19:00:00Z",
			"agent_version": map[string]any{"major": int64(0), "minor": int64(1), "patch": int64(0)},
			"sensor_health": map[string]any{"sensor_running": true, "tamper_detected": false,
				"driver_blocklist_version": int64(0), "policy_version": int64(0)},
			"schedule": map[string]any{"interval_s": int64(900), "deferred_s": int64(0), "heavy_checks_skipped": false},
			"protection": map[string]any{
				"security_center": map[string]any{"state": "ok", "products": int64(1), "enabled": int64(1), "up_to_date": int64(1)},
				"defender": map[string]any{"state": "ok", "am_service": "on", "antivirus": "on", "real_time_protection": "on",
					"behavior_monitor": "on", "tamper_protection": "on", "signature_age_days": int64(0), "running_mode": "normal"},
				"edr": map[string]any{"state": "ok", "agents": map[string]any{
					"items": []any{
						map[string]any{"vendor": "huntress", "running": true},
						map[string]any{"vendor": "microsoft_defender_endpoint", "running": true},
					},
					"total": int64(2), "truncated": false,
				}},
				"bitlocker_os_volume": "on", "firewall_profiles_on": int64(3),
				"vulnerable_driver_blocklist": "default", "memory_integrity": "on",
			},
		},
	}
}

func epPred(o map[string]any) map[string]any { return o["predicate"].(map[string]any) }
func epProt(o map[string]any) map[string]any { return epPred(o)["protection"].(map[string]any) }
func epObj(o map[string]any, k string) map[string]any {
	return epProt(o)[k].(map[string]any)
}

func validateEndpoint(t *testing.T, o map[string]any) error {
	t.Helper()
	b, err := canon.Encode(o)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Validate(b)
	return err
}

func TestEndpointStatementValidates(t *testing.T) {
	_, dev := testKeys(t)
	o := endpointStatement(dev)
	b, _ := canon.Encode(o)
	st, err := Validate(b)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IsEndpoint() || st.IsPosture() || st.Int("seq") != 4 || st.Str("protection.defender.state") != "ok" {
		t.Fatalf("unexpected statement %+v", st.Predicate)
	}
	walkStrings(o, func(s string) {
		if !allowedString.MatchString(s) {
			t.Errorf("string %q has no fixed format", s)
		}
	})
}

// A check that did not run claims no values; the schema's switch on
// state allows exactly these shapes.
func TestEndpointChecksThatDidNotRun(t *testing.T) {
	_, dev := testKeys(t)
	for _, state := range []string{"unknown", "not_applicable"} {
		o := endpointStatement(dev)
		epProt(o)["security_center"] = map[string]any{"state": state, "products": int64(-1), "enabled": int64(-1), "up_to_date": int64(-1)}
		epProt(o)["defender"] = map[string]any{"state": state, "am_service": "unknown", "antivirus": "unknown",
			"real_time_protection": "unknown", "behavior_monitor": "unknown", "tamper_protection": "unknown",
			"signature_age_days": int64(-1), "running_mode": "unknown"}
		epProt(o)["edr"] = map[string]any{"state": state}
		if err := validateEndpoint(t, o); err != nil {
			t.Errorf("%s checks refused: %v", state, err)
		}
	}
	// ok with Defender's signature age unknown (one NULL property) is fine.
	o := endpointStatement(dev)
	epObj(o, "defender")["signature_age_days"] = int64(-1)
	if err := validateEndpoint(t, o); err != nil {
		t.Errorf("unknown signature age refused: %v", err)
	}
	// ok with no EDR agents found.
	o = endpointStatement(dev)
	epObj(o, "edr")["agents"] = map[string]any{"items": []any{}, "total": int64(0), "truncated": false}
	if err := validateEndpoint(t, o); err != nil {
		t.Errorf("empty agent list refused: %v", err)
	}
}

func agentItems(vendors ...string) []any {
	var out []any
	for _, v := range vendors {
		out = append(out, map[string]any{"vendor": v, "running": true})
	}
	return out
}

func TestEndpointRefusesBadContent(t *testing.T) {
	_, dev := testKeys(t)
	_, other := testKeys(t)
	nine := []string{"bitdefender", "carbon_black", "cortex_xdr", "crowdstrike", "eset", "huntress", "malwarebytes", "sentinelone", "sophos"}
	cases := map[string]func(o map[string]any){
		"hostname": func(o map[string]any) { epPred(o)["hostname"] = "MARIA-LAPTOP" },
		"tenant before enrollment": func(o map[string]any) {
			epPred(o)["tenant"] = "tnt_" + strings.Repeat("0", 16)
		},
		"path as enum":    func(o map[string]any) { epProt(o)["memory_integrity"] = "C:/Users/maria/taxes.pdf" },
		"version as text": func(o map[string]any) { epPred(o)["agent_version"] = "0.1.0" },
		"version out of range": func(o map[string]any) {
			epPred(o)["agent_version"].(map[string]any)["minor"] = int64(70000)
		},
		"other attester kind": func(o map[string]any) { epPred(o)["attester_kind"] = "cloud_connector" },
		"connector id":        func(o map[string]any) { epPred(o)["attester"] = "con_" + dev.Public().KeyID()[:16] },
		"attester not the key": func(o map[string]any) {
			id := AttesterID(DeviceAgent, other.Public())
			epPred(o)["attester"] = id
			o["subject"].([]any)[0].(map[string]any)["name"] = id
		},
		"subject mismatch": func(o map[string]any) {
			o["subject"].([]any)[0].(map[string]any)["name"] = AttesterID(DeviceAgent, other.Public())
		},
		"sensor field missing": func(o map[string]any) { delete(epPred(o)["sensor_health"].(map[string]any), "policy_version") },
		"count when unknown": func(o map[string]any) {
			epObj(o, "security_center")["state"] = "unknown"
		},
		"unknown count when ok": func(o map[string]any) { epObj(o, "security_center")["products"] = int64(-1) },
		"enabled > products":    func(o map[string]any) { epObj(o, "security_center")["enabled"] = int64(2) },
		"toggle when unknown": func(o map[string]any) {
			d := epObj(o, "defender")
			for k, v := range map[string]any{"state": "unknown", "signature_age_days": int64(-1), "running_mode": "unknown",
				"am_service": "unknown", "antivirus": "unknown", "behavior_monitor": "unknown", "tamper_protection": "unknown"} {
				d[k] = v
			}
			d["real_time_protection"] = "on"
		},
		"age when n/a": func(o map[string]any) {
			d := epObj(o, "defender")
			for _, k := range []string{"am_service", "antivirus", "behavior_monitor", "tamper_protection", "real_time_protection", "running_mode"} {
				d[k] = "unknown"
			}
			d["state"] = "not_applicable"
		},
		"agents when unknown": func(o map[string]any) { epObj(o, "edr")["state"] = "unknown" },
		"no agents when ok":   func(o map[string]any) { delete(epObj(o, "edr"), "agents") },
		"agents as array": func(o map[string]any) {
			epObj(o, "edr")["agents"] = agentItems("huntress")
		},
		"unknown vendor": func(o map[string]any) {
			epObj(o, "edr")["agents"] = map[string]any{"items": agentItems("acme_edr"), "total": int64(1), "truncated": false}
		},
		"service name": func(o map[string]any) {
			it := map[string]any{"vendor": "huntress", "running": true, "service": "HuntressAgent"}
			epObj(o, "edr")["agents"] = map[string]any{"items": []any{it}, "total": int64(1), "truncated": false}
		},
		"unsorted vendors": func(o map[string]any) {
			epObj(o, "edr")["agents"] = map[string]any{"items": agentItems("sophos", "huntress"), "total": int64(2), "truncated": false}
		},
		"repeated vendor": func(o map[string]any) {
			epObj(o, "edr")["agents"] = map[string]any{"items": agentItems("sophos", "sophos"), "total": int64(2), "truncated": false}
		},
		"wrong total": func(o map[string]any) {
			epObj(o, "edr")["agents"] = map[string]any{"items": agentItems("huntress"), "total": int64(3), "truncated": false}
		},
		"over the cap": func(o map[string]any) {
			epObj(o, "edr")["agents"] = map[string]any{"items": agentItems(nine...), "total": int64(9), "truncated": false}
		},
		"truncated but not full": func(o map[string]any) {
			epObj(o, "edr")["agents"] = map[string]any{"items": agentItems("huntress"), "total": int64(5), "truncated": true}
		},
		"firewall 4":  func(o map[string]any) { epProt(o)["firewall_profiles_on"] = int64(4) },
		"no schedule": func(o map[string]any) { delete(epPred(o), "schedule") },
		"interval too long": func(o map[string]any) {
			epPred(o)["schedule"].(map[string]any)["interval_s"] = int64(86400)
		},
		"interval too short": func(o map[string]any) {
			epPred(o)["schedule"].(map[string]any)["interval_s"] = int64(5)
		},
		"negative deferral": func(o map[string]any) {
			epPred(o)["schedule"].(map[string]any)["deferred_s"] = int64(-1)
		},
		"power source": func(o map[string]any) {
			epPred(o)["schedule"].(map[string]any)["on_battery"] = true
		},
		"blocklist suspended": func(o map[string]any) {
			epProt(o)["vulnerable_driver_blocklist"] = "suspended"
		},
	}
	for name, mutate := range cases {
		o := endpointStatement(dev)
		mutate(o)
		if err := validateEndpoint(t, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Each count on its own must be -1 when the check did not run.
	for _, k := range []string{"products", "enabled", "up_to_date"} {
		o := endpointStatement(dev)
		sc := map[string]any{"state": "unknown", "products": int64(-1), "enabled": int64(-1), "up_to_date": int64(-1)}
		sc[k] = int64(0)
		epProt(o)["security_center"] = sc
		if err := validateEndpoint(t, o); err == nil {
			t.Errorf("security_center.%s = 0 accepted when state is unknown", k)
		}
	}
	// A full list with truncated set is allowed: total says how many.
	o := endpointStatement(dev)
	epObj(o, "edr")["agents"] = map[string]any{"items": agentItems(nine[:EDRAgentsMaxItems]...), "total": int64(9), "truncated": true}
	if err := validateEndpoint(t, o); err != nil {
		t.Errorf("truncated full list refused: %v", err)
	}
}

// The endpoint schema's sensor_health is SPEC 6.4's, and its enums are
// sorted (so the exported schema is stable).
func TestEndpointSchemaShape(t *testing.T) {
	p := EndpointPredicateSpec().Fields
	if p["sensor_health"] == nil || len(p["sensor_health"].Fields) != 4 {
		t.Fatal("sensor_health missing")
	}
	if _, ok := p["tenant"]; ok {
		t.Fatal("tenant must stay out of endpoint/v1 until endpoint enrollment (SPEC 6.5)")
	}
	for _, vals := range [][]string{availabilityVals, toggleVals, runningModeVals, volumeVals, blocklistVals, edrVendorVals} {
		for i := 1; i < len(vals); i++ {
			if vals[i-1] >= vals[i] {
				t.Errorf("enum %v is not sorted", vals)
			}
		}
	}
}
