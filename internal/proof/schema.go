package proof

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The sensor_health schema as data, in the style of the engine's posture
// schema: every object lists exactly its allowed fields, every string is an
// enum, a constant, a timestamp, fixed-length hex or a key-derived ID.
// Unknown fields are refused first, so a smuggled "hostname" or "path"
// fails with a plain message.

// Rule is the one-line privacy rule, quoted in error messages.
const Rule = "statements may carry only yes/no values, counts, enums and timestamps"

type spec struct {
	t        string // bool, int, enum, const, timestamp, hex, id, object, array
	min, max int64
	values   []string
	n        int    // hex: number of hex characters
	value    string // const
	fields   map[string]*spec
	le       [][2]string // object: int field a <= int field b
	of       *spec       // array element
	maxItems int
	key      string // array: items sorted and unique by this enum field
}

func boolean() *spec               { return &spec{t: "bool"} }
func integer(min, max int64) *spec { return &spec{t: "int", min: min, max: max} }
func enumOf(table []string) *spec {
	var v []string
	for _, n := range table {
		if n != "" {
			v = append(v, n)
		}
	}
	return &spec{t: "enum", values: v}
}
func constant(v string) *spec         { return &spec{t: "const", value: v} }
func hexN(n int) *spec                { return &spec{t: "hex", n: n} }
func object(f map[string]*spec) *spec { return &spec{t: "object", fields: f} }
func deviceID() *spec                 { return &spec{t: "id"} }
func timestamp() *spec                { return &spec{t: "timestamp"} }
func arrayOf(of *spec, max int, key string) *spec {
	return &spec{t: "array", of: of, maxItems: max, key: key}
}

func checksSpec() *spec {
	sc := object(map[string]*spec{
		"state":      enumOf(availabilityNames),
		"products":   integer(UnknownCount, MaxAVProducts),
		"enabled":    integer(UnknownCount, MaxAVProducts),
		"up_to_date": integer(UnknownCount, MaxAVProducts),
	})
	sc.le = [][2]string{{"enabled", "products"}, {"up_to_date", "products"}}
	return object(map[string]*spec{
		"security_center": sc,
		"defender": object(map[string]*spec{
			"state":                enumOf(availabilityNames),
			"am_service":           enumOf(toggleNames),
			"antivirus":            enumOf(toggleNames),
			"real_time_protection": enumOf(toggleNames),
			"behavior_monitor":     enumOf(toggleNames),
			"tamper_protection":    enumOf(toggleNames),
			"signature_age_days":   integer(UnknownCount, MaxSignatureAgeDays),
			"running_mode":         enumOf(runningModeNames),
		}),
		"edr": object(map[string]*spec{
			"state": enumOf(availabilityNames),
			"agents": arrayOf(object(map[string]*spec{
				"vendor":  enumOf(vendorNames),
				"running": boolean(),
			}), MaxEDRAgents, "vendor"),
		}),
		"bitlocker_os_volume":         enumOf(volumeNames),
		"firewall_profiles_on":        integer(UnknownCount, 3),
		"vulnerable_driver_blocklist": enumOf(blocklistNames),
		"memory_integrity":            enumOf(toggleNames),
	})
}

func predicateSpec() *spec {
	return object(map[string]*spec{
		"attester":      deviceID(),
		"attester_kind": enumOf(attesterKindNames),
		"seq":           integer(1, 1<<31-1),
		"prev":          hexN(64),
		"nonce":         hexN(32),
		"nonce_source":  enumOf(nonceSourceNames),
		"salt":          hexN(64),
		"observed_at":   timestamp(),
		"agent_version": object(map[string]*spec{
			"major": integer(0, 65535), "minor": integer(0, 65535), "patch": integer(0, 65535),
		}),
		"key_protection":       enumOf(keyProtectionNames),
		"heartbeat_interval_s": integer(MinIntervalS, MaxIntervalS),
		"checks":               checksSpec(),
	})
}

func statementSpec() *spec {
	subject := object(map[string]*spec{
		"name":   deviceID(),
		"digest": object(map[string]*spec{"sha256": hexN(64)}),
	})
	s := arrayOf(subject, 1, "")
	return object(map[string]*spec{
		"_type":         constant(InTotoStatementType),
		"subject":       s,
		"predicateType": constant(PredicateSensorHealth),
		"predicate":     predicateSpec(),
	})
}

// checkStatement validates a decoded statement: schema first, then the
// cross-field rules.
func checkStatement(obj map[string]any) error {
	if err := check(obj, statementSpec(), ""); err != nil {
		return err
	}
	subj := obj["subject"].([]any)
	if len(subj) != 1 {
		return failf("subject", "must have exactly one item")
	}
	s := subj[0].(map[string]any)
	p := obj["predicate"].(map[string]any)
	digest := s["digest"].(map[string]any)["sha256"].(string)
	if s["name"] != p["attester"] {
		return failf("subject[0].name", "must equal predicate.attester")
	}
	if p["attester"] != DevicePrefix+digest[:16] {
		return failf("predicate.attester", "must be derived from the key in subject[0].digest")
	}
	c := p["checks"].(map[string]any)
	// A check that did not run must not claim values, and one that ran
	// must report real counts. This keeps "0" and "unknown" distinct.
	sc := c["security_center"].(map[string]any)
	if err := countsMatchState("predicate.checks.security_center", sc, true, "products", "enabled", "up_to_date"); err != nil {
		return err
	}
	// Defender can be readable while one property is NULL, so its age may
	// be unknown even when state is ok.
	d := c["defender"].(map[string]any)
	if err := countsMatchState("predicate.checks.defender", d, false, "signature_age_days"); err != nil {
		return err
	}
	if d["state"] != "ok" {
		for _, k := range []string{"am_service", "antivirus", "real_time_protection", "behavior_monitor", "tamper_protection", "running_mode"} {
			if d[k] != "unknown" {
				return failf("predicate.checks.defender."+k, "must be unknown when state is %v", d["state"])
			}
		}
	}
	e := c["edr"].(map[string]any)
	if e["state"] != "ok" && len(e["agents"].([]any)) != 0 {
		return failf("predicate.checks.edr.agents", "must be empty when state is %v", e["state"])
	}
	return nil
}

func countsMatchState(path string, o map[string]any, realWhenOK bool, keys ...string) error {
	ok := o["state"] == "ok"
	for _, k := range keys {
		n := o[k].(int64)
		if ok && realWhenOK && n < 0 {
			return failf(path+"."+k, "must be a real count when state is ok")
		}
		if !ok && n != UnknownCount {
			return failf(path+"."+k, "must be %d when state is %v", UnknownCount, o["state"])
		}
	}
	return nil
}

// ContentError says why a statement was refused, with the JSON path.
type ContentError struct{ Path, Reason string }

func (e *ContentError) Error() string {
	if e.Path == "" {
		return e.Reason
	}
	return e.Path + ": " + e.Reason
}

func failf(path, format string, a ...any) error {
	return &ContentError{Path: path, Reason: fmt.Sprintf(format, a...)}
}

func check(v any, s *spec, path string) error {
	switch s.t {
	case "bool":
		if _, ok := v.(bool); !ok {
			return failf(path, "must be true or false (%s)", Rule)
		}
	case "int":
		n, ok := v.(int64)
		if !ok {
			return failf(path, "must be an integer (%s)", Rule)
		}
		if n < s.min || n > s.max {
			return failf(path, "integer %d is outside %d..%d", n, s.min, s.max)
		}
	case "enum":
		str, ok := v.(string)
		if !ok || !contains(s.values, str) {
			return failf(path, "must be one of %s (%s)", strings.Join(s.values, ", "), Rule)
		}
	case "const":
		if str, ok := v.(string); !ok || str != s.value {
			return failf(path, "must be %q", s.value)
		}
	case "timestamp":
		str, ok := v.(string)
		if !ok {
			return failf(path, "must be a UTC timestamp like 2026-10-01T14:00:00Z")
		}
		if t, err := time.Parse(TimeLayout, str); err != nil || t.Format(TimeLayout) != str {
			return failf(path, "must be a UTC timestamp like 2026-10-01T14:00:00Z")
		}
	case "hex":
		str, ok := v.(string)
		if !ok || len(str) != s.n || !isLowerHex(str) {
			return failf(path, "must be %d lowercase hex characters", s.n)
		}
	case "id":
		str, ok := v.(string)
		if !ok || !strings.HasPrefix(str, DevicePrefix) || len(str) != len(DevicePrefix)+16 || !isLowerHex(str[len(DevicePrefix):]) {
			return failf(path, "must be a key-derived device ID (%s followed by 16 hex characters)", DevicePrefix)
		}
	case "array":
		arr, ok := v.([]any)
		if !ok {
			return failf(path, "must be an array")
		}
		if len(arr) > s.maxItems {
			return failf(path, "at most %d items are allowed", s.maxItems)
		}
		prev := ""
		for i, it := range arr {
			ip := fmt.Sprintf("%s[%d]", path, i)
			if err := check(it, s.of, ip); err != nil {
				return err
			}
			if s.key != "" {
				k := it.(map[string]any)[s.key].(string)
				if i > 0 && k <= prev {
					return failf(ip, "items must be sorted by %s with no repeats", s.key)
				}
				prev = k
			}
		}
	case "object":
		return checkObject(v, s, path)
	default:
		return failf(path, "schema error: unknown type %q", s.t)
	}
	return nil
}

func checkObject(v any, s *spec, path string) error {
	o, ok := v.(map[string]any)
	if !ok {
		return failf(path, "must be an object")
	}
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := s.fields[k]; !ok {
			return failf(join(path, k), "field is not allowed (%s)", Rule)
		}
	}
	names := make([]string, 0, len(s.fields))
	for k := range s.fields {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		val, ok := o[k]
		if !ok {
			return failf(join(path, k), "required field is missing")
		}
		if err := check(val, s.fields[k], join(path, k)); err != nil {
			return err
		}
	}
	for _, le := range s.le {
		a, _ := o[le[0]].(int64)
		b, _ := o[le[1]].(int64)
		if a > b {
			return failf(join(path, le[0]), "must not exceed %s (%d > %d)", le[1], a, b)
		}
	}
	return nil
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// NewSalt returns 256 fresh random bits. Every statement needs its own
// salt so that its log commitment cannot be found by guessing the few
// booleans and counts inside.
func NewSalt() (Salt, error) {
	var s Salt
	_, err := rand.Read(s[:])
	return s, err
}

// NewAgentNonce returns a random nonce for a statement made while the
// server challenge could not be fetched (NonceAgent).
func NewAgentNonce() (Nonce, error) {
	var n Nonce
	_, err := rand.Read(n[:])
	return n, err
}
