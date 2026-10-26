package pack

import (
	"errors"
	"fmt"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

// PolicyType identifies trust policy files.
const PolicyType = "proof-trust-policy/v1"

// TrustPolicy is everything a verifier trusts. A production verifier pins
// it in its own code and publishes it at a well-known URL; a pack can never
// supply its own trust roots.
type TrustPolicy struct {
	DemoOnly       bool
	LogOrigin      string
	LogKey         *note.VerifierKey
	Witnesses      []Party
	WitnessQuorum  int
	TSAs           []Party
	TSAQuorum      int
	MaxReportDelay time.Duration // TSA time may trail the claimed time by this much
	MaxClockSkew   time.Duration // claimed time may lead TSA time by this much
	MaxTSASpread   time.Duration // tokens from different TSAs must agree this closely
	witnessKeys    []*note.VerifierKey
	tsaTrusted     []tsa.Trusted
}

// Party is a witness or timestamp authority as listed in a policy.
type Party struct {
	Name      string
	VKey      string // witnesses
	Kind      string // TSAs
	PublicKey string // TSAs: base64 SPKI
	Label     string
	Simulated bool
}

// Default limits.
const (
	DefaultMaxReportDelay = 15 * time.Minute
	DefaultMaxClockSkew   = 5 * time.Minute
	DefaultMaxTSASpread   = 5 * time.Minute
)

// Value renders the policy as JSON.
func (t *TrustPolicy) Value() map[string]any {
	ws := []any{}
	for _, w := range t.Witnesses {
		ws = append(ws, map[string]any{"name": w.Name, "vkey": w.VKey, "label": w.Label, "simulated": w.Simulated})
	}
	ts := []any{}
	for _, a := range t.TSAs {
		ts = append(ts, map[string]any{"name": a.Name, "kind": a.Kind, "public_key": a.PublicKey, "label": a.Label, "simulated": a.Simulated})
	}
	return map[string]any{
		"policy_type":           PolicyType,
		"demo_only":             t.DemoOnly,
		"log":                   map[string]any{"origin": t.LogOrigin, "vkey": t.LogKey.Vkey},
		"witnesses":             ws,
		"witness_quorum":        int64(t.WitnessQuorum),
		"timestamp_authorities": ts,
		"timestamp_quorum":      int64(t.TSAQuorum),
		"limits": map[string]any{
			"max_report_delay_s": int64(t.MaxReportDelay / time.Second),
			"max_clock_skew_s":   int64(t.MaxClockSkew / time.Second),
			"max_tsa_spread_s":   int64(t.MaxTSASpread / time.Second),
		},
	}
}

// ParseTrustPolicy decodes and checks a policy file.
func ParseTrustPolicy(b []byte) (*TrustPolicy, error) {
	v, err := canon.ParseContainer(b)
	if err != nil {
		return nil, fmt.Errorf("trust policy: %w", err)
	}
	top, err := fields(v, "trust policy", "policy_type", "demo_only", "log", "witnesses", "witness_quorum", "timestamp_authorities", "timestamp_quorum", "limits")
	if err != nil {
		return nil, err
	}
	if top["policy_type"] != PolicyType {
		return nil, errors.New("not a " + PolicyType + " file")
	}
	t := &TrustPolicy{}
	t.DemoOnly, _ = top["demo_only"].(bool)
	lg, err := fields(top["log"], "log", "origin", "vkey")
	if err != nil {
		return nil, err
	}
	t.LogOrigin, _ = lg["origin"].(string)
	vk, _ := lg["vkey"].(string)
	if t.LogKey, err = note.ParseVKey(vk); err != nil || t.LogKey.Type != note.TypeEd25519 || t.LogKey.Name != t.LogOrigin {
		return nil, errors.New("trust policy: log vkey must be an Ed25519 note key named after the log origin")
	}
	ws, _ := top["witnesses"].([]any)
	for _, w := range ws {
		wo, err := fields(w, "witness", "name", "vkey", "label", "simulated")
		if err != nil {
			return nil, err
		}
		p := Party{}
		p.Name, _ = wo["name"].(string)
		p.VKey, _ = wo["vkey"].(string)
		p.Label, _ = wo["label"].(string)
		p.Simulated, _ = wo["simulated"].(bool)
		t.Witnesses = append(t.Witnesses, p)
	}
	as, _ := top["timestamp_authorities"].([]any)
	for _, a := range as {
		ao, err := fields(a, "timestamp authority", "name", "kind", "public_key", "label", "simulated")
		if err != nil {
			return nil, err
		}
		p := Party{}
		p.Name, _ = ao["name"].(string)
		p.Kind, _ = ao["kind"].(string)
		p.PublicKey, _ = ao["public_key"].(string)
		p.Label, _ = ao["label"].(string)
		p.Simulated, _ = ao["simulated"].(bool)
		t.TSAs = append(t.TSAs, p)
	}
	wq, _ := top["witness_quorum"].(int64)
	tq, _ := top["timestamp_quorum"].(int64)
	t.WitnessQuorum, t.TSAQuorum = int(wq), int(tq)
	lim, err := fields(top["limits"], "limits", "max_report_delay_s", "max_clock_skew_s", "max_tsa_spread_s")
	if err != nil {
		return nil, err
	}
	sec := func(k string) time.Duration { n, _ := lim[k].(int64); return time.Duration(n) * time.Second }
	t.MaxReportDelay, t.MaxClockSkew, t.MaxTSASpread = sec("max_report_delay_s"), sec("max_clock_skew_s"), sec("max_tsa_spread_s")
	return t, t.init()
}

// init parses keys and enforces sane minimums: a policy cannot switch off
// the witness or timestamp requirements.
func (t *TrustPolicy) init() error {
	if t.WitnessQuorum < 1 || t.WitnessQuorum > len(t.Witnesses) {
		return errors.New("trust policy: witness quorum must be between 1 and the number of witnesses")
	}
	if t.TSAQuorum < 2 || t.TSAQuorum > len(t.TSAs) {
		return errors.New("trust policy: at least two independent timestamp authorities are required")
	}
	t.witnessKeys, t.tsaTrusted = nil, nil
	for _, w := range t.Witnesses {
		vk, err := note.ParseVKey(w.VKey)
		if err != nil || vk.Type != note.TypeCosignature || vk.Name != w.Name {
			return fmt.Errorf("trust policy: bad witness key for %s", w.Name)
		}
		t.witnessKeys = append(t.witnessKeys, vk)
	}
	for _, a := range t.TSAs {
		pk, err := sigs.ParsePublicKeyBase64(a.PublicKey)
		if err != nil {
			return fmt.Errorf("trust policy: bad key for TSA %s", a.Name)
		}
		t.tsaTrusted = append(t.tsaTrusted, tsa.Trusted{Name: a.Name, Kind: a.Kind, PublicKey: pk})
	}
	if t.MaxReportDelay <= 0 || t.MaxClockSkew < 0 || t.MaxTSASpread <= 0 {
		return errors.New("trust policy: limits must be positive")
	}
	return nil
}

// NewTrustPolicy builds a policy in code (for generators and tests).
func NewTrustPolicy(origin, logVKey string, witnesses []Party, witnessQuorum int, tsas []Party, demo bool) (*TrustPolicy, error) {
	vk, err := note.ParseVKey(logVKey)
	if err != nil {
		return nil, err
	}
	t := &TrustPolicy{DemoOnly: demo, LogOrigin: origin, LogKey: vk, Witnesses: witnesses, WitnessQuorum: witnessQuorum,
		TSAs: tsas, TSAQuorum: 2, MaxReportDelay: DefaultMaxReportDelay, MaxClockSkew: DefaultMaxClockSkew, MaxTSASpread: DefaultMaxTSASpread}
	return t, t.init()
}

// JSON renders the policy file.
func (t *TrustPolicy) JSON() []byte {
	b, _ := marshalIndent(t.Value())
	return b
}
