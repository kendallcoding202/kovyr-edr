package checks

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

var errBoom = errors.New("boom")

func TestDecodeProductState(t *testing.T) {
	on, off, unk := proof.ToggleOn, proof.ToggleOff, proof.ToggleUnknown
	cases := []struct {
		state       uint32
		enabled, up proof.Toggle
	}{
		{0x061100, on, on},   // 397568 Defender on, up to date
		{0x060100, off, on},  // 393472 Defender off
		{0x061110, on, off},  // 397584 on, out of date
		{0x060110, off, off}, // 393488 off, out of date
		{0x041000, on, on},   // 266240 third party on
		{0x040000, off, on},  // 262144 third party off
		{0x062100, unk, on},  // unrecognized scanner byte
		{0x061105, on, unk},  // unrecognized signature byte
		{unknownProductState, unk, unk},
	}
	for _, c := range cases {
		en, up := DecodeProductState(c.state)
		if en != c.enabled || up != c.up {
			t.Errorf("0x%06x: got enabled=%v up_to_date=%v, want %v %v", c.state, en, up, c.enabled, c.up)
		}
	}
}

func TestSecurityCenterFrom(t *testing.T) {
	got := SecurityCenterFrom([]uint32{0x061100, 0x060100, 0x041010}, nil)
	want := proof.SecurityCenter{State: proof.AvailOK, Products: 3, Enabled: 2, UpToDate: 2}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := SecurityCenterFrom(nil, nil); got != (proof.SecurityCenter{State: proof.AvailOK}) {
		t.Errorf("no products: %+v", got)
	}
	// Windows Server: no SecurityCenter2 namespace.
	if got := SecurityCenterFrom(nil, fmt.Errorf("wrap: %w", ErrNotApplicable)); got != proof.UnknownSecurityCenter(proof.AvailNotApplicable) {
		t.Errorf("server: %+v", got)
	}
	for _, err := range []error{ErrAccessDenied, ErrEncryptionRequired, errBoom} {
		if got := SecurityCenterFrom([]uint32{0x061100}, err); got != proof.UnknownSecurityCenter(proof.AvailUnknown) {
			t.Errorf("%v: %+v", err, got)
		}
	}
	many := make([]uint32, 100)
	if got := SecurityCenterFrom(many, nil); got.Products != proof.MaxAVProducts {
		t.Errorf("product count not capped: %d", got.Products)
	}
}

func TestMapRunningMode(t *testing.T) {
	cases := map[string]proof.RunningMode{
		"Normal": proof.ModeNormal, " normal ": proof.ModeNormal,
		"Passive": proof.ModePassive, "Passive Mode": proof.ModePassive,
		"EDR Block Mode": proof.ModeEDRBlock, "edr  block mode": proof.ModeEDRBlock,
		"SxS Passive Mode": proof.ModeSxSPassive,
		"":                 proof.ModeUnknown, "Not running": proof.ModeUnknown, "MARIA-LAPTOP": proof.ModeUnknown,
	}
	for in, want := range cases {
		if got := MapRunningMode(in); got != want {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
	}
}

func TestDefenderFrom(t *testing.T) {
	f := HealthyFake()
	got := DefenderFrom(f.Defender, nil)
	want := proof.Defender{State: proof.AvailOK, AMService: proof.ToggleOn, Antivirus: proof.ToggleOn,
		RealTime: proof.ToggleOn, BehaviorMonitor: proof.ToggleOn, TamperProtection: proof.ToggleOn,
		SignatureAgeDays: 0, RunningMode: proof.ModeNormal}
	if got != want {
		t.Errorf("healthy: got %+v", got)
	}

	tampered := f.Defender
	tampered.RealTimeProtectionEnabled = ptr(false)
	tampered.IsTamperProtected = ptr(false)
	tampered.AntivirusSignatureAge = ptr(uint32(40))
	got = DefenderFrom(tampered, nil)
	if got.RealTime != proof.ToggleOff || got.TamperProtection != proof.ToggleOff || got.SignatureAgeDays != 40 {
		t.Errorf("tampered: got %+v", got)
	}

	// NULL properties are unknown, not off.
	got = DefenderFrom(DefenderStatus{}, nil)
	if got.State != proof.AvailOK || got.RealTime != proof.ToggleUnknown || got.SignatureAgeDays != proof.UnknownCount || got.RunningMode != proof.ModeUnknown {
		t.Errorf("all NULL: got %+v", got)
	}
	never := DefenderStatus{AntivirusSignatureAge: ptr(uint32(4294967295))}
	if got := DefenderFrom(never, nil); got.SignatureAgeDays != proof.MaxSignatureAgeDays {
		t.Errorf("age not capped: %d", got.SignatureAgeDays)
	}
	if got := DefenderFrom(f.Defender, ErrNotApplicable); got != proof.UnknownDefender(proof.AvailNotApplicable) {
		t.Errorf("no Defender: %+v", got)
	}
	if got := DefenderFrom(f.Defender, ErrAccessDenied); got != proof.UnknownDefender(proof.AvailUnknown) {
		t.Errorf("denied: %+v", got)
	}
}

func TestEDRFrom(t *testing.T) {
	services := []Service{
		{Name: "Sense", Running: true},
		{Name: "CSFalconService", Running: false},
		{Name: "csfalconservice", Running: false},
		{Name: "SentinelAgent", Running: true},
		{Name: "HuntressAgent", Running: false},
		{Name: "HuntressRio", Running: true}, // one Huntress service running: Huntress runs
		{Name: "Spooler", Running: true},     // not an EDR: dropped
		{Name: "MARIA-LAPTOP-svc", Running: true},
	}
	got := EDRFrom(services, nil)
	sort.Slice(got.Agents, func(i, j int) bool { return got.Agents[i].Vendor < got.Agents[j].Vendor })
	want := []proof.EDRAgent{
		{Vendor: proof.VendorDefenderForEndpoint, Running: true},
		{Vendor: proof.VendorCrowdStrike, Running: false},
		{Vendor: proof.VendorSentinelOne, Running: true},
		{Vendor: proof.VendorHuntress, Running: true},
	}
	if got.State != proof.AvailOK || fmt.Sprint(got.Agents) != fmt.Sprint(want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := EDRFrom(nil, nil); got.State != proof.AvailOK || len(got.Agents) != 0 {
		t.Errorf("none installed: %+v", got)
	}
	if got := EDRFrom(services, ErrAccessDenied); got.State != proof.AvailUnknown || got.Agents != nil {
		t.Errorf("error: %+v", got)
	}
	if got := EDRFrom(nil, ErrNotApplicable); got.State != proof.AvailNotApplicable {
		t.Errorf("n/a: %+v", got)
	}
}

func TestEveryAllowlistedServiceMapsToARealVendor(t *testing.T) {
	seen := map[proof.Vendor]bool{}
	for _, name := range EDRServiceNames() {
		v, ok := VendorForService(name)
		if !ok || strings.HasPrefix(v.String(), "invalid") {
			t.Errorf("%q maps to %v", name, v)
		}
		seen[v] = true
	}
	if len(seen) != proof.MaxEDRAgents {
		t.Errorf("%d vendors have service names, want all %d", len(seen), proof.MaxEDRAgents)
	}
}

func TestBitLockerFrom(t *testing.T) {
	cases := []struct {
		status uint32
		err    error
		want   proof.VolumeProtection
	}{
		{0, nil, proof.VolumeOff},
		{1, nil, proof.VolumeOn},
		{2, nil, proof.VolumeUnknown}, // volume locked
		{7, nil, proof.VolumeUnknown},
		{1, ErrAccessDenied, proof.VolumeUnknown}, // not elevated
		{1, ErrEncryptionRequired, proof.VolumeUnknown},
		{1, ErrNotFound, proof.VolumeUnknown},
		{1, ErrNotApplicable, proof.VolumeNotApplicable},
	}
	for _, c := range cases {
		if got := BitLockerFrom(c.status, c.err); got != c.want {
			t.Errorf("status %d err %v: got %v, want %v", c.status, c.err, got, c.want)
		}
	}
}

func TestFirewallFromRespectsGroupPolicy(t *testing.T) {
	on, off := ptr(uint32(1)), ptr(uint32(0))
	p := func(policy, local *uint32) FirewallProfile { return FirewallProfile{Policy: policy, Local: local} }
	cases := []struct {
		name string
		s    FirewallSettings
		want int8
	}{
		{"all local on", FirewallSettings{p(nil, on), p(nil, on), p(nil, on)}, 3},
		{"public off locally", FirewallSettings{p(nil, on), p(nil, on), p(nil, off)}, 2},
		{"policy turns public off", FirewallSettings{p(nil, on), p(nil, on), p(off, on)}, 2},
		{"policy turns all on", FirewallSettings{p(on, off), p(on, off), p(on, off)}, 3},
		{"all off", FirewallSettings{p(nil, off), p(off, on), p(nil, off)}, 0},
		{"one profile unreadable", FirewallSettings{p(nil, on), p(nil, nil), p(nil, on)}, proof.UnknownCount},
		{"non-zero means on", FirewallSettings{p(nil, ptr(uint32(5))), p(nil, on), p(nil, on)}, 3},
	}
	for _, c := range cases {
		if got := FirewallFrom(c.s, nil); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	if got := FirewallFrom(FirewallSettings{p(nil, on), p(nil, on), p(nil, on)}, ErrAccessDenied); got != proof.UnknownCount {
		t.Errorf("error: got %d", got)
	}
}

func TestDriverBlocklistFrom(t *testing.T) {
	cases := []struct {
		v    uint32
		err  error
		want proof.BlocklistState
	}{
		{1, nil, proof.BlocklistOn},
		{0, nil, proof.BlocklistOff},
		{2, nil, proof.BlocklistUnknown},
		{0, ErrNotFound, proof.BlocklistDefault},
		{0, fmt.Errorf("x: %w", ErrNotFound), proof.BlocklistDefault},
		{1, ErrAccessDenied, proof.BlocklistUnknown},
		{1, errBoom, proof.BlocklistUnknown},
	}
	for _, c := range cases {
		if got := DriverBlocklistFrom(c.v, c.err); got != c.want {
			t.Errorf("v=%d err=%v: got %v, want %v", c.v, c.err, got, c.want)
		}
	}
}

func TestMemoryIntegrityFrom(t *testing.T) {
	cases := []struct {
		running []uint32
		err     error
		want    proof.Toggle
	}{
		{[]uint32{1, 2}, nil, proof.ToggleOn},
		{[]uint32{2}, nil, proof.ToggleOn},
		{[]uint32{1}, nil, proof.ToggleOff}, // Credential Guard only
		{[]uint32{0}, nil, proof.ToggleOff},
		{nil, nil, proof.ToggleOff},
		{[]uint32{2}, ErrNotApplicable, proof.ToggleUnknown},
		{[]uint32{2}, errBoom, proof.ToggleUnknown},
	}
	for _, c := range cases {
		if got := MemoryIntegrityFrom(c.running, c.err); got != c.want {
			t.Errorf("%v err=%v: got %v, want %v", c.running, c.err, got, c.want)
		}
	}
}
