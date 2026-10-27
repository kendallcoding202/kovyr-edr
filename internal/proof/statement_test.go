package proof

import (
	"encoding/base64"
	"encoding/json"
	"math/rand/v2"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// wantVocabulary is every enum string a statement may contain. It is
// written out by hand, not derived from the code, so adding a value to the
// vocabulary needs a reviewed change to this test.
var wantVocabulary = []string{
	// availability
	"unknown", "ok", "not_applicable",
	// toggles, blocklist, volume protection
	"on", "off", "default",
	// Defender running mode
	"normal", "passive", "edr_block", "sxs_passive",
	// EDR vendors
	"microsoft_defender_endpoint", "crowdstrike", "sentinelone", "huntress", "sophos",
	"bitdefender", "eset", "malwarebytes", "webroot", "carbon_black", "cortex_xdr",
	"trend_micro", "symantec",
	// attester kind
	"device_agent",
}

var (
	deviceIDRe  = regexp.MustCompile(`^dev_[0-9a-f]{16}$`)
	enumValueRe = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
)

func hexOf(n int) func(string) bool {
	return regexp.MustCompile(`^[0-9a-f]{` + strconv.Itoa(n) + `}$`).MatchString
}

// protocolFormats are the only keys whose string values are not enum
// values. Each has a fixed, text-free format.
var protocolFormats = map[string]func(string) bool{
	"_type":         func(s string) bool { return s == InTotoStatementType },
	"predicateType": func(s string) bool { return s == PredicateEndpoint },
	"name":          deviceIDRe.MatchString,
	"attester":      deviceIDRe.MatchString,
	"sha256":        hexOf(64),
	"prev":          hexOf(64),
	"salt":          hexOf(64),
	"nonce":         hexOf(32),
	"observed_at": func(s string) bool {
		t, err := time.Parse(TimeLayout, s)
		return err == nil && t.Format(TimeLayout) == s
	},
}

// forbiddenStrings walks a decoded statement and returns every string that
// is neither a fixed-format protocol value under its own key nor an
// allowlisted enum value.
func forbiddenStrings(v any, key, path string) []string {
	allowed := map[string]bool{}
	for _, w := range wantVocabulary {
		allowed[w] = true
	}
	var bad []string
	var walk func(v any, key, path string)
	walk = func(v any, key, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(e, k, path+"."+k)
			}
		case []any:
			for _, e := range x {
				walk(e, key, path+"[]")
			}
		case string:
			if f, ok := protocolFormats[key]; ok {
				if !f(x) {
					bad = append(bad, path+"="+x)
				}
				return
			}
			if !allowed[x] {
				bad = append(bad, path+"="+x)
			}
		case bool, int64:
		default:
			bad = append(bad, path+": unexpected type")
		}
	}
	walk(v, key, path)
	return bad
}

func TestVocabularyIsExactlyTheAllowlist(t *testing.T) {
	got := map[string]bool{}
	for _, table := range [][]string{availabilityNames, toggleNames, blocklistNames, volumeNames,
		runningModeNames, vendorNames, attesterKindNames} {
		for _, n := range table {
			if n == "" {
				continue
			}
			if !enumValueRe.MatchString(n) {
				t.Errorf("enum value %q is not a short snake_case identifier", n)
			}
			got[n] = true
		}
	}
	want := map[string]bool{}
	for _, w := range wantVocabulary {
		want[w] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("vocabulary drifted from the reviewed allowlist:\n code %v\n test %v", keys(got), keys(want))
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func testHeader(seq uint32) Header {
	h := Header{
		Seq:          seq,
		ObservedAt:   time.Date(2026, 10, 26, 19, 0, 0, 0, time.UTC),
		AgentVersion: Version{0, 1, 0},
	}
	h.Nonce[0], h.Salt[0], h.Prev[0] = 1, 2, 3
	return h
}

var testSensor = SensorHealth{SensorRunning: true}

func healthyReadings() Readings {
	return Readings{
		SecurityCenter: SecurityCenter{State: AvailOK, Products: 1, Enabled: 1, UpToDate: 1},
		Defender: Defender{State: AvailOK, AMService: ToggleOn, Antivirus: ToggleOn, RealTime: ToggleOn,
			BehaviorMonitor: ToggleOn, TamperProtection: ToggleOn, SignatureAgeDays: 0, RunningMode: ModeNormal},
		EDR:                EDR{State: AvailOK, Agents: []EDRAgent{{VendorHuntress, true}, {VendorDefenderForEndpoint, true}}},
		BitLocker:          VolumeOn,
		FirewallProfilesOn: 3,
		DriverBlocklist:    BlocklistDefault,
		MemoryIntegrity:    ToggleOn,
	}
}

func TestBuildValidateRoundTrip(t *testing.T) {
	s := newTestSigner(t)
	r := healthyReadings()
	payload, err := BuildStatement(s.Public(), testHeader(7), testSensor, r)
	if err != nil {
		t.Fatal(err)
	}
	st, err := ValidateStatement(payload)
	if err != nil {
		t.Fatalf("own statement does not validate: %v\n%s", err, payload)
	}
	if st.DeviceID != s.Public().DeviceID() || st.KeyID != s.Public().KeyID() || st.Seq != 7 || st.SensorHealth != testSensor {
		t.Errorf("header did not round-trip: %+v", st)
	}
	sort.Slice(r.EDR.Agents, func(i, j int) bool { return r.EDR.Agents[i].Vendor.String() < r.EDR.Agents[j].Vendor.String() })
	if !reflect.DeepEqual(st.Readings, r) {
		t.Errorf("readings did not round-trip:\n got %+v\nwant %+v", st.Readings, r)
	}
	obj, _ := ParseCanonicalObject(payload)
	if bad := forbiddenStrings(obj, "", ""); len(bad) != 0 {
		t.Errorf("forbidden strings in a healthy statement: %v", bad)
	}
}

func TestUnknownReadingsBuild(t *testing.T) {
	s := newTestSigner(t)
	payload, err := BuildStatement(s.Public(), testHeader(1), testSensor, UnknownReadings())
	if err != nil {
		t.Fatalf("all-unknown readings must build: %v", err)
	}
	if _, err := ValidateStatement(payload); err != nil {
		t.Fatal(err)
	}
}

// randomReadings draws readings from the whole vocabulary, consistent with
// the cross-field rules.
func randomReadings(r *rand.Rand) Readings {
	pick := func(table []string, allowZero bool) uint8 {
		lo := 0
		if !allowZero {
			lo = 1
		}
		return uint8(lo + r.IntN(len(table)-lo))
	}
	out := UnknownReadings()
	if st := Availability(pick(availabilityNames, true)); st == AvailOK {
		p := int16(r.IntN(MaxAVProducts + 1))
		out.SecurityCenter = SecurityCenter{State: st, Products: p, Enabled: int16(r.IntN(int(p) + 1)), UpToDate: int16(r.IntN(int(p) + 1))}
	} else {
		out.SecurityCenter = UnknownSecurityCenter(st)
	}
	if st := Availability(pick(availabilityNames, true)); st == AvailOK {
		tg := func() Toggle { return Toggle(pick(toggleNames, true)) }
		out.Defender = Defender{State: st, AMService: tg(), Antivirus: tg(), RealTime: tg(), BehaviorMonitor: tg(),
			TamperProtection: tg(), SignatureAgeDays: int32(r.IntN(MaxSignatureAgeDays + 1)),
			RunningMode: RunningMode(pick(runningModeNames, true))}
	} else {
		out.Defender = UnknownDefender(st)
	}
	out.EDR.State = Availability(pick(availabilityNames, true))
	if out.EDR.State == AvailOK {
		for v := Vendor(1); v < vendorCount; v++ {
			if r.IntN(3) == 0 {
				out.EDR.Agents = append(out.EDR.Agents, EDRAgent{Vendor: v, Running: r.IntN(2) == 0})
			}
		}
		r.Shuffle(len(out.EDR.Agents), func(i, j int) { out.EDR.Agents[i], out.EDR.Agents[j] = out.EDR.Agents[j], out.EDR.Agents[i] })
	}
	out.BitLocker = VolumeProtection(pick(volumeNames, true))
	out.FirewallProfilesOn = int8(r.IntN(5) - 1)
	out.DriverBlocklist = BlocklistState(pick(blocklistNames, true))
	out.MemoryIntegrity = Toggle(pick(toggleNames, true))
	return out
}

// The adversarial privacy test: across the whole vocabulary, no statement
// the builder produces contains a string that is not an allowlisted enum
// value or a fixed-format protocol value.
func TestNoForbiddenStringsAcrossVocabulary(t *testing.T) {
	s := newTestSigner(t)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 500; i++ {
		h := testHeader(uint32(1 + rng.IntN(1<<31-1)))
		sh := SensorHealth{SensorRunning: rng.IntN(2) == 0, TamperDetected: rng.IntN(2) == 0,
			DriverBlocklistVersion: rng.Uint64N(MaxVersion + 1), PolicyVersion: rng.Uint64N(MaxVersion + 1)}
		rd := randomReadings(rng)
		payload, err := BuildStatement(s.Public(), h, sh, rd)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		obj, err := ParseCanonicalObject(payload)
		if err != nil {
			t.Fatal(err)
		}
		if bad := forbiddenStrings(obj, "", ""); len(bad) != 0 {
			t.Fatalf("case %d: forbidden strings %v", i, bad)
		}
		if _, err := ValidateStatement(payload); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}

// The walker must actually catch smuggled text; otherwise the test above
// proves nothing.
func TestWalkerCatchesSmuggledText(t *testing.T) {
	s := newTestSigner(t)
	payload, err := BuildStatement(s.Public(), testHeader(1), testSensor, healthyReadings())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(o map[string]any){
		"hostname field": func(o map[string]any) { pred(o)["hostname"] = "MARIA-LAPTOP" },
		"path in enum":   func(o map[string]any) { checksOf(o)["memory_integrity"] = `C:\Users\maria\taxes.pdf` },
		"name as vendor": func(o map[string]any) {
			checksOf(o)["edr"].(map[string]any)["agents"].([]any)[0].(map[string]any)["vendor"] = "maria@example.com"
		},
		"text as nonce": func(o map[string]any) { pred(o)["nonce"] = "front desk pc" },
	} {
		obj, _ := ParseCanonicalObject(payload)
		mutate(obj)
		if bad := forbiddenStrings(obj, "", ""); len(bad) == 0 {
			t.Errorf("%s: walker found nothing", name)
		}
	}
}

func pred(o map[string]any) map[string]any     { return o["predicate"].(map[string]any) }
func checksOf(o map[string]any) map[string]any { return pred(o)["protection"].(map[string]any) }

func TestBuilderRefusesValuesOutsideTheVocabulary(t *testing.T) {
	s := newTestSigner(t)
	cases := map[string]func(h *Header, r *Readings, p *SensorHealth){
		"vendor 200":             func(h *Header, r *Readings, p *SensorHealth) { r.EDR.Agents = []EDRAgent{{Vendor: 200}} },
		"vendor zero":            func(h *Header, r *Readings, p *SensorHealth) { r.EDR.Agents = []EDRAgent{{Vendor: 0}} },
		"toggle 9":               func(h *Header, r *Readings, p *SensorHealth) { r.MemoryIntegrity = 9 },
		"availability 7":         func(h *Header, r *Readings, p *SensorHealth) { r.EDR.State = 7 },
		"running mode 99":        func(h *Header, r *Readings, p *SensorHealth) { r.Defender.RunningMode = 99 },
		"blocklist version 2^53": func(h *Header, r *Readings, p *SensorHealth) { p.DriverBlocklistVersion = MaxVersion + 1 },
		"policy version max":     func(h *Header, r *Readings, p *SensorHealth) { p.PolicyVersion = 1<<64 - 1 },
		"firewall 4":             func(h *Header, r *Readings, p *SensorHealth) { r.FirewallProfilesOn = 4 },
		"firewall -2":            func(h *Header, r *Readings, p *SensorHealth) { r.FirewallProfilesOn = -2 },
		"enabled > products": func(h *Header, r *Readings, p *SensorHealth) {
			r.SecurityCenter.Enabled = r.SecurityCenter.Products + 1
		},
		"duplicate vendor": func(h *Header, r *Readings, p *SensorHealth) {
			r.EDR.Agents = []EDRAgent{{VendorSophos, true}, {VendorSophos, false}}
		},
		"agents when unknown": func(h *Header, r *Readings, p *SensorHealth) {
			r.EDR.State = AvailUnknown
		},
		"count when n/a": func(h *Header, r *Readings, p *SensorHealth) {
			r.SecurityCenter.State = AvailNotApplicable
		},
		"toggle when unknown": func(h *Header, r *Readings, p *SensorHealth) {
			r.Defender = UnknownDefender(AvailUnknown)
			r.Defender.RealTime = ToggleOn
		},
		"unknown count when ok": func(h *Header, r *Readings, p *SensorHealth) { r.SecurityCenter.Products = -1 },
		"age -2":                func(h *Header, r *Readings, p *SensorHealth) { r.Defender.SignatureAgeDays = -2 },
		"seq zero":              func(h *Header, r *Readings, p *SensorHealth) { h.Seq = 0 },
		"no salt":               func(h *Header, r *Readings, p *SensorHealth) { h.Salt = Salt{} },
		"no nonce":              func(h *Header, r *Readings, p *SensorHealth) { h.Nonce = Nonce{} },
		"no time":               func(h *Header, r *Readings, p *SensorHealth) { h.ObservedAt = time.Time{} },
	}
	for name, mutate := range cases {
		h, r, p := testHeader(1), healthyReadings(), testSensor
		mutate(&h, &r, &p)
		if _, err := BuildStatement(s.Public(), h, p, r); err == nil {
			t.Errorf("%s: builder accepted it", name)
		}
	}
}

// The receiver-side validator refuses statements that a hostile or buggy
// agent could hand-craft, even with a valid signature.
func TestValidatorRefusesHandCraftedStatements(t *testing.T) {
	s := newTestSigner(t)
	other := newTestSigner(t)
	payload, err := BuildStatement(s.Public(), testHeader(1), testSensor, healthyReadings())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(o map[string]any){
		"extra top field":      func(o map[string]any) { o["comment"] = "hi" },
		"extra predicate":      func(o map[string]any) { pred(o)["user"] = "maria" },
		"extra check":          func(o map[string]any) { checksOf(o)["last_file"] = "taxes" },
		"free-text enum":       func(o map[string]any) { checksOf(o)["bitlocker_os_volume"] = "on (C:)" },
		"string as int":        func(o map[string]any) { checksOf(o)["firewall_profiles_on"] = "3" },
		"bool as enum":         func(o map[string]any) { checksOf(o)["memory_integrity"] = true },
		"timestamp offset":     func(o map[string]any) { pred(o)["observed_at"] = "2026-10-26T19:00:00+02:00" },
		"uppercase hex":        func(o map[string]any) { pred(o)["prev"] = strings.Repeat("AB", 32) },
		"short hex":            func(o map[string]any) { pred(o)["nonce"] = "ab" },
		"other device id":      func(o map[string]any) { pred(o)["attester"] = other.Public().DeviceID() },
		"subject mismatch":     func(o map[string]any) { o["subject"].([]any)[0].(map[string]any)["name"] = other.Public().DeviceID() },
		"two subjects":         func(o map[string]any) { o["subject"] = append(o["subject"].([]any), o["subject"].([]any)[0]) },
		"other predicate":      func(o map[string]any) { o["predicateType"] = "https://kovyr.com/attestation/posture/v1" },
		"sensor extra field":   func(o map[string]any) { pred(o)["sensor_health"].(map[string]any)["process"] = "kovyr.exe" },
		"sensor field missing": func(o map[string]any) { delete(pred(o)["sensor_health"].(map[string]any), "policy_version") },
		"sensor version text":  func(o map[string]any) { pred(o)["sensor_health"].(map[string]any)["policy_version"] = "1.2" },
		"agent nonce source":   func(o map[string]any) { pred(o)["nonce_source"] = "agent" },
		"key protection":       func(o map[string]any) { pred(o)["key_protection"] = "software" },
		"old checks name":      func(o map[string]any) { pred(o)["checks"] = pred(o)["protection"]; delete(pred(o), "protection") },
		"unknown agent field": func(o map[string]any) {
			checksOf(o)["edr"].(map[string]any)["agents"].([]any)[0].(map[string]any)["service"] = "Sense"
		},
	}
	for name, mutate := range cases {
		obj, _ := ParseCanonicalObject(payload)
		mutate(obj)
		b, err := EncodeCanonical(obj)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := ValidateStatement(b); err == nil {
			t.Errorf("%s: validator accepted it", name)
		}
	}
	if _, err := ValidateStatement([]byte(base64.StdEncoding.EncodeToString(payload))); err == nil {
		t.Error("accepted base64 text as a statement")
	}
	if _, err := ValidateStatement(append(payload, ' ')); err == nil {
		t.Error("accepted non-canonical bytes")
	}
}

// specSensorHealth is copied verbatim from SPEC.md section 6.4
// (proof-of-protection/engine/SPEC.md). The agent's sensor_health section
// must be exactly this schema.
const specSensorHealth = `{"t":"object","fields":{
  "sensor_running":           {"t":"bool"},
  "tamper_detected":          {"t":"bool"},
  "driver_blocklist_version": {"t":"int","min":0,"max":9007199254740991},
  "policy_version":           {"t":"int","min":0,"max":9007199254740991}}}`

// specJSON renders a spec in the engine's schema language (only the parts
// sensor_health uses).
func specJSON(s *spec) map[string]any {
	out := map[string]any{"t": s.t}
	switch s.t {
	case "int":
		out["min"], out["max"] = float64(s.min), float64(s.max)
	case "object":
		f := map[string]any{}
		for k, v := range s.fields {
			f[k] = specJSON(v)
		}
		out["fields"] = f
	}
	return out
}

func TestSensorHealthIsExactlySpecSection6_4(t *testing.T) {
	var want map[string]any
	if err := json.Unmarshal([]byte(specSensorHealth), &want); err != nil {
		t.Fatal(err)
	}
	if got := specJSON(sensorHealthSpec()); !reflect.DeepEqual(got, want) {
		t.Fatalf("sensor_health schema differs from SPEC 6.4:\n got %v\nwant %v", got, want)
	}
	if got := predicateSpec().fields["sensor_health"]; !reflect.DeepEqual(specJSON(got), want) {
		t.Fatal("the predicate does not use the SPEC 6.4 sensor_health section")
	}
	// The posture/v1 common fields keep SPEC 6.2's names and formats.
	p := predicateSpec().fields
	for name, typ := range map[string]string{"attester": "id", "attester_kind": "enum", "seq": "int",
		"prev": "hex", "nonce": "hex", "salt": "hex", "observed_at": "timestamp"} {
		if p[name] == nil || p[name].t != typ {
			t.Errorf("common field %s missing or not %s", name, typ)
		}
	}
	if p["nonce"].n != 32 || p["prev"].n != 64 || p["salt"].n != 64 || p["seq"].min != 1 || p["seq"].max != 1<<31-1 {
		t.Error("common field formats differ from SPEC 6.2")
	}
}
