package posture

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

func testKeys(t *testing.T) (tenant, device sigs.Signer) {
	t.Helper()
	a, _ := sigs.GenerateKey(sigs.ES256)
	b, _ := sigs.GenerateKey(sigs.ES256)
	tenant, _ = sigs.NewSigner(a)
	device, _ = sigs.NewSigner(b)
	return
}

func goodDevice() DeviceChecks {
	return DeviceChecks{
		DiskEncryption: EncryptionOn, OSPatch: PatchCurrent, FirewallOn: true,
		ScreenLockOn: true, ScreenLockMaxIdleMin: 10, EDRRunning: true, EDRKind: EDRDefender,
		LocalAdminCount: 1, HeartbeatIntervalS: 300, Heartbeats24h: 288,
	}
}

func header(tenant, device sigs.Signer) Header {
	return Header{
		TenantKey: tenant.Public(), Attester: device.Public(), Kind: DeviceAgent, Seq: 3,
		Prev: sha256.Sum256([]byte("prev")), Nonce: Nonce{0xab, 0xcd, 0xef}, Salt: Salt{0xfe, 9, 9},
		ObservedAt: time.Date(2026, 10, 14, 14, 5, 0, 0, time.UTC),
	}
}

func TestBuildAndValidateDevice(t *testing.T) {
	tenant, device := testKeys(t)
	payload, err := BuildDevice(header(tenant, device), goodDevice())
	if err != nil {
		t.Fatal(err)
	}
	st, err := Validate(payload)
	if err != nil {
		t.Fatal(err)
	}
	if st.Str("device.disk_encryption") != "on" || st.Int("seq") != 3 || st.Str("attester") != AttesterID(DeviceAgent, device.Public()) {
		t.Fatalf("unexpected statement %+v", st.Predicate)
	}
}

// Every string a statement can contain must have one of these fixed
// shapes. This is an independent check on the builder's output, written
// without reference to the schema walker.
var allowedString = regexp.MustCompile(`^(` +
	`[a-z0-9_]+|[A-Z]+-[0-9]{2}|` + // enum values and stable check IDs
	`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|` + // timestamps
	`[0-9a-f]{32}|[0-9a-f]{64}|` + // nonces, salts, digests
	`(tnt|dev|con|stf)_[0-9a-f]{16}|` + // key-derived identifiers
	`[A-Za-z0-9+/]+={0,2}|` + // base64 public keys
	`https://[A-Za-z0-9./-]+|ecdsa-p256-sha256` + // fixed URIs and algorithm names
	`)$`)

func walkStrings(v any, f func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			f(k)
			walkStrings(e, f)
		}
	case []any:
		for _, e := range x {
			walkStrings(e, f)
		}
	case string:
		f(x)
	}
}

func TestBuilderOutputHasOnlyFixedFormatStrings(t *testing.T) {
	tenant, device := testKeys(t)
	d := goodDevice()
	d.UnapprovedRemoteTools = []Count[RemoteTool]{{"anydesk", 2}, {"teamviewer", 1}, {"vnc", 1}, {"rustdesk", 1}, {"splashtop", 3}}
	payload, err := BuildDevice(header(tenant, device), d)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := canon.Parse(payload)
	walkStrings(v, func(s string) {
		if !allowedString.MatchString(s) {
			t.Errorf("unexpected string shape %q", s)
		}
	})
	// The cap kept the four most frequent tools and said so.
	st, _ := Validate(payload)
	tools := st.Get("device.unapproved_remote_tools").(map[string]any)
	if tools["truncated"] != true || tools["total"] != int64(8) || len(tools["items"].([]any)) != RemoteToolsMaxItems {
		t.Fatalf("counted list not capped correctly: %v", tools)
	}
}

func TestBuilderRejectsSmuggledText(t *testing.T) {
	tenant, device := testKeys(t)
	h := header(tenant, device)
	cases := map[string]func(*DeviceChecks){
		"path as enum":      func(d *DeviceChecks) { d.DiskEncryption = `C:\Users\maria\Documents\client-ssn.xlsx` },
		"product name":      func(d *DeviceChecks) { d.EDRKind = "CrowdStrike Falcon on MARIA-LAPTOP" },
		"case variant enum": func(d *DeviceChecks) { d.DiskEncryption = "On" },
		"padded enum":       func(d *DeviceChecks) { d.OSPatch = "current " },
		"homoglyph enum":    func(d *DeviceChecks) { d.DiskEncryption = "\u03bfn" },
		"tool with path": func(d *DeviceChecks) {
			d.UnapprovedRemoteTools = []Count[RemoteTool]{{`anydesk \\fileserver\share`, 1}}
		},
		"out of range": func(d *DeviceChecks) { d.ScreenLockMaxIdleMin = 5000 },
	}
	for name, mutate := range cases {
		d := goodDevice()
		mutate(&d)
		if _, err := BuildDevice(h, d); err == nil {
			t.Errorf("%s: builder accepted it", name)
		}
	}
	if _, err := BuildStaffEvent(Header{Kind: StaffAttester}, StaffEvent{}); err == nil {
		t.Error("empty staff event accepted")
	}
	noSalt := h
	noSalt.Salt = Salt{}
	if _, err := BuildDevice(noSalt, goodDevice()); err == nil {
		t.Error("statement without salt accepted")
	}
}

// The adversarial validator test: take a valid statement, then try every
// way we could think of to sneak a file name, path, host name, user name or
// free text past the validator.
func TestValidatorRejectsForbiddenContent(t *testing.T) {
	tenant, device := testKeys(t)
	payload, _ := BuildDevice(header(tenant, device), goodDevice())
	type mut func(st, pred, dev map[string]any)
	cases := map[string]mut{
		"hostname field":    func(_, _, d map[string]any) { d["hostname"] = "MARIA-LAPTOP" },
		"path field":        func(_, _, d map[string]any) { d["path"] = `C:\Users\maria\Documents\client-ssn.xlsx` },
		"username field":    func(_, p, _ map[string]any) { p["username"] = "maria" },
		"free text note":    func(_, p, _ map[string]any) { p["note"] = "Maria said she turned it off" },
		"top-level comment": func(s, _, _ map[string]any) { s["comment"] = "x" },
		"path in enum":      func(_, _, d map[string]any) { d["disk_encryption"] = `C:\Users\maria` },
		"padded enum":       func(_, _, d map[string]any) { d["disk_encryption"] = "on " },
		"case enum":         func(_, _, d map[string]any) { d["disk_encryption"] = "ON" },
		"string bool":       func(_, _, d map[string]any) { d["firewall_on"] = "true" },
		"array bool":        func(_, _, d map[string]any) { d["firewall_on"] = []any{true} },
		"object in enum":    func(_, _, d map[string]any) { d["edr_kind"] = map[string]any{"name": "CrowdStrike"} },
		"float count":       func(_, _, d map[string]any) { d["local_admin_count"] = 1.5 },
		"huge count":        func(_, _, d map[string]any) { d["local_admin_count"] = int64(99999) },
		"negative count":    func(_, _, d map[string]any) { d["heartbeats_24h"] = int64(-1) },
		"null value":        func(_, _, d map[string]any) { d["edr_running"] = nil },
		"case-variant key": func(_, _, d map[string]any) {
			d["Disk_Encryption"] = d["disk_encryption"]
			delete(d, "disk_encryption")
		},
		"proto key":              func(_, _, d map[string]any) { d["__proto__"] = map[string]any{"admin": true} },
		"hostname as subject":    func(s, _, _ map[string]any) { s["subject"].([]any)[0].(map[string]any)["name"] = "MARIA-LAPTOP" },
		"hostname in id":         func(_, p, _ map[string]any) { p["attester"] = "dev_MARIA-LAPTOP-0001" },
		"hex-looking text id":    func(_, p, _ map[string]any) { p["tenant"] = "tnt_deadbeefcafe" },
		"uppercase nonce":        func(_, p, _ map[string]any) { p["nonce"] = strings.ToUpper(p["nonce"].(string)) },
		"missing salt":           func(_, p, _ map[string]any) { delete(p, "salt") },
		"zoned timestamp":        func(_, p, _ map[string]any) { p["observed_at"] = "2026-10-14T10:05:00-04:00" },
		"fractional timestamp":   func(_, p, _ map[string]any) { p["observed_at"] = "2026-10-14T14:05:00.5Z" },
		"wrong section for kind": func(_, p, d map[string]any) { p["tenant_posture"] = d; delete(p, "device") },
		"extra section":          func(_, p, d map[string]any) { p["tenant_posture"] = d },
		"unknown predicate":      func(s, _, _ map[string]any) { s["predicateType"] = "https://example.com/anything/v1" },
		"tool name with path": func(_, _, d map[string]any) {
			d["unapproved_remote_tools"] = map[string]any{"items": []any{map[string]any{"count": int64(1), "kind": `AnyDesk C:\Tools`}}, "total": int64(1), "truncated": false}
		},
		"extra field in list item": func(_, _, d map[string]any) {
			d["unapproved_remote_tools"] = map[string]any{"items": []any{map[string]any{"count": int64(1), "kind": "anydesk", "path": `C:\Tools\AnyDesk.exe`}}, "total": int64(1), "truncated": false}
		},
		"list total mismatch": func(_, _, d map[string]any) {
			d["unapproved_remote_tools"] = map[string]any{"items": []any{map[string]any{"count": int64(1), "kind": "anydesk"}}, "total": int64(5), "truncated": false}
		},
		"list unsorted": func(_, _, d map[string]any) {
			d["unapproved_remote_tools"] = map[string]any{"items": []any{map[string]any{"count": int64(1), "kind": "vnc"}, map[string]any{"count": int64(1), "kind": "anydesk"}}, "total": int64(2), "truncated": false}
		},
		"list over cap": func(_, _, d map[string]any) {
			var items []any
			for _, k := range remoteToolKinds[:5] {
				items = append(items, map[string]any{"count": int64(1), "kind": k})
			}
			d["unapproved_remote_tools"] = map[string]any{"items": items, "total": int64(5), "truncated": false}
		},
	}
	for name, mutate := range cases {
		v, _ := canon.Parse(payload)
		st := v.(map[string]any)
		pred := st["predicate"].(map[string]any)
		mutate(st, pred, pred["device"].(map[string]any))
		if _, err := ValidateValue(st); err == nil {
			t.Errorf("%s: validator accepted it", name)
		}
		// The same object, if it can be encoded at all, is also rejected
		// when it arrives as bytes.
		if b, err := canon.Encode(st); err == nil {
			if _, err := Validate(b); err == nil {
				t.Errorf("%s: validator accepted the encoded form", name)
			}
		}
	}

	// Byte-level tricks the canonical parser must catch.
	raw := string(payload)
	for name, bad := range map[string]string{
		"duplicate key": strings.Replace(raw, `"firewall_on":true`, `"firewall_on":true,"firewall_on":false`, 1),
		"escaped text":  strings.Replace(raw, `"disk_encryption":"on"`, `"disk_encryption":"o\u006e"`, 1),
		"whitespace":    strings.Replace(raw, `"seq":3`, `"seq": 3`, 1),
		"float":         strings.Replace(raw, `"seq":3`, `"seq":3.0`, 1),
	} {
		if bad == raw {
			t.Fatalf("%s: test replacement did not apply", name)
		}
		if _, err := Validate([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTenantPostureRules(t *testing.T) {
	tenant, _ := testKeys(t)
	cs, _ := sigs.GenerateKey(sigs.Ed25519)
	conn, _ := sigs.NewSigner(cs)
	h := header(tenant, conn)
	h.Kind = CloudConnector
	tp := TenantPosture{AccountsTotal: 11, AccountsMFA: 11, AccountsPasskey: 6, AdminAccounts: 2, DevicesKnown: 12, DevicesEnrolled: 12,
		MailboxAlerts24h: []Count[MailboxAlert]{{"forwarding_rule_external", 1}}, MailboxAlertsOpen: 1}
	if _, err := BuildTenantPosture(h, tp); err != nil {
		t.Fatal(err)
	}
	tp.AccountsMFA = 12
	if _, err := BuildTenantPosture(h, tp); err == nil {
		t.Fatal("more MFA accounts than accounts accepted")
	}
}

func TestEnrollmentStatements(t *testing.T) {
	tenant, device := testKeys(t)
	at := time.Date(2026, 9, 29, 16, 0, 0, 0, time.UTC)
	g, err := BuildTenantGenesis(tenant.Public(), sha256.Sum256([]byte("c")), at, Nonce{1}, Salt{1})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := Validate(g); err != nil || st.Str("tenant_key") != base64.StdEncoding.EncodeToString(tenant.Public().SPKI) {
		t.Fatalf("genesis: %v", err)
	}
	info := EnrollmentInfo{Kind: DeviceAgent, KeyProtection: "software", KeyAttestation: "none", Method: "enrollment_code",
		DeviceClass: "laptop", Platform: "windows", DeviceNumber: 7, StaffRole: "none"}
	if _, err := BuildAttesterEnrollment(tenant.Public(), device.Public(), info, at, Nonce{2}, Salt{2}); err != nil {
		t.Fatal(err)
	}
	info.Platform = "Windows 11 Pro on MARIA-LAPTOP"
	if _, err := BuildAttesterEnrollment(tenant.Public(), device.Public(), info, at, Nonce{2}, Salt{2}); err == nil {
		t.Fatal("free-text platform accepted")
	}
}

func TestDecodeRejectsTruncatedInput(t *testing.T) {
	tenant, device := testKeys(t)
	payload, _ := BuildDevice(header(tenant, device), goodDevice())
	st, _ := Validate(payload)
	dev := st.Get("device").(map[string]any)
	if _, err := DecodeDeviceChecks(dev); err != nil {
		t.Fatal(err)
	}
	dev["serial_number"] = "PF3ABCDE"
	if _, err := DecodeDeviceChecks(dev); err == nil {
		t.Fatal("decoder accepted an extra field")
	}
}

func TestScanStatements(t *testing.T) {
	tenant, _ := testKeys(t)
	cs, _ := sigs.GenerateKey(sigs.Ed25519)
	svc, _ := sigs.NewSigner(cs)
	h := header(tenant, svc)
	h.Kind = ExternalScanner
	r := ScanResults{Results: []ScanResult{{"TLS-01", "pass", "info"}, {"EMAIL-04", "warn", "medium"}, {"EMAIL-01", "pass", "info"}}}
	payload, err := BuildScan(h, r)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Validate(payload)
	if err != nil {
		t.Fatal(err)
	}
	items := st.Get("scan.results.items").([]any)
	if len(items) != 3 || items[0].(map[string]any)["check_id"] != "EMAIL-01" || !strings.HasPrefix(st.Str("attester"), PrefixScanner) {
		t.Fatalf("unexpected scan statement %v", st.Predicate)
	}
	for name, bad := range map[string]ScanResults{
		"domain as check id": {Results: []ScanResult{{"maplestreettax.example", "pass", "info"}}},
		"free-text status":   {Results: []ScanResult{{"TLS-01", "expires in 9 days", "info"}}},
		"duplicate check":    {Results: []ScanResult{{"TLS-01", "pass", "info"}, {"TLS-01", "fail", "high"}}},
	} {
		if _, err := BuildScan(h, bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	v, _ := canon.Parse(payload)
	scan := v.(map[string]any)["predicate"].(map[string]any)["scan"].(map[string]any)
	scan["domain"] = "maplestreettax.example"
	if _, err := ValidateValue(v.(map[string]any)); err == nil {
		t.Fatal("domain field accepted")
	}
}
