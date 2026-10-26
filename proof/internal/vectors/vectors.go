// Package vectors generates the cross-language test vectors in
// testdata/vectors. Every key is derived from a fixed seed and every
// signature is deterministic (Ed25519, and ECDSA with RFC 6979 nonces), so
// the files regenerate byte for byte. Other implementations (the browser
// verifier, a Python or Rust client) must reproduce the canonical bytes and
// hashes and must accept and reject exactly what these files say.
package vectors

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/brand"
	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
	"github.com/kendallcoding202/kovyr-edr/proof/pack"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tlog"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
	"github.com/kendallcoding202/kovyr-edr/proof/witness"
)

func seed(label string) []byte {
	s := sha256.Sum256([]byte("proof-test-vector-key/v1\n" + label))
	return s[:]
}

// Ed25519Key derives a deterministic Ed25519 test key.
func Ed25519Key(label string) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed(label)) }

// P256Key derives a deterministic P-256 test key.
func P256Key(label string) *ecdsa.PrivateKey {
	d := seed(label)
	for {
		if k, err := ecdh.P256().NewPrivateKey(d); err == nil {
			pub := k.PublicKey().Bytes() // 0x04 || X || Y
			return &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pub[1:33]), Y: new(big.Int).SetBytes(pub[33:])},
				D:         new(big.Int).SetBytes(d),
			}
		}
		h := sha256.Sum256(d)
		d = h[:]
	}
}

func signer(k any) sigs.Signer {
	var s sigs.Signer
	var err error
	switch x := k.(type) {
	case ed25519.PrivateKey:
		s, err = sigs.NewSigner(x)
	case *ecdsa.PrivateKey:
		s, err = sigs.NewSigner(x)
	}
	if err != nil {
		panic(err)
	}
	return s
}

func keyVector(k any) map[string]any {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	s := signer(k)
	return map[string]any{"alg": string(s.Public().Alg), "pkcs8": b64(der), "spki": s.Public().Base64(), "keyid": s.Public().KeyID()}
}

func b64(b []byte) string     { return base64.StdEncoding.EncodeToString(b) }
func hexs(b []byte) string    { return hex.EncodeToString(b) }
func hh(h merkle.Hash) string { return b64(h[:]) }

func hashList(hs []merkle.Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = hh(h)
	}
	return out
}

func pretty(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	_ = e.Encode(v)
	return b.Bytes()
}

// Generate returns file name -> contents.
func Generate() (map[string][]byte, error) {
	files := map[string][]byte{}
	gens := map[string]func() (any, error){
		"canonicalization.json": canonVectors,
		"dsse.json":             dsseVectors,
		"merkle.json":           merkleVectors,
		"note.json":             noteVectors,
		"statement.json":        statementVectors,
	}
	for name, g := range gens {
		v, err := g()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		files[name] = pretty(v)
	}
	mp, trust, expect, err := miniPack()
	if err != nil {
		return nil, fmt.Errorf("mini pack: %w", err)
	}
	files["mini-pack.json"] = mp
	files["mini-trust-policy.json"] = trust
	files["mini-pack-expected.json"] = pretty(expect)
	schema, _ := posture.SchemaJSON()
	files["posture-schema.json"] = append(schema, '\n')
	files["README.md"] = []byte(readme)
	return files, nil
}

func canonVectors() (any, error) {
	type valid struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
		SHA256    string `json:"sha256"`
	}
	type invalid struct {
		Name  string `json:"name"`
		Input string `json:"input"`
		Why   string `json:"why"`
	}
	var vs []valid
	for _, c := range [][2]string{
		{"sorted keys, no whitespace", `{ "b": 2, "a": [true, false], "_c": {"z": -7, "y": ""} }`},
		{"nested arrays", `[[1,[2,[3]]],{"k":"v"}]`},
		{"key order is byte order", `{"b":1,"B":2,"a":3,"_":4,"0":5}`},
		{"largest safe integers", `{"max":9007199254740991,"min":-9007199254740991}`},
		{"printable ASCII", `{"s":"A-z 0-9 !#$%&'()*+,-./:;<=>?@[]^_{|}~"}`},
	} {
		out, err := canon.Canonicalize([]byte(c[1]))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c[0], err)
		}
		h := sha256.Sum256(out)
		vs = append(vs, valid{c[0], c[1], string(out), hexs(h[:])})
	}
	var notCanon []invalid
	for _, c := range [][3]string{
		{"whitespace", `{"a": 1}`, "insignificant whitespace"},
		{"unsorted", `{"b":1,"a":2}`, "keys out of order"},
		{"escape", `{"a":"\u0041"}`, "escape sequence"},
		{"trailing newline", "{\"a\":1}\n", "bytes after the value"},
	} {
		if _, err := canon.Parse([]byte(c[1])); err == nil {
			return nil, fmt.Errorf("%s accepted", c[0])
		}
		notCanon = append(notCanon, invalid{c[0], c[1], c[2]})
	}
	var never []invalid
	for _, c := range [][3]string{
		{"duplicate key", `{"a":1,"a":1}`, "duplicate key"},
		{"float", `{"a":1.0}`, "non-integer number"},
		{"exponent", `{"a":1e2}`, "non-integer number"},
		{"null", `{"a":null}`, "null"},
		{"unsafe integer", `{"a":9007199254740992}`, "outside +-(2^53-1)"},
		{"non-ascii string", `{"a":"é"}`, "outside printable ASCII"},
		{"control character", "{\"a\":\"\t\"}", "control character"},
		{"quote in string", `{"a":"\""}`, "quote cannot appear in canonical strings"},
	} {
		if _, err := canon.Parse([]byte(c[1])); err == nil {
			return nil, fmt.Errorf("%s accepted", c[0])
		}
		never = append(never, invalid{c[0], c[1], c[2]})
	}
	return map[string]any{
		"version":                      canon.Version,
		"canonicalize":                 vs,
		"reject_as_canonical":          notCanon,
		"reject_in_signed_data_always": never,
	}, nil
}

func dsseVectors() (any, error) {
	payload := []byte(`{"hello":"world"}`)
	pae := dsse.PAE(dsse.PayloadTypeInToto, payload)
	ed, p := Ed25519Key("dsse-ed25519"), P256Key("dsse-p256")
	var sigsOut []any
	for _, k := range []any{ed, p} {
		s := signer(k)
		env, err := dsse.Sign(dsse.PayloadTypeInToto, payload, s)
		if err != nil {
			return nil, err
		}
		if err := env.VerifySignature(0, s.Public()); err != nil {
			return nil, err
		}
		sigsOut = append(sigsOut, map[string]any{
			"key": keyVector(k), "envelope_canonical": string(env.Canonical()), "sig": b64(env.Signatures[0].Sig),
		})
	}
	ps := signer(p)
	good, _ := ps.Sign(pae)
	der, _ := sigs.ECDSAToDER(good)
	bad := append([]byte(nil), good...)
	bad[10] ^= 1
	neg := []any{
		map[string]any{"name": "ES256 high-S twin (r, n-s)", "spki": ps.Public().Base64(), "sig": b64(sigs.HighS(good)), "why": "high S is rejected so each statement has one signature encoding"},
		map[string]any{"name": "ES256 signature in DER", "spki": ps.Public().Base64(), "sig": b64(der), "why": "envelopes carry IEEE P1363 r||s; convert DER before signing"},
		map[string]any{"name": "ES256 corrupted", "spki": ps.Public().Base64(), "sig": b64(bad), "why": "does not verify"},
	}
	for _, n := range neg {
		m := n.(map[string]any)
		pk, _ := sigs.ParsePublicKeyBase64(m["spki"].(string))
		sb, _ := base64.StdEncoding.DecodeString(m["sig"].(string))
		if pk.Verify(pae, sb) == nil {
			return nil, fmt.Errorf("negative vector %s verified", m["name"])
		}
	}
	return map[string]any{
		"payload_type": dsse.PayloadTypeInToto, "payload": b64(payload), "pae_hex": hexs(pae),
		"signatures": sigsOut, "must_reject": neg,
		"notes": "ES256 signs SHA-256(PAE) and encodes r||s big-endian (64 bytes) with s <= n/2. keyid = hex(SHA-256(SPKI DER)).",
	}, nil
}

func merkleVectors() (any, error) {
	leaves := []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}
	t := merkle.NewTree()
	var leafHashes []string
	for _, l := range leaves {
		b, _ := hex.DecodeString(l)
		h := merkle.LeafHash(b)
		t.Append(h)
		leafHashes = append(leafHashes, hexs(h[:]))
	}
	var roots []string
	for n := uint64(1); n <= t.Size(); n++ {
		r, _ := t.Root(n)
		roots = append(roots, hexs(r[:]))
	}
	var incl, cons []any
	for _, c := range [][2]uint64{{0, 1}, {0, 8}, {5, 8}, {2, 3}, {6, 7}, {3, 5}} {
		p, _ := t.InclusionProof(c[0], c[1])
		incl = append(incl, map[string]any{"index": c[0], "size": c[1], "proof": hashList(p)})
	}
	for _, c := range [][2]uint64{{1, 1}, {1, 8}, {6, 8}, {2, 5}, {3, 7}, {4, 8}} {
		p, _ := t.ConsistencyProof(c[0], c[1])
		cons = append(cons, map[string]any{"from": c[0], "to": c[1], "proof": hashList(p)})
	}
	return map[string]any{
		"about":      "RFC 6962 reference leaves (hex). leaf_hash = SHA-256(0x00||leaf); node = SHA-256(0x01||l||r). Proof hashes are base64.",
		"leaves_hex": leaves, "leaf_hashes_hex": leafHashes, "roots_hex_by_size": roots,
		"inclusion": incl, "consistency": cons, "empty_root_hex": func() string { e := merkle.EmptyRoot(); return hexs(e[:]) }(),
	}, nil
}

func noteVectors() (any, error) {
	logKey, wKey := Ed25519Key("note-log"), Ed25519Key("note-witness")
	origin, wname := "example.com/proof-vectors-log", "witness.example"
	root := merkle.LeafHash([]byte("vector"))
	body := note.Checkpoint{Origin: origin, Size: 12, Root: root}.Body()
	signed, err := note.Sign(body, origin, logKey)
	if err != nil {
		return nil, err
	}
	n, _ := note.Parse(signed)
	const t = 1793232000 // 2026-10-29T00:00:00Z
	line := note.Cosign(n.Text, wname, wKey, t)
	n.AddSigLine(line)
	return map[string]any{
		"c2sp_signed_note_example": map[string]any{
			"vkey": "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
			"note": "This is an example message.\n\n\u2014 example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n",
		},
		"log_key_seed_hex":     hexs(seed("note-log")),
		"log_vkey":             note.FormatVKey(origin, note.TypeEd25519, logKey.Public().(ed25519.PublicKey)),
		"checkpoint_body":      body,
		"signed_checkpoint":    signed,
		"witness_key_seed_hex": hexs(seed("note-witness")),
		"witness_vkey":         note.FormatVKey(wname, note.TypeCosignature, wKey.Public().(ed25519.PublicKey)),
		"cosignature_time":     t,
		"cosigned_message":     string(note.CosignatureMessage(n.Text, t)),
		"cosigned_checkpoint":  n.String(),
		"notes":                "Log key ID = SHA-256(name||0x0A||0x01||key)[:4]; witness key ID uses type 0x04; the cosignature line encodes keyID||time(8 bytes BE)||signature.",
	}, nil
}

func fixedHeader(tenant, dev sigs.Signer, seq uint32, at time.Time) posture.Header {
	var h posture.Header
	h.TenantKey, h.Attester, h.Kind, h.Seq, h.ObservedAt = tenant.Public(), dev.Public(), posture.DeviceAgent, seq, at
	copy(h.Prev[:], seed("prev"))
	copy(h.Nonce[:], seed("nonce"))
	copy(h.Salt[:], seed("salt"))
	return h
}

func statementVectors() (any, error) {
	tenant, dev := signer(P256Key("stmt-tenant")), signer(P256Key("stmt-device"))
	at := time.Date(2026, 10, 14, 14, 5, 12, 0, time.UTC)
	checks := posture.DeviceChecks{DiskEncryption: posture.EncryptionOff, OSPatch: posture.PatchPending, FirewallOn: true, ScreenLockOn: true,
		ScreenLockMaxIdleMin: 10, EDRRunning: false, EDRKind: posture.EDRDefender, LocalAdminCount: 1, HeartbeatIntervalS: 300, Heartbeats24h: 7,
		UnapprovedRemoteTools: []posture.Count[posture.RemoteTool]{{Kind: "anydesk", N: 1}}}
	payload, err := posture.BuildDevice(fixedHeader(tenant, dev, 12, at), checks)
	if err != nil {
		return nil, err
	}
	env, err := posture.Sign(payload, dev)
	if err != nil {
		return nil, err
	}
	digest := tlog.EntryDigest(env)
	leaf := tlog.LeafHash(digest)
	chain := posture.PayloadDigest(payload)
	ts := signer(Ed25519Key("stmt-tsa"))
	auth, _ := tsa.NewSimulated("tsa-vector.example", ts, func() time.Time { return at.Add(11 * time.Second) }, 0)
	tok, _ := auth.Timestamp(context.Background(), digest)
	tstMsg, _ := tsa.SimulatedMessage(tok["tst"].(map[string]any))
	var rejects []any
	for _, c := range []struct{ name, from, to string }{
		{"host name smuggled in", `"heartbeats_24h":7`, `"heartbeats_24h":7,"hostname":"MARIA-LAPTOP"`},
		{"path in an enum", `"disk_encryption":"off"`, `"disk_encryption":"C:/Users/maria"`},
		{"boolean as string", `"firewall_on":true`, `"firewall_on":"true"`},
		{"float count", `"local_admin_count":1`, `"local_admin_count":1.0`},
		{"unknown predicate field", `"seq":12`, `"note":"free text","seq":12`},
	} {
		bad := bytes.Replace(payload, []byte(c.from), []byte(c.to), 1)
		if bytes.Equal(bad, payload) {
			return nil, fmt.Errorf("replacement %q did not apply", c.name)
		}
		if _, err := posture.Validate(bad); err == nil {
			return nil, fmt.Errorf("%s accepted", c.name)
		}
		rejects = append(rejects, map[string]any{"name": c.name, "payload": string(bad)})
	}
	scanner := signer(Ed25519Key("stmt-scanner"))
	sh := fixedHeader(tenant, scanner, 3, at)
	sh.Kind = posture.ExternalScanner
	scanPayload, err := posture.BuildScan(sh, posture.ScanResults{Results: []posture.ScanResult{
		{CheckID: "TLS-01", Status: "pass", Severity: "info"}, {CheckID: "EMAIL-04", Status: "warn", Severity: "medium"}}})
	if err != nil {
		return nil, err
	}
	scanEnv, _ := posture.Sign(scanPayload, scanner)
	badScan := bytes.Replace(scanPayload, []byte(`"source":"external_scan"`), []byte(`"domain":"maplestreet.example","source":"external_scan"`), 1)
	if _, err := posture.Validate(badScan); err == nil {
		return nil, fmt.Errorf("scan with a domain accepted")
	}
	rejects = append(rejects, map[string]any{"name": "domain name in a scan statement", "payload": string(badScan)})
	return map[string]any{
		"scan_payload_canonical":  string(scanPayload),
		"scan_envelope_canonical": string(scanEnv.Canonical()),
		"scanner_key":             keyVector(Ed25519Key("stmt-scanner")),
		"predicate_type":          brand.PredicatePosture,
		"tenant_key":              keyVector(P256Key("stmt-tenant")),
		"device_key":              keyVector(P256Key("stmt-device")),
		"payload_canonical":       string(payload),
		"payload_sha256_hex":      hexs(chain[:]),
		"envelope_canonical":      string(env.Canonical()),
		"entry_digest_hex":        hexs(digest[:]),
		"leaf_hash_hex":           hexs(leaf[:]),
		"timestamp_token":         tok,
		"tsa_key":                 keyVector(Ed25519Key("stmt-tsa")),
		"tsa_signed_message":      string(tstMsg),
		"must_reject_payloads":    rejects,
		"notes": "payload_sha256 is the chain hash the next statement puts in prev. entry_digest = SHA-256(envelope_canonical) is what the public log stores " +
			"and what timestamp authorities sign; leaf_hash = SHA-256(0x00||entry_digest).",
	}, nil
}

// miniPack builds a two-device, three-day pack with one gap, plus a
// tampered copy, and records the outcome every verifier must reach.
func miniPack() ([]byte, []byte, any, error) {
	ctx := context.Background()
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := start.Add(-24 * time.Hour)
	clock := func() time.Time { return now }
	lg, err := tlog.NewLog("example.com/mini-log", Ed25519Key("mini-log"), clock)
	if err != nil {
		return nil, nil, nil, err
	}
	var auths []tsa.Authority
	var tparties []pack.Party
	for i, n := range []string{"tsa-1.example", "tsa-2.example"} {
		s := signer(Ed25519Key("mini-" + n))
		off := time.Duration(i+1) * time.Second
		a, _ := tsa.NewSimulated(n, s, func() time.Time { return now.Add(off) }, 0)
		auths = append(auths, a)
		tparties = append(tparties, pack.Party{Name: n, Kind: tsa.KindSimulated, PublicKey: s.Public().Base64(), Label: n, Simulated: true})
	}
	srv := tlog.NewServer(lg, auths, clock, nil)
	srv.NonceSource = func(subject string, at time.Time) posture.Nonce {
		var n posture.Nonce
		h := sha256.Sum256([]byte(subject + at.String()))
		copy(n[:], h[:])
		return n
	}
	tenant := signer(P256Key("mini-tenant"))
	devs := []sigs.Signer{signer(P256Key("mini-dev-1")), signer(P256Key("mini-dev-2"))}
	salt := func(s string) posture.Salt { return posture.Salt(sha256.Sum256([]byte("salt" + s + now.String()))) }
	submit := func(env *dsse.Envelope) error {
		now = now.Add(10 * time.Second)
		_, err := srv.Submit(ctx, env)
		return err
	}

	nameSalt := hexs(seed("mini-name-salt"))
	tid := posture.TenantID(tenant.Public())
	n, _ := srv.IssueNonce(tid)
	g, err := posture.BuildTenantGenesis(tenant.Public(), pack.NameCommitment("Example Firm (test vector)", nameSalt), now, n, salt("g"))
	if err != nil {
		return nil, nil, nil, err
	}
	env, _ := posture.Sign(g, tenant)
	if err := submit(env); err != nil {
		return nil, nil, nil, err
	}
	prev := map[int]posture.Digest{}
	for i, d := range devs {
		now = now.Add(time.Minute)
		id := posture.AttesterID(posture.DeviceAgent, d.Public())
		n, _ := srv.IssueNonce(id)
		p, err := posture.BuildAttesterEnrollment(tenant.Public(), d.Public(), posture.EnrollmentInfo{Kind: posture.DeviceAgent,
			KeyProtection: "software", KeyAttestation: "none", Method: "enrollment_code", DeviceClass: "laptop", Platform: "windows",
			DeviceNumber: uint16(i + 1), StaffRole: "none"}, now, n, salt(id))
		if err != nil {
			return nil, nil, nil, err
		}
		env, _ := posture.Sign(p, tenant, d)
		if err := submit(env); err != nil {
			return nil, nil, nil, err
		}
		prev[i] = posture.PayloadDigest(p)
	}
	w, _ := witness.New("witness-1.example", Ed25519Key("mini-witness"), clock)
	cosign := func() error {
		signed, err := lg.SignCheckpoint()
		if err != nil {
			return err
		}
		var proof []merkle.Hash
		if seen, ok := w.Seen[lg.Origin()]; ok {
			proof, _ = lg.ConsistencyProof(seen.Size, lg.Size())
		}
		line, err := w.Cosign(signed, lg.VKey(), proof)
		if err != nil {
			return err
		}
		lg.AddCosignature(line)
		return nil
	}
	var earlier string
	seq := map[int]uint32{}
	for day := 0; day < 3; day++ {
		for i, d := range devs {
			if i == 1 && day == 1 {
				continue // device 2 is silent on Oct 2: a gap
			}
			now = start.AddDate(0, 0, day).Add(time.Duration(14*60+i*7) * time.Minute)
			id := posture.AttesterID(posture.DeviceAgent, d.Public())
			n, _ := srv.IssueNonce(id)
			seq[i]++
			h := posture.Header{TenantKey: tenant.Public(), Attester: d.Public(), Kind: posture.DeviceAgent, Seq: seq[i], Prev: prev[i],
				Nonce: n, Salt: salt(id), ObservedAt: now}
			p, err := posture.BuildDevice(h, posture.DeviceChecks{DiskEncryption: "on", OSPatch: "current", FirewallOn: true, ScreenLockOn: true,
				ScreenLockMaxIdleMin: 10, EDRRunning: true, EDRKind: "defender", LocalAdminCount: 1, HeartbeatIntervalS: 300, Heartbeats24h: 288})
			if err != nil {
				return nil, nil, nil, err
			}
			env, _ := posture.Sign(p, d)
			if err := submit(env); err != nil {
				return nil, nil, nil, err
			}
			prev[i] = posture.PayloadDigest(p)
		}
		now = start.AddDate(0, 0, day).Add(23*time.Hour + 50*time.Minute)
		if err := cosign(); err != nil {
			return nil, nil, nil, err
		}
		if day == 0 {
			earlier = lg.Latest()
		}
	}
	trust, err := pack.NewTrustPolicy(lg.Origin(), lg.VKey(), []pack.Party{{Name: w.Name, VKey: w.VKey(), Label: "witness 1", Simulated: true}}, 1, tparties, true)
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := pack.Build(pack.ServerSource{S: srv}, trust, pack.Request{TenantID: tid, DisplayName: "Example Firm (test vector)", DisplayNameSalt: nameSalt,
		From: "2026-10-01", To: "2026-10-03", IssuedAt: start.AddDate(0, 0, 3), Sample: true, Earlier: []string{earlier}})
	if err != nil {
		return nil, nil, nil, err
	}
	r := pack.Verify(p, trust)
	if !r.Verified {
		return nil, nil, nil, fmt.Errorf("mini pack does not verify:\n%s", r.Text())
	}
	steps := map[string]string{}
	for _, s := range r.Steps {
		steps[s.ID] = string(s.Status)
	}
	pb, _ := p.MarshalJSON()
	expect := map[string]any{
		"verified": true, "steps": steps, "summary": p.Summary,
		"tampered": map[string]any{
			"how":          "In the entry at log index 5 (device 1, Oct 2), change disk_encryption \"on\" to \"off\" inside the payload and re-encode it.",
			"entry_index":  5,
			"failed_steps": []string{"signatures", "sequence", "timestamps", "inclusion", "gaps"},
		},
	}
	// Check the tampered outcome so the expectation file cannot drift.
	tp, _ := pack.Parse(pb)
	for _, e := range tp.Entries {
		if e.Evidence.Index == 5 {
			e.Evidence.Envelope.Payload = bytes.Replace(e.Evidence.Envelope.Payload, []byte(`"disk_encryption":"on"`), []byte(`"disk_encryption":"off"`), 1)
		}
	}
	tr := pack.Verify(tp, trust)
	if got := fmt.Sprint(tr.FailedSteps()); got != "[signatures sequence timestamps inclusion gaps]" {
		return nil, nil, nil, fmt.Errorf("tampered mini pack failed %s", got)
	}
	return pb, trust.JSON(), expect, nil
}

const readme = `# Cross-language test vectors

Generated by ` + "`go test ./proof/internal/vectors -run TestVectorsAreUpToDate -update`" + `
(from the kovyr-edr module root). Do not edit; regenerate. Every key is derived from a fixed seed (SHA-256 of
"proof-test-vector-key/v1\n" + label) and every signature is deterministic,
so regenerating produces identical files. ` + "`go test ./...`" + ` fails if they drift.

| File | What an implementation must do |
|---|---|
| canonicalization.json | produce ` + "`canonical`" + ` from ` + "`input`" + `; reject every ` + "`reject_*`" + ` input as signed data |
| dsse.json | reproduce ` + "`pae_hex`" + `; verify each signature; reject each ` + "`must_reject`" + ` signature |
| merkle.json | reproduce leaf hashes and roots; verify each inclusion and consistency proof |
| note.json | verify the C2SP example; verify the checkpoint signature and the witness cosignature |
| statement.json | validate ` + "`payload_canonical`" + `; reproduce the chain hash, entry digest and leaf hash; verify the timestamp token; reject each ` + "`must_reject_payloads`" + ` |
| mini-pack.json + mini-trust-policy.json | verify: every step passes and the summary matches ` + "`mini-pack-expected.json`" + `; after the described tampering exactly the listed steps fail |
| posture-schema.json | the statement schema as data (the same file the browser verifier embeds) |
`
