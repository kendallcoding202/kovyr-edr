package pack_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/internal/sample"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
	"github.com/kendallcoding202/kovyr-edr/proof/pack"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tlog"
)

// The sample world is built once (with fresh random keys) and every test
// works on its own copy of the pack.
var (
	once     sync.Once
	world    *sample.World
	packRaw  []byte
	setupErr error
)

func genuine(t *testing.T) (*sample.World, *pack.Pack) {
	t.Helper()
	once.Do(func() {
		k, err := sample.GenerateKeys()
		if err != nil {
			setupErr = err
			return
		}
		if world, err = sample.Build(ctx, k, sample.Genuine); err != nil {
			setupErr = err
			return
		}
		p, err := world.Pack()
		if err != nil {
			setupErr = err
			return
		}
		packRaw, setupErr = p.MarshalJSON()
	})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	p, err := pack.Parse(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	return world, p
}

func failed(t *testing.T, p *pack.Pack, w *sample.World) (*pack.Report, string) {
	t.Helper()
	r := pack.Verify(p, w.Trust)
	return r, strings.Join(r.FailedSteps(), " ")
}

func expectFailed(t *testing.T, p *pack.Pack, w *sample.World, want string) *pack.Report {
	t.Helper()
	r, got := failed(t, p, w)
	if got != want {
		t.Fatalf("failed steps = %q, want %q\n%s", got, want, r.Text())
	}
	return r
}

// find returns the pack entry for an attester's report on a date.
func find(t *testing.T, p *pack.Pack, deviceNumber int, date string) int {
	t.Helper()
	var attester string
	for _, e := range p.Entries {
		st, _ := posture.Validate(e.Evidence.Envelope.Payload)
		if !st.IsPosture() && st.Str("kind") == "attester" && st.Str("attester_kind") == "device_agent" && st.Int("device_number") == int64(deviceNumber) {
			attester = st.Str("attester")
		}
	}
	for i, e := range p.Entries {
		st, _ := posture.Validate(e.Evidence.Envelope.Payload)
		if st.IsPosture() && st.Str("attester") == attester && strings.HasPrefix(st.Str("observed_at"), date) {
			return i
		}
	}
	t.Fatalf("no report from D%02d on %s", deviceNumber, date)
	return -1
}

func TestGenuinePackVerifiesAndDisclosesTheGap(t *testing.T) {
	w, p := genuine(t)
	r := expectFailed(t, p, w, "")
	gaps := r.Computed["gaps"].([]any)
	if len(gaps) != 1 {
		t.Fatalf("want exactly one gap, got %v", gaps)
	}
	g := gaps[0].(map[string]any)
	if g["device_number"] != int64(7) || g["from"] != "2026-10-12" || g["to"] != "2026-10-13" || g["days"] != int64(2) {
		t.Fatalf("wrong gap %v", g)
	}
	if !strings.Contains(r.Step("gaps").Detail, "Laptop D07 sent no reports Oct 12 to Oct 13 (2 days)") {
		t.Fatalf("gap not described: %s", r.Step("gaps").Detail)
	}
	if r.Step("consistency").Status != pack.Pass || r.Step("witnesses").Status != pack.Pass {
		t.Fatal("log checks did not pass")
	}
}

func TestPackRoundTripAndStrictParsing(t *testing.T) {
	_, p := genuine(t)
	b, _ := p.MarshalJSON()
	if !bytes.Equal(b, packRaw) {
		t.Fatal("pack does not round-trip byte for byte")
	}
	for name, bad := range map[string]string{
		"duplicate key": strings.Replace(string(packRaw), `"sample": true,`, `"sample": true, "sample": false,`, 1),
		"unknown field": strings.Replace(string(packRaw), `"sample": true,`, `"sample": true, "note": "trust me",`, 1),
		"float":         regexp.MustCompile(`"index":(\d+),`).ReplaceAllString(string(packRaw), `"index":$1.0,`),
	} {
		if bad == string(packRaw) {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := pack.Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func setPayload(t *testing.T, e *pack.Entry, mutate func(map[string]any)) {
	t.Helper()
	v, err := canon.Parse(e.Evidence.Envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	mutate(v.(map[string]any)["predicate"].(map[string]any))
	e.Evidence.Envelope.Payload = canon.MustEncode(v)
}

// The sales demo's first tamper: hide the bad day by flipping encryption
// back on. Five independent checks notice.
func TestTamperedValueFails(t *testing.T) {
	w, p := genuine(t)
	i := find(t, p, 7, "2026-10-14")
	setPayload(t, &p.Entries[i], func(pred map[string]any) {
		pred["device"].(map[string]any)["disk_encryption"] = "on"
		pred["device"].(map[string]any)["edr_running"] = true
	})
	r := expectFailed(t, p, w, "signatures sequence timestamps inclusion gaps")
	if !strings.Contains(strings.Join(r.Step("signatures").Problems, " "), "Laptop D07 report #12 (Oct 14): the signature does not match the content") {
		t.Fatalf("unexpected message: %v", r.Step("signatures").Problems)
	}
}

func TestSignatureForgeryFails(t *testing.T) {
	w, p := genuine(t)
	i := find(t, p, 7, "2026-10-14")
	// An attacker with their own key re-signs a clean version but cannot
	// produce the enrolled device's signature.
	cs, _ := sigs.GenerateKey(sigs.ES256)
	attacker, _ := sigs.NewSigner(cs.(*ecdsa.PrivateKey))
	setPayload(t, &p.Entries[i], func(pred map[string]any) { pred["device"].(map[string]any)["disk_encryption"] = "on" })
	env, _ := dsse.Sign(dsse.PayloadTypeInToto, p.Entries[i].Evidence.Envelope.Payload, attacker)
	env.Signatures[0].KeyID = p.Entries[i].Evidence.Envelope.Signatures[0].KeyID // claim to be D07
	p.Entries[i].Evidence.Envelope = env
	r, got := failed(t, p, w)
	if !strings.HasPrefix(got, "signatures") {
		t.Fatalf("forgery not caught by signatures: %s\n%s", got, r.Text())
	}
	// Signing under its own key ID instead, the attacker's key is simply
	// not the one enrolled for D07.
	env2, _ := dsse.Sign(dsse.PayloadTypeInToto, env.Payload, attacker)
	p.Entries[i].Evidence.Envelope = env2
	r = pack.Verify(p, w.Trust)
	if r.Step("signatures").Status != pack.Fail || !strings.Contains(strings.Join(r.Step("signatures").Problems, " "), "different key than the one enrolled") {
		t.Fatalf("unenrolled key not reported: %v", r.Step("signatures").Problems)
	}
}

func TestReplayFails(t *testing.T) {
	w, p := genuine(t)
	// Swap the bad Oct 14 entry for the genuine, all-green Oct 4 one.
	i, old := find(t, p, 7, "2026-10-14"), find(t, p, 7, "2026-10-04")
	p.Entries[i] = p.Entries[old]
	r := pack.Verify(p, w.Trust)
	if r.Step("sequence").Status != pack.Fail {
		t.Fatalf("replayed report not caught:\n%s", r.Text())
	}
	// The full replay attack: the old report re-sent to a bypassed ingest
	// server on Oct 14, so it is genuinely in the log with fresh timestamps.
	k := w.Keys
	rw, err := sample.Build(ctx, k, sample.Replay)
	if err != nil {
		t.Fatal(err)
	}
	rp, _ := rw.Pack()
	r = expectFailed(t, rp, rw, "sequence timestamps")
	if !strings.Contains(strings.Join(r.Step("sequence").Problems, " "), "replayed") {
		t.Fatalf("no replay message: %v", r.Step("sequence").Problems)
	}
}

func TestIngestRejectsReplayAndBackdating(t *testing.T) {
	w, _ := genuine(t)
	// Resubmitting a logged envelope is refused (nonce already used).
	var dev *tlog.Evidence
	for _, ev := range w.Server.Evidence() {
		if ev.Statement.IsPosture() && ev.Statement.Str("attester_kind") == "device_agent" {
			dev = ev
		}
	}
	if _, err := w.Server.Submit(ctx, dev.Envelope); err == nil {
		t.Fatal("ingest accepted a replayed envelope")
	}
}

func TestBackdatedTimestampIsCaught(t *testing.T) {
	w, _ := genuine(t)
	bw, err := sample.Build(ctx, w.Keys, sample.Backdate)
	if err != nil {
		t.Fatal(err)
	}
	bp, _ := bw.Pack()
	r := expectFailed(t, bp, bw, "timestamps")
	msg := strings.Join(r.Step("timestamps").Problems, " ")
	if !strings.Contains(msg, "says it was made Oct 12") || !strings.Contains(msg, "backdated") {
		t.Fatalf("unexpected message: %s", msg)
	}
	// The forged reports are excluded, so the gap is still disclosed.
	if !strings.Contains(r.Step("gaps").Detail, "Oct 12 to Oct 13") {
		t.Fatalf("gap hidden by backdated reports: %s", r.Step("gaps").Detail)
	}

	// Editing a timestamp token's time breaks the TSA signature.
	_, p := genuine(t)
	i := find(t, p, 3, "2026-10-10")
	tst := p.Entries[i].Evidence.Timestamps[0]["tst"].(map[string]any)
	tst["gen_time"] = "2026-10-10T09:00:00Z"
	expectFailed(t, p, w, "timestamps gaps")
}

// SPEC 8 and 13: a hole in a device's numbering is a lost-report gap.
// Since ingest accepts lost uploads, a report deleted from a pack looks
// the same as one that never arrived, so it is disclosed, never hidden.
func TestDeletedEntryAndRewrittenHistoryFail(t *testing.T) {
	w, p := genuine(t)
	// Deleting the bad day from the pack leaves a hole in D07's numbering
	// and makes the summary's lapse unsupported.
	i := find(t, p, 7, "2026-10-14")
	p.Entries = append(p.Entries[:i], p.Entries[i+1:]...)
	r := expectFailed(t, p, w, "gaps")
	seq := r.Step("sequence")
	if seq.Status != pack.Warn || !strings.Contains(strings.Join(seq.Problems, " "), "Laptop D07: report #12 is missing") {
		t.Fatalf("deleted report not disclosed: %s %v", seq.Status, seq.Problems)
	}
	if !strings.Contains(strings.Join(r.Step("gaps").Problems, " "), "hides lost reports the evidence shows: Laptop D07: report #12 missing") {
		t.Fatalf("summary mismatch not explained: %v", r.Step("gaps").Problems)
	}

	// Even with the summary recomputed to match, the hole stays in it: the
	// lapse is gone but D07's report #12 is disclosed as lost.
	p.Summary = pack.Verify(p, w.Trust).Computed
	r = expectFailed(t, p, w, "")
	lost, _ := r.Computed["lost_reports"].([]any)
	if len(lost) != 1 {
		t.Fatalf("want one lost report run, got %v", lost)
	}
	l := lost[0].(map[string]any)
	if l["device_number"] != int64(7) || l["first_seq"] != int64(12) || l["last_seq"] != int64(12) || l["count"] != int64(1) {
		t.Fatalf("wrong lost report %v", l)
	}
	if !strings.Contains(r.Text(), "lost report run(s) disclosed") || r.Step("sequence").Status != pack.Warn {
		t.Fatalf("lost report not visible in the report:\n%s", r.Text())
	}

	// The log operator deletes it from the log itself and re-signs. The
	// hole is disclosed and the rewrite is caught.
	_, vp, err := w.VendorRewrite()
	if err != nil {
		t.Fatal(err)
	}
	r = expectFailed(t, vp, w, "consistency witnesses")
	if r.Step("sequence").Status != pack.Warn {
		t.Fatalf("the vendor's deletion left no visible hole: %s", r.Step("sequence").Status)
	}
	if !strings.Contains(strings.Join(r.Step("consistency").Problems, " "), "not consistent") {
		t.Fatalf("unexpected consistency message: %v", r.Step("consistency").Problems)
	}
}

// A genuine pack with no holes has no lost_reports key at all, so its
// summary is byte for byte what earlier verifiers compute.
func TestNoLostReportsKeyWithoutHoles(t *testing.T) {
	w, p := genuine(t)
	r := pack.Verify(p, w.Trust)
	if _, ok := r.Computed["lost_reports"]; ok {
		t.Fatal("lost_reports present in a pack without holes")
	}
	if r.Step("sequence").Status != pack.Pass {
		t.Fatalf("sequence = %s", r.Step("sequence").Status)
	}
}

func TestMissingWitnessQuorumFails(t *testing.T) {
	w, p := genuine(t)
	n, err := note.Parse(p.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	all := n.Sigs
	for keep, want := range map[int]string{3: "", 2: "", 1: "witnesses", 0: "witnesses"} {
		n.Sigs = all[:1+keep] // the log's signature plus `keep` witnesses
		p.Checkpoint = n.String()
		r, got := failed(t, p, w)
		if got != want {
			t.Fatalf("%d witnesses: failed %q want %q\n%s", keep, got, want, r.Text())
		}
	}
	// A duplicated cosignature from one witness still counts once.
	n.Sigs = append([]note.SigLine{all[0]}, all[1], all[1])
	p.Checkpoint = n.String()
	if _, got := failed(t, p, w); got != "witnesses" {
		t.Fatalf("duplicate cosignature counted twice: %q", got)
	}
}

func TestForbiddenFieldRejectedEvenWhenSigned(t *testing.T) {
	// A buggy or malicious agent signs a statement that carries a host name
	// and a file path. The signature is valid; the content check still fails.
	w, p := genuine(t)
	i := find(t, p, 5, "2026-10-20")
	kf := w.Keys.Firms[0].Devices[4]
	s, err := kf.Signer()
	if err != nil {
		t.Fatal(err)
	}
	setPayload(t, &p.Entries[i], func(pred map[string]any) {
		pred["device"].(map[string]any)["hostname"] = "MARIA-LAPTOP"
		pred["device"].(map[string]any)["last_file"] = "C:/Users/maria/Documents/client-ssn.xlsx"
	})
	env, _ := dsse.Sign(dsse.PayloadTypeInToto, p.Entries[i].Evidence.Envelope.Payload, s)
	p.Entries[i].Evidence.Envelope = env
	r := pack.Verify(p, w.Trust)
	if r.Step("signatures").Status != pack.Pass {
		t.Fatalf("signature should be valid: %v", r.Step("signatures").Problems)
	}
	if r.Step("content").Status != pack.Fail || !strings.Contains(strings.Join(r.Step("content").Problems, " "), "field is not allowed") {
		t.Fatalf("forbidden field not rejected: %v", r.Step("content").Problems)
	}
}

func TestHiddenGapOrLapseFails(t *testing.T) {
	w, p := genuine(t)
	s := p.Summary.(map[string]any)
	s["gaps"] = []any{}
	r := expectFailed(t, p, w, "gaps")
	if !strings.Contains(strings.Join(r.Step("gaps").Problems, " "), "hides a gap") {
		t.Fatalf("unexpected: %v", r.Step("gaps").Problems)
	}
	_, p = genuine(t)
	s = p.Summary.(map[string]any)
	s["lapses"] = s["lapses"].([]any)[1:]
	expectFailed(t, p, w, "gaps")
}

func TestOmittedDeviceIsCaught(t *testing.T) {
	// "Enroll only the good laptops": drop D07 from the pack entirely.
	w, p := genuine(t)
	var attester string
	var keep []pack.Entry
	for _, e := range p.Entries {
		st, _ := posture.Validate(e.Evidence.Envelope.Payload)
		if !st.IsPosture() && st.Str("kind") == "attester" && st.Int("device_number") == 7 {
			attester = st.Str("attester")
		}
	}
	for _, e := range p.Entries {
		st, _ := posture.Validate(e.Evidence.Envelope.Payload)
		if st.Str("attester") != attester {
			keep = append(keep, e)
		}
	}
	p.Entries = keep
	r := pack.Verify(p, w.Trust)
	if r.Step("enrollment").Status != pack.Fail || !strings.Contains(strings.Join(r.Step("enrollment").Problems, " "), "a device was left out") {
		t.Fatalf("omitted device not caught:\n%s", r.Text())
	}
}

func TestWrongFirmNameOrTrustRootsFail(t *testing.T) {
	w, p := genuine(t)
	p.DisplayName = "Some Other Firm LLC"
	expectFailed(t, p, w, "enrollment")

	// Trust roots come from the verifier, never the pack: a policy that
	// pins a different log key rejects the pack.
	_, p = genuine(t)
	other, _ := sample.GenerateKeys()
	ow, err := sample.Build(ctx, other, sample.Genuine)
	if err != nil {
		t.Fatal(err)
	}
	r := pack.Verify(p, ow.Trust)
	for _, id := range []string{"timestamps", "checkpoint", "witnesses"} {
		if r.Step(id).Status != pack.Fail {
			t.Errorf("%s passed against foreign trust roots", id)
		}
	}
}

// The public log must not reveal any firm's posture or identity: it holds
// checkpoints and 32-byte commitments only.
func TestPublicLogRevealsNoPostureOrIdentity(t *testing.T) {
	w, p := genuine(t)
	dir := t.TempDir()
	if err := w.Server.Log.WriteTiles(dir); err != nil {
		t.Fatal(err)
	}
	var published [][]byte
	walk(t, dir, func(b []byte) { published = append(published, b) })
	blob := bytes.Join(published, []byte{0})

	secrets := []string{sample.FirmName, "Maple Street", w.TenantID, w.NameSalt,
		"disk_encryption", "edr_running", "device_agent", "observed_at", "payload", "in-toto"}
	for _, e := range p.Entries {
		env := e.Evidence.Envelope
		st, _ := posture.Validate(env.Payload)
		secrets = append(secrets, st.Str("attester"), st.Str("nonce"), st.Str("salt"), st.SubjectDigest,
			string(env.Payload[:40]), string(env.Value()["payload"].(string)[:40]))
		for _, s := range env.Signatures {
			secrets = append(secrets, s.KeyID)
		}
	}
	for _, s := range secrets {
		if s != "" && bytes.Contains(blob, []byte(s)) {
			t.Errorf("public log contains %q", s)
		}
	}
	// Every published leaf is exactly SHA-256 of an envelope: a commitment.
	digests, err := tlog.ReadEntryBundles(dir, w.Server.Log.Size())
	if err != nil {
		t.Fatal(err)
	}
	for i, ev := range w.Server.Evidence() {
		if digests[i] != tlog.EntryDigest(ev.Envelope) {
			t.Fatalf("leaf %d is not the envelope digest", i)
		}
	}
	// And the tiles reproduce the signed checkpoint.
	if _, err := tlog.ReadPublic(dir); err != nil {
		t.Fatal(err)
	}
}

func TestStatementsAreSalted(t *testing.T) {
	// Two reports with identical posture still have unrelated commitments.
	_, p := genuine(t)
	a, b := p.Entries[find(t, p, 2, "2026-10-05")], p.Entries[find(t, p, 2, "2026-10-06")]
	sa, _ := posture.Validate(a.Evidence.Envelope.Payload)
	sb, _ := posture.Validate(b.Evidence.Envelope.Payload)
	if sa.Str("salt") == sb.Str("salt") || len(sa.Str("salt")) != 64 {
		t.Fatal("salts missing or repeated")
	}
	if tlog.EntryDigest(a.Evidence.Envelope) == tlog.EntryDigest(b.Evidence.Envelope) {
		t.Fatal("identical commitments")
	}
}

var ctx = context.Background()
