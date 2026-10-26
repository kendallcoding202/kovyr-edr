package vectors

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
	"github.com/kendallcoding202/kovyr-edr/proof/pack"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tlog"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

const dir = "../../testdata/vectors"

// The CLI that used to write the vectors is not vendored; this flag does
// the same job.
var update = flag.Bool("update", false, "rewrite the committed vectors in testdata/vectors")

// Regenerate is the command that rewrites the vectors.
const Regenerate = "go test ./proof/internal/vectors -run TestVectorsAreUpToDate -update"

// The committed vectors must be exactly what the generator produces.
func TestVectorsAreUpToDate(t *testing.T) {
	files, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		for name, b := range files {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v (run: %s)", name, err, Regenerate)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale; run: %s", name, Regenerate)
		}
	}
}

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func str(v any) string { s, _ := v.(string); return s }

// The remaining tests read the files as another implementation would.

func TestCanonicalizationVectors(t *testing.T) {
	v := load(t, "canonicalization.json")
	for _, c := range v["canonicalize"].([]any) {
		m := c.(map[string]any)
		out, err := canon.Canonicalize([]byte(str(m["input"])))
		if err != nil || string(out) != str(m["canonical"]) {
			t.Errorf("%s: got %s", m["name"], out)
		}
		if _, err := canon.Parse(out); err != nil {
			t.Errorf("%s: canonical output rejected", m["name"])
		}
	}
	for _, k := range []string{"reject_as_canonical", "reject_in_signed_data_always"} {
		for _, c := range v[k].([]any) {
			m := c.(map[string]any)
			if _, err := canon.Parse([]byte(str(m["input"]))); err == nil {
				t.Errorf("%s accepted", m["name"])
			}
		}
	}
}

func TestDSSEVectors(t *testing.T) {
	v := load(t, "dsse.json")
	payload, _ := base64.StdEncoding.DecodeString(str(v["payload"]))
	if hex.EncodeToString(dsse.PAE(str(v["payload_type"]), payload)) != str(v["pae_hex"]) {
		t.Fatal("PAE mismatch")
	}
	for _, s := range v["signatures"].([]any) {
		m := s.(map[string]any)
		key := m["key"].(map[string]any)
		pk, err := sigs.ParsePublicKeyBase64(str(key["spki"]))
		if err != nil || pk.KeyID() != str(key["keyid"]) {
			t.Fatal("key mismatch")
		}
		env, err := dsse.Parse([]byte(str(m["envelope_canonical"])))
		if err != nil || env.VerifySignature(0, pk) != nil {
			t.Fatalf("%s signature does not verify", key["alg"])
		}
	}
	pae, _ := hex.DecodeString(str(v["pae_hex"]))
	for _, s := range v["must_reject"].([]any) {
		m := s.(map[string]any)
		pk, _ := sigs.ParsePublicKeyBase64(str(m["spki"]))
		sig, _ := base64.StdEncoding.DecodeString(str(m["sig"]))
		if pk.Verify(pae, sig) == nil {
			t.Errorf("%s accepted", m["name"])
		}
	}
}

func hashes(t *testing.T, v any) []merkle.Hash {
	var out []merkle.Hash
	for _, s := range v.([]any) {
		b, err := base64.StdEncoding.DecodeString(str(s))
		if err != nil || len(b) != 32 {
			t.Fatal("bad hash")
		}
		var h merkle.Hash
		copy(h[:], b)
		out = append(out, h)
	}
	return out
}

func TestMerkleVectors(t *testing.T) {
	v := load(t, "merkle.json")
	tr := merkle.NewTree()
	for i, l := range v["leaves_hex"].([]any) {
		b, _ := hex.DecodeString(str(l))
		h := merkle.LeafHash(b)
		if hex.EncodeToString(h[:]) != str(v["leaf_hashes_hex"].([]any)[i]) {
			t.Fatal("leaf hash")
		}
		tr.Append(h)
	}
	roots := v["roots_hex_by_size"].([]any)
	root := func(n uint64) merkle.Hash {
		var h merkle.Hash
		b, _ := hex.DecodeString(str(roots[n-1]))
		copy(h[:], b)
		return h
	}
	for _, c := range v["inclusion"].([]any) {
		m := c.(map[string]any)
		i, n := uint64(m["index"].(float64)), uint64(m["size"].(float64))
		if merkle.VerifyInclusion(i, n, tr.LeafHashAt(i), hashes(t, m["proof"]), root(n)) != nil {
			t.Errorf("inclusion %d/%d", i, n)
		}
	}
	for _, c := range v["consistency"].([]any) {
		m := c.(map[string]any)
		a, b := uint64(m["from"].(float64)), uint64(m["to"].(float64))
		if merkle.VerifyConsistency(a, b, hashes(t, m["proof"]), root(a), root(b)) != nil {
			t.Errorf("consistency %d->%d", a, b)
		}
	}
}

func TestNoteVectors(t *testing.T) {
	v := load(t, "note.json")
	ex := v["c2sp_signed_note_example"].(map[string]any)
	vk, _ := note.ParseVKey(str(ex["vkey"]))
	n, err := note.Parse(str(ex["note"]))
	if err != nil || n.VerifySignedBy(vk) != nil {
		t.Fatal("C2SP example")
	}
	lvk, _ := note.ParseVKey(str(v["log_vkey"]))
	wvk, _ := note.ParseVKey(str(v["witness_vkey"]))
	cn, err := note.Parse(str(v["cosigned_checkpoint"]))
	if err != nil || cn.VerifySignedBy(lvk) != nil {
		t.Fatal("checkpoint signature")
	}
	if ts, err := cn.VerifyCosignature(wvk); err != nil || float64(ts) != v["cosignature_time"].(float64) {
		t.Fatal("cosignature")
	}
	if string(note.CosignatureMessage(cn.Text, uint64(v["cosignature_time"].(float64)))) != str(v["cosigned_message"]) {
		t.Fatal("cosigned message")
	}
}

func TestStatementVectors(t *testing.T) {
	v := load(t, "statement.json")
	payload := []byte(str(v["payload_canonical"]))
	if _, err := posture.Validate(payload); err != nil {
		t.Fatal(err)
	}
	d := posture.PayloadDigest(payload)
	if hex.EncodeToString(d[:]) != str(v["payload_sha256_hex"]) {
		t.Fatal("chain hash")
	}
	env, err := dsse.Parse([]byte(str(v["envelope_canonical"])))
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := sigs.ParsePublicKeyBase64(str(v["device_key"].(map[string]any)["spki"]))
	if env.VerifySignature(0, pk) != nil {
		t.Fatal("statement signature")
	}
	digest := tlog.EntryDigest(env)
	leaf := tlog.LeafHash(digest)
	if hex.EncodeToString(digest[:]) != str(v["entry_digest_hex"]) || hex.EncodeToString(leaf[:]) != str(v["leaf_hash_hex"]) {
		t.Fatal("entry digest or leaf hash")
	}
	tokJSON, _ := json.Marshal(v["timestamp_token"])
	tokV, err := canon.ParseContainer(tokJSON)
	if err != nil {
		t.Fatal(err)
	}
	tpk, _ := sigs.ParsePublicKeyBase64(str(v["tsa_key"].(map[string]any)["spki"]))
	if _, err := tsa.Verify(tokV.(map[string]any), digest, []tsa.Trusted{{Name: "tsa-vector.example", Kind: tsa.KindSimulated, PublicKey: tpk}}); err != nil {
		t.Fatal(err)
	}
	if _, err := posture.Validate([]byte(str(v["scan_payload_canonical"]))); err != nil {
		t.Fatal(err)
	}
	senv, err := dsse.Parse([]byte(str(v["scan_envelope_canonical"])))
	spk, _ := sigs.ParsePublicKeyBase64(str(v["scanner_key"].(map[string]any)["spki"]))
	if err != nil || senv.VerifySignature(0, spk) != nil {
		t.Fatal("scan statement signature")
	}
	ep := []byte(str(v["endpoint_payload_canonical"]))
	est, err := posture.Validate(ep)
	if err != nil || !est.IsEndpoint() {
		t.Fatalf("endpoint statement: %v", err)
	}
	eenv, err := dsse.Parse([]byte(str(v["endpoint_envelope_canonical"])))
	epk, _ := sigs.ParsePublicKeyBase64(str(v["endpoint_device_key"].(map[string]any)["spki"]))
	if err != nil || len(eenv.Signatures) != 1 || eenv.VerifySignature(0, epk) != nil || string(eenv.Payload) != string(ep) {
		t.Fatal("endpoint statement signature")
	}
	if est.Str("attester") != posture.AttesterID(posture.DeviceAgent, epk) {
		t.Fatal("endpoint attester is not derived from its key")
	}
	for _, r := range v["must_reject_payloads"].([]any) {
		m := r.(map[string]any)
		if _, err := posture.Validate([]byte(str(m["payload"]))); err == nil {
			t.Errorf("%s accepted", m["name"])
		}
	}
}

func TestMiniPackVector(t *testing.T) {
	pb, _ := os.ReadFile(filepath.Join(dir, "mini-pack.json"))
	tb, _ := os.ReadFile(filepath.Join(dir, "mini-trust-policy.json"))
	exp := load(t, "mini-pack-expected.json")
	trust, err := pack.ParseTrustPolicy(tb)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Parse(pb)
	if err != nil {
		t.Fatal(err)
	}
	r := pack.Verify(p, trust)
	for id, want := range exp["steps"].(map[string]any) {
		if string(r.Step(id).Status) != want {
			t.Errorf("step %s = %s, want %s", id, r.Step(id).Status, want)
		}
	}
	tm := exp["tampered"].(map[string]any)
	for _, e := range p.Entries {
		if e.Evidence.Index == uint64(tm["entry_index"].(float64)) {
			e.Evidence.Envelope.Payload = bytes.Replace(e.Evidence.Envelope.Payload, []byte(`"disk_encryption":"on"`), []byte(`"disk_encryption":"off"`), 1)
		}
	}
	var want []string
	for _, s := range tm["failed_steps"].([]any) {
		want = append(want, str(s))
	}
	if got := strings.Join(pack.Verify(p, trust).FailedSteps(), ","); got != strings.Join(want, ",") {
		t.Fatalf("tampered: failed %s want %s", got, strings.Join(want, ","))
	}
}
