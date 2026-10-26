package pack

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tlog"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

// Status of a verification step.
type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	Warn Status = "warn"
)

// StepDef names one verification step.
type StepDef struct{ ID, Title string }

// Steps lists the verification steps in the order they are reported. The
// IDs are shared with every other verifier implementation.
func Steps() []StepDef { return append([]StepDef(nil), steps...) }

var steps = []StepDef{
	{"signatures", "Statement signatures"},
	{"content", "Only yes/no answers, counts, categories and times"},
	{"enrollment", "Devices enrolled in the log"},
	{"sequence", "Sequence and no replay"},
	{"timestamps", "Timestamps from two independent authorities"},
	{"inclusion", "Merkle inclusion proofs"},
	{"checkpoint", "Log checkpoint signature"},
	{"consistency", "Log history never rewritten"},
	{"witnesses", "Witness quorum"},
	{"gaps", "Gaps disclosed"},
}

// Step is one step's outcome.
type Step struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Status   Status   `json:"status"`
	Checked  int      `json:"checked"`
	Detail   string   `json:"detail"`
	Problems []string `json:"problems,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

func (s *Step) fail(format string, a ...any) {
	s.Status = Fail
	s.Problems = append(s.Problems, fmt.Sprintf(format, a...))
}

// warn records something a reader must see that does not fail the step.
func (s *Step) warn(format string, a ...any) {
	if s.Status == Pass {
		s.Status = Warn
	}
	s.Problems = append(s.Problems, fmt.Sprintf(format, a...))
}

// Report is the result of verifying a pack.
type Report struct {
	Verified    bool           `json:"verified"`
	TenantID    string         `json:"tenant"`
	DisplayName string         `json:"display_name"`
	From        string         `json:"from"`
	To          string         `json:"to"`
	Sample      bool           `json:"sample"`
	Steps       []*Step        `json:"steps"`
	Computed    map[string]any `json:"computed_summary"`
	Simulated   []string       `json:"simulated"`
	gaps        []gap
	labels      map[string]string
}

// Step returns the step with the given ID.
func (r *Report) Step(id string) *Step {
	for _, s := range r.Steps {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// FailedSteps lists the IDs of failed steps.
func (r *Report) FailedSteps() []string {
	var out []string
	for _, s := range r.Steps {
		if s.Status == Fail {
			out = append(out, s.ID)
		}
	}
	return out
}

type item struct {
	e       Entry
	digest  merkle.Hash
	st      *posture.Statement
	stErr   error
	label   string
	sigOK   bool
	enrolOK bool
	tsOK    bool
	inclOK  bool
	tsTime  time.Time
}

func (it *item) index() uint64       { return it.e.Evidence.Index }
func (it *item) env() *dsse.Envelope { return it.e.Evidence.Envelope }
func (it *item) posture() bool       { return it.st != nil && it.st.IsPosture() }
func (it *item) endpoint() bool      { return it.st != nil && it.st.IsEndpoint() }
func (it *item) kind() string {
	if it.st == nil || it.st.IsPosture() || it.st.IsEndpoint() {
		return ""
	}
	return it.st.Str("kind")
}

type attester struct {
	id, kind string
	key      *sigs.PublicKey
	it       *item
	class    string
	number   int64
	role     string
	protect  string
}

// Verify checks a pack against a trust policy. It never stops early: every
// step runs and reports, so a reader sees every check a tampered pack
// fails.
func Verify(p *Pack, trust *TrustPolicy) *Report {
	r := &Report{TenantID: p.TenantID, DisplayName: p.DisplayName, From: p.From, To: p.To, Sample: p.Sample, labels: map[string]string{}}
	step := map[string]*Step{}
	for _, s := range steps {
		st := &Step{ID: s.ID, Title: s.Title, Status: Pass}
		r.Steps = append(r.Steps, st)
		step[s.ID] = st
	}

	// Decode every entry once.
	items := make([]*item, len(p.Entries))
	for i, e := range p.Entries {
		it := &item{e: e, digest: tlog.EntryDigest(e.Evidence.Envelope)}
		if e.Evidence.Envelope.PayloadType != dsse.PayloadTypeInToto {
			it.stErr = fmt.Errorf("payload type %q is not an in-toto statement", e.Evidence.Envelope.PayloadType)
		} else {
			it.st, it.stErr = posture.Validate(e.Evidence.Envelope.Payload)
		}
		items[i] = it
	}

	// Discover keys from enrollment records for this tenant.
	var tenantKey *sigs.PublicKey
	var genesis []*item
	attesters := map[string]*attester{}
	keyByID := map[string]*sigs.PublicKey{}
	var dupEnroll []*item
	for _, it := range items {
		switch it.kind() {
		case "tenant_genesis":
			genesis = append(genesis, it)
			if k, err := sigs.ParsePublicKeyBase64(it.st.Str("tenant_key")); err == nil && it.st.Str("tenant") == p.TenantID && tenantKey == nil {
				tenantKey = k
				keyByID[k.KeyID()] = k
			}
		case "attester":
			k, err := sigs.ParsePublicKeyBase64(it.st.Str("attester_key"))
			if err != nil {
				continue
			}
			id := it.st.Str("attester")
			if _, dup := attesters[id]; dup {
				dupEnroll = append(dupEnroll, it)
				continue
			}
			attesters[id] = &attester{id: id, kind: it.st.Str("attester_kind"), key: k, it: it,
				class: it.st.Str("device_class"), number: it.st.Int("device_number"),
				role: it.st.Str("staff_role"), protect: it.st.Str("key_protection")}
			keyByID[k.KeyID()] = k
		}
	}
	for id, a := range attesters {
		r.labels[id] = attesterLabel(a)
	}
	for _, it := range items {
		it.label = r.itemLabel(it)
	}

	// 1. Signatures.
	s := step["signatures"]
	algs := map[sigs.Alg]int{}
	for _, it := range items {
		env := it.env()
		ok := false
		switch {
		case it.kind() == "tenant_genesis":
			k, _ := sigs.ParsePublicKeyBase64(it.st.Str("tenant_key"))
			s.Checked++
			ok = len(env.Signatures) == 1 && k != nil && env.VerifySignature(0, k) == nil
			if ok {
				algs[k.Alg]++
			}
		case it.kind() == "attester":
			a := attesters[it.st.Str("attester")]
			s.Checked += 2
			switch {
			case tenantKey == nil:
				s.fail("%s: there is no firm enrollment to check the firm's signature against", it.label)
			case len(env.Signatures) != 2 || env.VerifySignature(0, tenantKey) != nil:
				s.fail("%s: not signed by the firm's enrollment key", it.label)
			case a == nil || env.VerifySignature(1, a.key) != nil:
				s.fail("%s: the enrolled key did not prove possession (second signature invalid)", it.label)
			default:
				ok = true
				algs[tenantKey.Alg]++
				algs[a.key.Alg]++
			}
		default:
			s.Checked++
			var key *sigs.PublicKey
			if it.posture() {
				if a := attesters[it.st.Str("attester")]; a != nil {
					key = a.key
				}
			}
			if key == nil && len(env.Signatures) > 0 {
				key = keyByID[env.Signatures[0].KeyID]
			}
			switch {
			case len(env.Signatures) != 1:
				s.fail("%s: expected exactly one signature, found %d", it.label, len(env.Signatures))
			case key == nil:
				s.fail("%s: signed by a key that is not enrolled for this firm", it.label)
			case env.Signatures[0].KeyID != key.KeyID():
				s.fail("%s: signed by a different key than the one enrolled for this device", it.label)
			default:
				if err := env.VerifySignature(0, key); err != nil {
					s.fail("%s: the signature does not match the content, so the report was changed after it was signed (%v)", it.label, err)
				} else {
					ok = true
					algs[key.Alg]++
				}
			}
		}
		it.sigOK = ok
	}
	if s.Status == Pass {
		s.Detail = fmt.Sprintf("%d of %d signatures valid (ECDSA P-256: %d, Ed25519: %d)", s.Checked, s.Checked, algs[sigs.ES256], algs[sigs.Ed25519])
	} else {
		s.Detail = fmt.Sprintf("Signature problems in %d of %d entries", len(s.Problems), len(items))
	}

	// 2. Content rules.
	s = step["content"]
	for _, it := range items {
		s.Checked++
		if it.stErr != nil {
			s.fail("%s: %v", it.label, it.stErr)
		}
	}
	if s.Status == Pass {
		s.Detail = fmt.Sprintf("All %d statements carry only yes/no answers, counts, categories and times; no names, paths or free text", s.Checked)
	} else {
		s.Detail = fmt.Sprintf("%d statements break the content rules", len(s.Problems))
	}

	// 3. Enrollment.
	s = step["enrollment"]
	verifyEnrollment(p, s, items, genesis, tenantKey, attesters, dupEnroll)

	// 4. Sequence and replay.
	verifySequence(step["sequence"], items, attesters, r)

	// 5. Timestamps.
	verifyTimestamps(step["timestamps"], items, trust)

	// 6, 7, 8, 9. The log.
	latest, latestNote := verifyCheckpoint(step["checkpoint"], p, trust)
	verifyInclusion(step["inclusion"], items, latest)
	verifyConsistency(step["consistency"], p, trust, latest)
	verifyWitnesses(step["witnesses"], latestNote, trust)

	// 10. Gaps and summary.
	r.Computed, r.gaps = summarize(p, items, attesters)
	verifySummary(step["gaps"], p, r)

	for _, w := range trust.Witnesses {
		if w.Simulated {
			r.Simulated = append(r.Simulated, "witness "+w.Name)
		}
	}
	for _, a := range trust.TSAs {
		if a.Simulated {
			r.Simulated = append(r.Simulated, "timestamp authority "+a.Name)
		}
	}
	r.Verified = len(r.FailedSteps()) == 0
	return r
}

func verifyEnrollment(p *Pack, s *Step, items []*item, genesis []*item, tenantKey *sigs.PublicKey, attesters map[string]*attester, dups []*item) {
	var g *item
	switch {
	case len(genesis) == 0:
		s.fail("The pack has no firm enrollment (tenant genesis) record")
	case len(genesis) > 1:
		s.fail("The pack has %d firm enrollment records; there must be exactly one", len(genesis))
	default:
		g = genesis[0]
	}
	if g != nil {
		s.Checked++
		switch {
		case g.st.Str("tenant") != p.TenantID || tenantKey == nil:
			s.fail("The firm enrollment is for a different firm (%s)", g.st.Str("tenant"))
		case posture.TenantID(tenantKey) != p.TenantID:
			s.fail("The firm ID is not derived from the firm's enrollment key")
		default:
			g.enrolOK = true
		}
		// The display name is checked separately: a wrong name fails this
		// step but does not make the firm's evidence any less its own.
		if c := NameCommitment(p.DisplayName, p.DisplayNameSalt); hex.EncodeToString(c[:]) != g.st.Str("display_name_commitment") {
			s.fail("The firm name in this pack (%q) is not the name committed at enrollment", p.DisplayName)
		}
	}
	for _, d := range dups {
		s.fail("%s: the same key was enrolled twice", d.label)
	}
	counts := map[string]int{}
	strength := map[string]int{}
	for _, a := range attesters {
		it := a.it
		s.Checked++
		switch {
		case it.st.Str("tenant") != p.TenantID:
			s.fail("%s: enrolled in a different firm", it.label)
		case posture.AttesterID(posture.AttesterKind(a.kind), a.key) != a.id:
			s.fail("%s: the device ID is not derived from its key", it.label)
		case g != nil && (it.index() <= g.index() || it.st.Time("enrolled_at").Before(g.st.Time("enrolled_at"))):
			s.fail("%s: enrolled before the firm itself was", it.label)
		default:
			it.enrolOK = g != nil && g.enrolOK
			counts[a.kind]++
			if a.kind == "device_agent" {
				strength[strengthOf(a)]++
			}
		}
	}
	for _, it := range items {
		if !it.endpoint() {
			continue
		}
		// SPEC 6.5: until endpoint enrollment ships, an endpoint
		// statement names no tenant, so nothing binds it to this firm.
		s.Checked++
		s.fail("%s: endpoint statements made before endpoint enrollment carry no tenant, so they cannot be part of a firm's Proof Pack", it.label)
	}
	var latestConn *item
	for _, it := range items {
		if !it.posture() {
			continue
		}
		s.Checked++
		a := attesters[it.st.Str("attester")]
		switch {
		case it.st.Str("tenant") != p.TenantID:
			s.fail("%s: belongs to a different firm", it.label)
		case a == nil:
			s.fail("%s: comes from a device or service with no enrollment record in this pack", it.label)
		case a.kind != it.st.Str("attester_kind"):
			s.fail("%s: does not match how the attester was enrolled", it.label)
		case a.it.index() >= it.index() || it.st.Time("observed_at").Before(a.it.st.Time("enrolled_at")):
			s.fail("%s: dated before the device was enrolled", it.label)
		default:
			it.enrolOK = a.it.enrolOK
			if a.kind == "cloud_connector" && it.sigOK && (latestConn == nil || it.st.Time("observed_at").After(latestConn.st.Time("observed_at"))) {
				latestConn = it
			}
		}
	}
	if latestConn != nil {
		known := latestConn.st.Int("tenant_posture.devices_known")
		enrolled := latestConn.st.Int("tenant_posture.devices_enrolled")
		if int64(counts["device_agent"]) < enrolled {
			s.fail("Microsoft 365 reports %d enrolled devices but this pack includes only %d; a device was left out", enrolled, counts["device_agent"])
		}
		s.Notes = append(s.Notes, fmt.Sprintf("Coverage: %d of %d devices known to Microsoft 365 are enrolled", enrolled, known))
		if unknown := latestConn.st.Int("tenant_posture.devices_unknown_seen"); unknown > 0 {
			s.Notes = append(s.Notes, fmt.Sprintf("%d unknown device(s) seen signing in", unknown))
		}
	}
	if strength["software"] > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("%d device key(s) are software keys (prototype). Production devices use TPM 2.0 or Secure Enclave keys, checked against the chip maker's certificate", strength["software"]))
	}
	if s.Status == Pass {
		s.Detail = fmt.Sprintf("1 firm, %d devices, %d cloud connector, %d external scanner, %d staff attester enrolled; every statement comes from an enrolled key",
			counts["device_agent"], counts["cloud_connector"], counts["external_scanner"], counts["staff_attester"])
	} else {
		s.Detail = fmt.Sprintf("%d enrollment problem(s)", len(s.Problems))
	}
}

// strengthOf is the evidence strength of an attester's device facts. The
// prototype never grants "hardware": that needs a verified TPM or Secure
// Enclave attestation chain, which this verifier does not check yet.
func strengthOf(a *attester) string {
	switch a.kind {
	case "cloud_connector":
		return "platform"
	case "staff_attester":
		return "staff_attested"
	case "external_scanner":
		return "scan_verified"
	}
	return "software"
}

func verifySequence(s *Step, items []*item, attesters map[string]*attester, r *Report) {
	nonces := map[string]*item{}
	chains := map[string][]*item{}
	for _, it := range items {
		if it.st == nil {
			continue
		}
		n := it.st.Str("nonce")
		if first, dup := nonces[n]; dup {
			if bytes.Equal(first.env().Payload, it.env().Payload) {
				s.fail("%s was logged a second time at log position %d (first at %d): an old report was replayed", first.label, it.index(), first.index())
				continue // judge the chain on the first copy only
			}
			s.fail("%s reuses the one-time server challenge of %s, so it is a replay", it.label, first.label)
		} else {
			nonces[n] = it
		}
		if it.posture() {
			chains[it.st.Str("attester")] = append(chains[it.st.Str("attester")], it)
		}
	}
	ids := make([]string, 0, len(chains))
	for id := range chains {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	total, lost := 0, 0
	for _, id := range ids {
		chain := chains[id]
		sort.SliceStable(chain, func(i, j int) bool {
			if chain[i].st.Int("seq") != chain[j].st.Int("seq") {
				return chain[i].st.Int("seq") < chain[j].st.Int("seq")
			}
			return chain[i].index() < chain[j].index()
		})
		total += len(chain)
		name := r.attesterName(id)
		first := chain[0]
		if first.st.Int("seq") == 1 {
			if a := attesters[id]; a != nil {
				want := posture.PayloadDigest(a.it.env().Payload)
				if first.st.Str("prev") != hex.EncodeToString(want[:]) {
					s.fail("%s does not link back to the device's enrollment record", first.label)
				}
			}
		} else {
			s.Notes = append(s.Notes, fmt.Sprintf("%s: chain starts at report #%d (earlier reports are outside this pack's dates)", name, first.st.Int("seq")))
		}
		for i := 1; i < len(chain); i++ {
			a, b := chain[i-1], chain[i]
			sa, sb := a.st.Int("seq"), b.st.Int("seq")
			switch {
			case sb == sa:
				s.fail("Two different reports both claim to be %s (log positions %d and %d)", b.label, a.index(), b.index())
			case sb > sa+1:
				// SPEC 8 and 13: a hole in the numbering is a lost-report
				// gap. Ingest accepts it so a device is never locked out,
				// and offline it cannot be told apart from a report left
				// out of the pack, so it is disclosed (here and in the
				// summary), not failed. b's prev names the missing report
				// and cannot be checked.
				lost += int(sb - sa - 1)
				if sb == sa+2 {
					s.warn("%s: report #%d is missing: it never reached the log, or it was left out of this pack (disclosed as a lost report)", name, sa+1)
				} else {
					s.warn("%s: reports #%d to #%d are missing: they never reached the log, or they were left out of this pack (disclosed as lost reports)", name, sa+1, sb-1)
				}
			default:
				want := posture.PayloadDigest(a.env().Payload)
				if b.st.Str("prev") != hex.EncodeToString(want[:]) {
					s.fail("%s does not link to report #%d before it; the history was altered", b.label, sa)
				}
				if b.index() < a.index() || b.st.Time("observed_at").Before(a.st.Time("observed_at")) {
					s.fail("%s is out of order with report #%d", b.label, sa)
				}
			}
		}
	}
	s.Checked = total
	switch s.Status {
	case Pass:
		s.Detail = fmt.Sprintf("%d reports from %d devices and services: numbered in order, each linked to the one before, no repeats, nothing missing", total, len(chains))
	case Warn:
		s.Detail = fmt.Sprintf("%d reports from %d devices and services: in order and linked, no repeats; %d numbered report(s) missing, disclosed as lost", total, len(chains), lost)
	default:
		s.Detail = fmt.Sprintf("%d sequence problem(s)", len(s.Problems))
	}
}

func verifyTimestamps(s *Step, items []*item, trust *TrustPolicy) {
	tokens := 0
	for _, it := range items {
		s.Checked++
		valid := map[string]time.Time{}
		var firstErr error
		for _, tok := range it.e.Evidence.Timestamps {
			v, err := tsa.Verify(tok, it.digest, trust.tsaTrusted)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if _, dup := valid[v.TSA]; !dup {
				valid[v.TSA] = v.GenTime
			}
		}
		if len(valid) < trust.TSAQuorum {
			reason := ""
			if firstErr != nil {
				reason = " (" + firstErr.Error() + ")"
			}
			s.fail("%s: %d valid timestamp(s) from independent authorities, %d required%s", it.label, len(valid), trust.TSAQuorum, reason)
			continue
		}
		var lo, hi time.Time
		for _, t := range valid {
			if lo.IsZero() || t.Before(lo) {
				lo = t
			}
			if t.After(hi) {
				hi = t
			}
		}
		tokens += len(valid)
		it.tsTime = lo
		if hi.Sub(lo) > trust.MaxTSASpread {
			s.fail("%s: the two timestamp authorities disagree by %s", it.label, hi.Sub(lo).Round(time.Second))
			continue
		}
		if it.st == nil {
			continue
		}
		claimed := it.st.Time("observed_at")
		if !it.st.IsPosture() && !it.st.IsEndpoint() {
			claimed = it.st.Time("enrolled_at")
		}
		switch {
		case lo.Sub(claimed) > trust.MaxReportDelay:
			s.fail("%s says it was made %s, but the timestamp authorities first saw it %s, %s later: it was backdated or replayed",
				it.label, fmtTime(claimed), fmtTime(lo), fmtDuration(lo.Sub(claimed)))
		case claimed.Sub(lo) > trust.MaxClockSkew:
			s.fail("%s is dated %s, after the timestamp authorities saw it (%s)", it.label, fmtTime(claimed), fmtTime(lo))
		default:
			it.tsOK = true
		}
	}
	if s.Status == Pass {
		s.Detail = fmt.Sprintf("%d timestamps valid: every entry was stamped by %d independent authorities within %s of when it says it was made", tokens, trust.TSAQuorum, fmtDuration(trust.MaxReportDelay))
	} else {
		s.Detail = fmt.Sprintf("%d timestamp problem(s)", len(s.Problems))
	}
	for _, a := range trust.TSAs {
		if a.Simulated {
			s.Notes = append(s.Notes, "The timestamp authorities are simulated in this prototype (local keys). Production uses independent RFC 3161 timestamp authorities")
			break
		}
	}
}

type checkpointInfo struct {
	ok   bool
	cp   note.Checkpoint
	note *note.Note
}

func parseCheckpointNote(signed string) (note.Checkpoint, error) {
	n, err := note.Parse(signed)
	if err != nil {
		return note.Checkpoint{}, err
	}
	return note.ParseCheckpoint(n.Text)
}

func verifyCheckpoint(s *Step, p *Pack, trust *TrustPolicy) (checkpointInfo, *note.Note) {
	s.Checked = 1
	n, err := note.Parse(p.Checkpoint)
	if err != nil {
		s.fail("The checkpoint is malformed: %v", err)
		s.Detail = "No valid checkpoint"
		return checkpointInfo{}, nil
	}
	cp, err := note.ParseCheckpoint(n.Text)
	if err != nil {
		s.fail("The checkpoint is malformed: %v", err)
		s.Detail = "No valid checkpoint"
		return checkpointInfo{}, n
	}
	if cp.Origin != trust.LogOrigin || p.LogOrigin != trust.LogOrigin {
		s.fail("The checkpoint is for log %q, not the trusted log %q", cp.Origin, trust.LogOrigin)
	}
	if err := n.VerifySignedBy(trust.LogKey); err != nil {
		s.fail("The checkpoint is not validly signed by the log: %v", err)
	}
	if s.Status == Pass {
		s.Detail = fmt.Sprintf("Signed by %s; the log held %d entries", cp.Origin, cp.Size)
	} else {
		s.Detail = "The checkpoint signature is not valid"
	}
	return checkpointInfo{ok: true, cp: cp, note: n}, n
}

func verifyInclusion(s *Step, items []*item, latest checkpointInfo) {
	seen := map[uint64]*item{}
	for _, it := range items {
		s.Checked++
		if !latest.ok {
			continue
		}
		if prev, dup := seen[it.index()]; dup {
			s.fail("%s and %s both claim log position %d", prev.label, it.label, it.index())
			continue
		}
		seen[it.index()] = it
		if err := merkle.VerifyInclusion(it.index(), latest.cp.Size, tlog.LeafHash(it.digest), it.e.Proof, latest.cp.Root); err != nil {
			s.fail("%s: does not match log entry %d, so it is not the statement that was logged", it.label, it.index())
			continue
		}
		it.inclOK = true
	}
	switch {
	case !latest.ok:
		s.fail("No valid checkpoint to check inclusion against")
		s.Detail = "Not checked"
	case s.Status == Pass:
		s.Detail = fmt.Sprintf("All %d entries are proven to be in the append-only log of %d entries", len(items), latest.cp.Size)
	default:
		s.Detail = fmt.Sprintf("%d entries are not proven to be in the log", len(s.Problems))
	}
	s.Notes = append(s.Notes, "The public log holds only fingerprints (SHA-256 of each statement); the results stay private until the firm shares them")
}

func verifyConsistency(s *Step, p *Pack, trust *TrustPolicy, latest checkpointInfo) {
	if len(p.Earlier) == 0 {
		s.Status = Warn
		s.Detail = "No earlier checkpoint was supplied, so this relies on the witnesses (next step)"
		return
	}
	for _, e := range p.Earlier {
		s.Checked++
		n, err := note.Parse(e.Checkpoint)
		if err != nil {
			s.fail("An earlier checkpoint is malformed: %v", err)
			continue
		}
		cp, err := note.ParseCheckpoint(n.Text)
		if err != nil {
			s.fail("An earlier checkpoint is malformed: %v", err)
			continue
		}
		when := ""
		for _, vk := range trust.witnessKeys {
			if t, err := n.VerifyCosignature(vk); err == nil {
				when = " (witnessed " + fmtTime(time.Unix(int64(t), 0).UTC()) + ")"
				break
			}
		}
		switch {
		case n.VerifySignedBy(trust.LogKey) != nil || cp.Origin != trust.LogOrigin:
			s.fail("The earlier checkpoint of %d entries is not signed by the trusted log", cp.Size)
		case !latest.ok:
			s.fail("No valid current checkpoint to compare the earlier one%s against", when)
		case cp.Size > latest.cp.Size:
			s.fail("The log shrank from %d entries%s to %d: entries were removed", cp.Size, when, latest.cp.Size)
		case merkle.VerifyConsistency(cp.Size, latest.cp.Size, e.Proof, cp.Root, latest.cp.Root) != nil:
			s.fail("The checkpoint of %d entries saved earlier%s is not consistent with today's log of %d: entries were removed or changed after the fact", cp.Size, when, latest.cp.Size)
		default:
			s.Notes = append(s.Notes, fmt.Sprintf("The firm's saved checkpoint of %d entries%s is a prefix of today's %d-entry log", cp.Size, when, latest.cp.Size))
		}
	}
	if s.Status == Pass {
		s.Detail = fmt.Sprintf("%d earlier checkpoint(s) proven consistent: nothing was removed or rewritten", s.Checked)
	} else {
		s.Detail = "The log's history does not match a checkpoint saved earlier"
	}
}

func verifyWitnesses(s *Step, n *note.Note, trust *TrustPolicy) {
	s.Checked = len(trust.witnessKeys)
	valid := 0
	var bad []string
	if n != nil {
		for i, vk := range trust.witnessKeys {
			t, err := n.VerifyCosignature(vk)
			switch {
			case err == nil:
				valid++
				s.Notes = append(s.Notes, fmt.Sprintf("%s cosigned at %s", trust.Witnesses[i].Label, fmtTime(time.Unix(int64(t), 0).UTC())))
			case strings.Contains(err.Error(), "does not verify"):
				bad = append(bad, fmt.Sprintf("%s: its cosignature is for a different checkpoint", trust.Witnesses[i].Label))
			}
		}
	}
	if valid < trust.WitnessQuorum {
		s.Status = Fail
		s.Problems = append(bad, fmt.Sprintf("Only %d of %d witnesses cosigned this checkpoint; %d are required. Witnesses refuse to cosign a log that rewrote its history", valid, len(trust.witnessKeys), trust.WitnessQuorum))
		s.Detail = fmt.Sprintf("%d of %d witnesses (quorum of %d not met)", valid, len(trust.witnessKeys), trust.WitnessQuorum)
	} else {
		s.Notes = append(s.Notes, bad...)
		s.Detail = fmt.Sprintf("%d of %d independent witnesses cosigned the same log state (%d required)", valid, len(trust.witnessKeys), trust.WitnessQuorum)
	}
	for _, w := range trust.Witnesses {
		if w.Simulated {
			s.Notes = append(s.Notes, "The witnesses are simulated in this prototype (local keys)")
			break
		}
	}
}

// Canonical returns the canonical bytes of a summary value, or nil if it
// cannot be encoded.
func Canonical(v any) []byte {
	b, err := canon.Encode(v)
	if err != nil {
		return nil
	}
	return b
}
