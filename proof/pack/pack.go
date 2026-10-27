// Package pack builds and verifies Proof Packs.
//
// A Proof Pack is what a firm shares privately with an insurer, client or
// regulator: the full signed statements for a date range, their timestamp
// tokens, Merkle inclusion proofs against a witnessed checkpoint of the
// public log, earlier checkpoints the firm kept, and an owner-facing
// summary. Verification is fully offline and needs only the pack and a
// trust policy (the log key, witness keys and timestamp authorities, which
// a real verifier pins in its own code).
package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/brand"
	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/tlog"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

// Format identifiers.
const (
	PackType           = "proof-pack/v1"
	NameCommitmentType = "tenant-name-commitment/v1"
	DateLayout         = "2006-01-02"
)

// Entry is one disclosed log entry.
type Entry struct {
	Evidence *tlog.Evidence
	Proof    []merkle.Hash
}

// EarlierCheckpoint is a checkpoint the firm (or the recipient) saved
// before, with a proof that today's tree extends it.
type EarlierCheckpoint struct {
	Checkpoint string
	Proof      []merkle.Hash
}

// Pack is a parsed Proof Pack.
type Pack struct {
	Sample          bool
	Product         string
	IssuedAt        time.Time
	From, To        string
	TenantID        string
	DisplayName     string
	DisplayNameSalt string
	LogOrigin       string
	Checkpoint      string
	Earlier         []EarlierCheckpoint
	Entries         []Entry
	Summary         any // canonical-JSON value; nil before Build fills it
}

// NameCommitment binds the firm's display name to its tenant without
// putting the name in any statement: SHA-256 of
// "tenant-name-commitment/v1\n" || salt (hex) || "\n" || UTF-8 name.
func NameCommitment(name, saltHex string) posture.Digest {
	return sha256.Sum256([]byte(NameCommitmentType + "\n" + saltHex + "\n" + name))
}

func encodeHashes(hs []merkle.Hash) []any {
	out := make([]any, len(hs))
	for i, h := range hs {
		out[i] = base64.StdEncoding.EncodeToString(h[:])
	}
	return out
}

func decodeHashes(v any) ([]merkle.Hash, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("proof must be an array of base64 hashes")
	}
	if len(arr) > 64 {
		return nil, errors.New("proof is too long")
	}
	out := make([]merkle.Hash, len(arr))
	for i, e := range arr {
		s, _ := e.(string)
		b, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
			return nil, errors.New("proof hash is not canonical base64 of 32 bytes")
		}
		copy(out[i][:], b)
	}
	return out, nil
}

// EntryValue is the JSON form of a pack entry.
func (e Entry) Value() map[string]any {
	v := e.Evidence.Value()
	v["inclusion_proof"] = encodeHashes(e.Proof)
	return v
}

// MarshalJSON renders the pack with one entry per line, so diffs of
// generated packs stay readable.
func (p *Pack) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	enc := func(v any) string {
		var buf bytes.Buffer
		e := json.NewEncoder(&buf)
		e.SetEscapeHTML(false)
		_ = e.Encode(v)
		return strings.TrimSuffix(buf.String(), "\n")
	}
	earlier := make([]any, len(p.Earlier))
	for i, e := range p.Earlier {
		earlier[i] = map[string]any{"checkpoint": e.Checkpoint, "consistency_proof": encodeHashes(e.Proof)}
	}
	b.WriteString("{\n")
	fmt.Fprintf(&b, " %q: %q,\n", "pack_type", PackType)
	fmt.Fprintf(&b, " %q: %q,\n", "canonicalization", canon.Version)
	fmt.Fprintf(&b, " %q: %s,\n", "product", enc(p.Product))
	fmt.Fprintf(&b, " %q: %t,\n", "sample", p.Sample)
	fmt.Fprintf(&b, " %q: %q,\n", "issued_at", p.IssuedAt.UTC().Format(tsa.TimeLayout))
	fmt.Fprintf(&b, " %q: %s,\n", "range", enc(map[string]any{"from": p.From, "to": p.To}))
	fmt.Fprintf(&b, " %q: %s,\n", "tenant", enc(map[string]any{"id": p.TenantID, "display_name": p.DisplayName, "display_name_salt": p.DisplayNameSalt}))
	fmt.Fprintf(&b, " %q: %s,\n", "log", enc(map[string]any{"origin": p.LogOrigin, "checkpoint": p.Checkpoint, "earlier_checkpoints": earlier}))
	b.WriteString(" \"entries\": [\n")
	for i, e := range p.Entries {
		b.WriteString("  ")
		b.Write(canon.MustEncode(e.Value()))
		if i < len(p.Entries)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString(" ],\n")
	summary, _ := json.MarshalIndent(p.Summary, " ", " ")
	fmt.Fprintf(&b, " %q: %s\n}\n", "summary", summary)
	return b.Bytes(), nil
}

// Parse decodes a Proof Pack strictly: valid UTF-8, no duplicate keys, no
// unknown or missing fields, integers only.
func Parse(b []byte) (*Pack, error) {
	v, err := canon.ParseContainer(b)
	if err != nil {
		return nil, fmt.Errorf("proof pack: %w", err)
	}
	top, err := fields(v, "pack", "pack_type", "canonicalization", "product", "sample", "issued_at", "range", "tenant", "log", "entries", "summary")
	if err != nil {
		return nil, err
	}
	if top["pack_type"] != PackType {
		return nil, fmt.Errorf("not a %s file", PackType)
	}
	if top["canonicalization"] != canon.Version {
		return nil, fmt.Errorf("unsupported canonicalization %v", top["canonicalization"])
	}
	p := &Pack{Summary: top["summary"]}
	var ok bool
	if p.Product, ok = top["product"].(string); !ok {
		return nil, errors.New("product must be a string")
	}
	if p.Sample, ok = top["sample"].(bool); !ok {
		return nil, errors.New("sample must be true or false")
	}
	is, _ := top["issued_at"].(string)
	if p.IssuedAt, err = tsa.ParseTime(is); err != nil {
		return nil, fmt.Errorf("issued_at: %w", err)
	}
	rng, err := fields(top["range"], "range", "from", "to")
	if err != nil {
		return nil, err
	}
	p.From, _ = rng["from"].(string)
	p.To, _ = rng["to"].(string)
	f, err1 := time.Parse(DateLayout, p.From)
	t, err2 := time.Parse(DateLayout, p.To)
	if err1 != nil || err2 != nil || f.Format(DateLayout) != p.From || t.Format(DateLayout) != p.To || t.Before(f) || t.Sub(f) > 366*24*time.Hour {
		return nil, errors.New("range must be two dates YYYY-MM-DD, in order, at most a year apart")
	}
	ten, err := fields(top["tenant"], "tenant", "id", "display_name", "display_name_salt")
	if err != nil {
		return nil, err
	}
	p.TenantID, _ = ten["id"].(string)
	p.DisplayName, _ = ten["display_name"].(string)
	p.DisplayNameSalt, _ = ten["display_name_salt"].(string)
	lg, err := fields(top["log"], "log", "origin", "checkpoint", "earlier_checkpoints")
	if err != nil {
		return nil, err
	}
	p.LogOrigin, _ = lg["origin"].(string)
	p.Checkpoint, _ = lg["checkpoint"].(string)
	earlier, ok := lg["earlier_checkpoints"].([]any)
	if !ok {
		return nil, errors.New("earlier_checkpoints must be an array")
	}
	for _, e := range earlier {
		eo, err := fields(e, "earlier checkpoint", "checkpoint", "consistency_proof")
		if err != nil {
			return nil, err
		}
		cp, _ := eo["checkpoint"].(string)
		proof, err := decodeHashes(eo["consistency_proof"])
		if err != nil {
			return nil, err
		}
		p.Earlier = append(p.Earlier, EarlierCheckpoint{Checkpoint: cp, Proof: proof})
	}
	entries, ok := top["entries"].([]any)
	if !ok {
		return nil, errors.New("entries must be an array")
	}
	for i, e := range entries {
		eo, err := fields(e, fmt.Sprintf("entry %d", i), "index", "envelope", "timestamps", "inclusion_proof")
		if err != nil {
			return nil, err
		}
		proof, err := decodeHashes(eo["inclusion_proof"])
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		delete(eo, "inclusion_proof")
		ev, err := tlog.EvidenceFromValue(eo)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		p.Entries = append(p.Entries, Entry{Evidence: ev, Proof: proof})
	}
	return p, nil
}

// fields requires v to be an object with exactly the named keys.
func fields(v any, what string, keys ...string) (map[string]any, error) {
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", what)
	}
	if len(o) != len(keys) {
		return nil, fmt.Errorf("%s must have exactly the fields %s", what, strings.Join(keys, ", "))
	}
	out := make(map[string]any, len(o))
	for _, k := range keys {
		val, ok := o[k]
		if !ok {
			return nil, fmt.Errorf("%s is missing %q", what, k)
		}
		out[k] = val
	}
	return out, nil
}

// Source is where the pack builder reads the log and evidence from: the
// firm's own copy, or the ingest server's private store.
type Source interface {
	Evidence() []*tlog.Evidence
	LogView() LogView
}

// LogView is the read side of the public log.
type LogView interface {
	Latest() string
	InclusionProof(i, size uint64) ([]merkle.Hash, error)
	ConsistencyProof(m, n uint64) ([]merkle.Hash, error)
	Origin() string
}

// ServerSource adapts a tlog.Server.
type ServerSource struct{ S *tlog.Server }

func (s ServerSource) Evidence() []*tlog.Evidence { return s.S.Evidence() }
func (s ServerSource) LogView() LogView           { return s.S.Log }

// Request says what to put in a pack.
type Request struct {
	TenantID        string
	DisplayName     string
	DisplayNameSalt string
	From, To        string
	IssuedAt        time.Time
	Sample          bool
	Earlier         []string // checkpoint notes the firm saved earlier
}

// Build assembles a pack: the tenant's genesis and enrollments, its posture
// statements dated within the range, proofs against the log's latest
// checkpoint, and a summary computed by running the verifier itself, so the
// summary says exactly what any verifier will find.
func Build(src Source, trust *TrustPolicy, req Request) (*Pack, error) {
	lv := src.LogView()
	latest := lv.Latest()
	size, err := checkpointSize(latest)
	if err != nil {
		return nil, fmt.Errorf("latest checkpoint: %w", err)
	}
	from, _ := time.Parse(DateLayout, req.From)
	to, _ := time.Parse(DateLayout, req.To)
	p := &Pack{
		Sample: req.Sample, Product: brand.Product, IssuedAt: req.IssuedAt, From: req.From, To: req.To,
		TenantID: req.TenantID, DisplayName: req.DisplayName, DisplayNameSalt: req.DisplayNameSalt,
		LogOrigin: lv.Origin(), Checkpoint: latest, Summary: map[string]any{},
	}
	for _, ev := range src.Evidence() {
		st := ev.Statement
		if st == nil || st.Str("tenant") != req.TenantID || ev.Index >= size {
			continue
		}
		if st.IsPosture() {
			day := st.Time("observed_at").Truncate(24 * time.Hour)
			if day.Before(from) || day.After(to) {
				continue
			}
		} else if st.Time("enrolled_at").After(to.Add(24 * time.Hour)) {
			continue
		}
		proof, err := lv.InclusionProof(ev.Index, size)
		if err != nil {
			return nil, err
		}
		p.Entries = append(p.Entries, Entry{Evidence: ev, Proof: proof})
	}
	sort.SliceStable(p.Entries, func(i, j int) bool { return p.Entries[i].Evidence.Index < p.Entries[j].Evidence.Index })
	for _, e := range req.Earlier {
		m, err := checkpointSize(e)
		if err != nil {
			return nil, fmt.Errorf("earlier checkpoint: %w", err)
		}
		proof, err := lv.ConsistencyProof(m, size)
		if err != nil {
			return nil, err
		}
		p.Earlier = append(p.Earlier, EarlierCheckpoint{Checkpoint: e, Proof: proof})
	}
	p.Summary = Verify(p, trust).Computed
	return p, nil
}

func checkpointSize(signed string) (uint64, error) {
	cp, err := parseCheckpointNote(signed)
	if err != nil {
		return 0, err
	}
	return cp.Size, nil
}

// NewSalt returns a random hex salt for the display-name commitment.
func NewSalt(b [32]byte) string { return hex.EncodeToString(b[:]) }
