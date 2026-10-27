package tlog

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

// Ingest limits. A statement must arrive within MaxClockSkew of the
// server's clock, using a nonce issued at most NonceLifetime ago.
const (
	NonceLifetime = 10 * time.Minute
	MaxClockSkew  = 5 * time.Minute
)

// Evidence is the private record of one log entry: what a Proof Pack
// discloses for it.
type Evidence struct {
	Index      uint64
	Envelope   *dsse.Envelope
	Timestamps []map[string]any
	Statement  *posture.Statement
	// LostBefore is how many of the attester's reports never reached the
	// log just before this one: the lost-report gap ingest recorded when
	// it accepted a seq jump (SPEC 8). It is the server's own record,
	// recomputed when evidence is loaded; it is not part of a pack, where
	// verifiers find the hole from the numbering themselves.
	LostBefore int64
}

// Value returns the evidence as a JSON value (for storage and packs).
func (e *Evidence) Value() map[string]any {
	ts := make([]any, len(e.Timestamps))
	for i, t := range e.Timestamps {
		ts[i] = t
	}
	return map[string]any{"index": int64(e.Index), "envelope": e.Envelope.Value(), "timestamps": ts}
}

// Attester is the server's registry record for an enrolled key.
type Attester struct {
	ID          string
	Tenant      string
	Kind        string
	Key         *sigs.PublicKey
	EnrolledAt  time.Time
	LastSeq     int64
	LastPayload posture.Digest
}

type issuedNonce struct {
	subject string
	at      time.Time
	used    bool
}

// Server validates submissions, obtains timestamps, appends commitments to
// the log and keeps the evidence.
type Server struct {
	Log       *Log
	tsas      []tsa.Authority
	clock     func() time.Time
	rand      io.Reader
	tenants   map[string]*sigs.PublicKey
	attesters map[string]*Attester // by tenant + "/" + attester ID
	nonces    map[string]*issuedNonce
	evidence  []*Evidence

	// NonceSource, if set, replaces rand for issuing nonces. The demo
	// generator uses it to make the sample reproducible.
	NonceSource func(subject string, at time.Time) posture.Nonce
}

// NewServer wraps a log. rand supplies nonces (crypto/rand in production; a
// seeded stream in the demo generator so the sample is reproducible).
func NewServer(l *Log, tsas []tsa.Authority, clock func() time.Time, rand io.Reader) *Server {
	return &Server{Log: l, tsas: tsas, clock: clock, rand: rand,
		tenants: map[string]*sigs.PublicKey{}, attesters: map[string]*Attester{}, nonces: map[string]*issuedNonce{}}
}

// IssueNonce returns a fresh single-use challenge for subject (the tenant
// or attester ID that will use it).
func (s *Server) IssueNonce(subject string) (posture.Nonce, error) {
	var n posture.Nonce
	if s.NonceSource != nil {
		n = s.NonceSource(subject, s.clock())
	} else if _, err := io.ReadFull(s.rand, n[:]); err != nil {
		return n, err
	}
	if _, dup := s.nonces[hex.EncodeToString(n[:])]; dup {
		return n, errors.New("nonce source repeated a nonce")
	}
	s.nonces[hex.EncodeToString(n[:])] = &issuedNonce{subject: subject, at: s.clock()}
	return n, nil
}

// Attester returns the registry record for an attester in a tenant. One
// key may be enrolled in many tenants (the vendor's scanner key is), so
// records and their sequence numbers are per tenant.
func (s *Server) Attester(tenant, id string) *Attester { return s.attesters[tenant+"/"+id] }

// Evidence returns all stored evidence in log order.
func (s *Server) Evidence() []*Evidence { return s.evidence }

// Submit runs every ingest check, then timestamps and logs the envelope.
// A Server is not safe for concurrent use; serialize calls.
func (s *Server) Submit(ctx context.Context, env *dsse.Envelope) (*Evidence, error) {
	st, err := s.check(env)
	if err != nil {
		return nil, err
	}
	return s.commit(ctx, env, st)
}

// AppendWithoutChecks logs an envelope while skipping the ingest checks
// (nonce, sequence, clock). It simulates a compromised or bypassed ingest
// server, so tests and the demo can show that verifiers still catch what
// ingest would have refused. Never call it from a real server.
func (s *Server) AppendWithoutChecks(ctx context.Context, env *dsse.Envelope) (*Evidence, error) {
	st, err := posture.Validate(env.Payload)
	if err != nil {
		return nil, err
	}
	return s.commit(ctx, env, st)
}

func (s *Server) check(env *dsse.Envelope) (*posture.Statement, error) {
	if env.PayloadType != dsse.PayloadTypeInToto {
		return nil, fmt.Errorf("payload type %q is not accepted", env.PayloadType)
	}
	st, err := posture.Validate(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("statement rejected: %w", err)
	}
	now := s.clock()
	nonce := st.Str("nonce")
	var subject string
	var when time.Time

	switch {
	case !st.IsPosture() && st.Str("kind") == "tenant_genesis":
		key, err := sigs.ParsePublicKeyBase64(st.Str("tenant_key"))
		if err != nil {
			return nil, err
		}
		subject, when = posture.TenantID(key), st.Time("enrolled_at")
		if st.Str("tenant") != subject {
			return nil, errors.New("tenant ID does not match the tenant key")
		}
		if _, dup := s.tenants[subject]; dup {
			return nil, errors.New("tenant already exists")
		}
		if len(env.Signatures) != 1 || env.VerifySignature(0, key) != nil {
			return nil, errors.New("tenant genesis must carry one valid signature by the tenant key")
		}
	case !st.IsPosture():
		tenantKey, ok := s.tenants[st.Str("tenant")]
		if !ok {
			return nil, errors.New("enrollment for an unknown tenant")
		}
		key, err := sigs.ParsePublicKeyBase64(st.Str("attester_key"))
		if err != nil {
			return nil, err
		}
		subject, when = st.Str("attester"), st.Time("enrolled_at")
		if posture.AttesterID(posture.AttesterKind(st.Str("attester_kind")), key) != subject {
			return nil, errors.New("attester ID does not match the attester key")
		}
		if _, dup := s.attesters[st.Str("tenant")+"/"+subject]; dup {
			return nil, errors.New("attester already enrolled in this tenant")
		}
		if len(env.Signatures) != 2 || env.VerifySignature(0, tenantKey) != nil || env.VerifySignature(1, key) != nil {
			return nil, errors.New("enrollment needs a valid tenant signature followed by the attester's proof-of-possession signature")
		}
	default:
		a, ok := s.attesters[st.Str("tenant")+"/"+st.Str("attester")]
		if !ok {
			return nil, errors.New("statement from an attester that is not enrolled")
		}
		subject, when = a.ID, st.Time("observed_at")
		if st.Str("tenant") != a.Tenant || st.Str("attester_kind") != a.Kind {
			return nil, errors.New("statement does not match the attester's enrollment")
		}
		if len(env.Signatures) != 1 || env.VerifySignature(0, a.Key) != nil {
			return nil, errors.New("statement signature is not valid for the enrolled key")
		}
		// SPEC 8: a seq at or below the last is a replay. A seq more than
		// one ahead means reports were lost before they reached the log;
		// it is accepted (index records the hole), because refusing it
		// would lock the attester out for good. prev can be checked only
		// against a report the server holds.
		switch seq := st.Int("seq"); {
		case seq <= a.LastSeq:
			return nil, fmt.Errorf("sequence %d rejected: not after the last accepted %d (replay)", seq, a.LastSeq)
		case seq == a.LastSeq+1 && st.Str("prev") != hex.EncodeToString(a.LastPayload[:]):
			return nil, errors.New("prev does not match the attester's previous statement")
		}
	}

	n, ok := s.nonces[nonce]
	switch {
	case !ok:
		return nil, errors.New("nonce was not issued by this server")
	case n.used:
		return nil, errors.New("nonce already used (replay)")
	case n.subject != subject:
		return nil, errors.New("nonce was issued to a different subject")
	case now.Sub(n.at) > NonceLifetime:
		return nil, errors.New("nonce expired")
	}
	if d := now.Sub(when); d > MaxClockSkew || d < -MaxClockSkew {
		return nil, fmt.Errorf("statement time is %s away from the server clock (backdated or clock wrong)", d.Round(time.Second))
	}
	return st, nil
}

func (s *Server) commit(ctx context.Context, env *dsse.Envelope, st *posture.Statement) (*Evidence, error) {
	if len(s.tsas) < 2 {
		return nil, errors.New("at least two timestamp authorities are required")
	}
	digest := EntryDigest(env)
	var tokens []map[string]any
	for _, a := range s.tsas {
		tok, err := a.Timestamp(ctx, digest)
		if err != nil {
			return nil, fmt.Errorf("timestamp from %s: %w", a.Name(), err)
		}
		tokens = append(tokens, tok)
	}
	if n, ok := s.nonces[st.Str("nonce")]; ok {
		n.used = true
	}
	ev := &Evidence{Index: s.Log.Append(digest), Envelope: env, Timestamps: tokens, Statement: st}
	s.evidence = append(s.evidence, ev)
	s.index(ev)
	return ev, nil
}

// index updates the registries from a logged entry.
func (s *Server) index(ev *Evidence) {
	st := ev.Statement
	switch {
	case !st.IsPosture() && st.Str("kind") == "tenant_genesis":
		key, _ := sigs.ParsePublicKeyBase64(st.Str("tenant_key"))
		s.tenants[st.Str("tenant")] = key
	case !st.IsPosture():
		key, _ := sigs.ParsePublicKeyBase64(st.Str("attester_key"))
		s.attesters[st.Str("tenant")+"/"+st.Str("attester")] = &Attester{
			ID: st.Str("attester"), Tenant: st.Str("tenant"), Kind: st.Str("attester_kind"), Key: key,
			EnrolledAt: st.Time("enrolled_at"), LastPayload: posture.PayloadDigest(ev.Envelope.Payload),
		}
	default:
		if a := s.attesters[st.Str("tenant")+"/"+st.Str("attester")]; a != nil && st.Int("seq") > a.LastSeq {
			ev.LostBefore = st.Int("seq") - a.LastSeq - 1
			a.LastSeq = st.Int("seq")
			a.LastPayload = posture.PayloadDigest(ev.Envelope.Payload)
		}
	}
}

// Import appends existing evidence verbatim (same envelope and timestamp
// tokens) at the next index. Mirrors use it, and the demo uses it to build
// a forked copy of a log.
func (s *Server) Import(ev *Evidence) (*Evidence, error) {
	st, err := posture.Validate(ev.Envelope.Payload)
	if err != nil {
		return nil, err
	}
	cp := &Evidence{Index: s.Log.Size(), Envelope: ev.Envelope, Timestamps: ev.Timestamps, Statement: st}
	return cp, s.restore(cp)
}

// restore re-adds evidence loaded from disk (already validated when it was
// first logged).
func (s *Server) restore(ev *Evidence) error {
	if ev.Index != s.Log.Size() {
		return fmt.Errorf("evidence %d out of order", ev.Index)
	}
	s.Log.Append(EntryDigest(ev.Envelope))
	s.evidence = append(s.evidence, ev)
	s.index(ev)
	return nil
}

// LeafHashes returns all leaf hashes (for tests and mirrors).
func (s *Server) LeafHashes() []merkle.Hash {
	out := make([]merkle.Hash, 0, s.Log.Size())
	for _, d := range s.Log.Digests() {
		out = append(out, LeafHash(d))
	}
	return out
}
