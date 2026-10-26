package tlog

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

// On-disk layout of a log directory:
//
//	log.json                    origin and verifier key (public)
//	public/                     what gets served: checkpoint + tlog-tiles
//	private/evidence/<n>.json   envelopes and timestamp tokens (never served)
//	private/checkpoints/<size>  every checkpoint as cosigned
//	private/nonces.json         issued challenges

type logConfig struct {
	Origin string `json:"origin"`
	VKey   string `json:"vkey"`
}

// EvidenceFromValue decodes stored or packed evidence strictly.
func EvidenceFromValue(v any) (*Evidence, error) {
	o, ok := v.(map[string]any)
	if !ok || len(o) != 3 {
		return nil, errors.New("evidence must have exactly index, envelope and timestamps")
	}
	idx, ok := o["index"].(int64)
	if !ok || idx < 0 {
		return nil, errors.New("evidence index must be a non-negative integer")
	}
	env, err := dsse.FromValue(o["envelope"])
	if err != nil {
		return nil, err
	}
	arr, ok := o["timestamps"].([]any)
	if !ok {
		return nil, errors.New("evidence timestamps must be an array")
	}
	ev := &Evidence{Index: uint64(idx), Envelope: env}
	for _, t := range arr {
		tm, ok := t.(map[string]any)
		if !ok {
			return nil, errors.New("timestamp token must be an object")
		}
		if _, err := canon.Encode(tm); err != nil {
			return nil, fmt.Errorf("timestamp token is not canonical JSON data: %w", err)
		}
		ev.Timestamps = append(ev.Timestamps, tm)
	}
	return ev, nil
}

// Save writes the log directory.
func (s *Server) Save(dir string) error {
	for _, d := range []string{"public", "private/evidence", "private/checkpoints"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return err
		}
	}
	cfg, _ := json.MarshalIndent(logConfig{Origin: s.Log.Origin(), VKey: s.Log.VKey()}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "log.json"), append(cfg, '\n'), 0o644); err != nil {
		return err
	}
	for _, ev := range s.evidence {
		p := filepath.Join(dir, "private", "evidence", fmt.Sprintf("%012d.json", ev.Index))
		if _, err := os.Stat(p); err == nil {
			continue // evidence is immutable
		}
		if err := os.WriteFile(p, append(canon.MustEncode(ev.Value()), '\n'), 0o600); err != nil {
			return err
		}
	}
	for size, n := range s.Log.history {
		p := filepath.Join(dir, "private", "checkpoints", fmt.Sprint(size))
		if err := os.WriteFile(p, []byte(n), 0o644); err != nil {
			return err
		}
	}
	type nonceRec struct {
		Subject string `json:"subject"`
		At      string `json:"issued_at"`
		Used    bool   `json:"used"`
	}
	ns := map[string]nonceRec{}
	for k, n := range s.nonces {
		ns[k] = nonceRec{n.subject, n.at.UTC().Format(tsa.TimeLayout), n.used}
	}
	nb, _ := json.MarshalIndent(ns, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "private", "nonces.json"), nb, 0o600); err != nil {
		return err
	}
	if s.Log.latest != nil {
		return s.Log.WriteTiles(filepath.Join(dir, "public"))
	}
	return nil
}

// Load opens a log directory written by Save. logKey may be nil for a
// read-only copy (building packs, computing proofs).
func Load(dir string, logKey ed25519.PrivateKey, tsas []tsa.Authority, clock func() time.Time, rand io.Reader) (*Server, error) {
	cb, err := os.ReadFile(filepath.Join(dir, "log.json"))
	if err != nil {
		return nil, err
	}
	var cfg logConfig
	if err := json.Unmarshal(cb, &cfg); err != nil {
		return nil, err
	}
	l, err := NewLog(cfg.Origin, logKey, clock)
	if err != nil {
		return nil, err
	}
	l.vkey = cfg.VKey
	if l.VKey() != cfg.VKey {
		return nil, errors.New("log key does not match log.json")
	}
	s := NewServer(l, tsas, clock, rand)
	files, _ := filepath.Glob(filepath.Join(dir, "private", "evidence", "*.json"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		v, err := canon.Parse([]byte(strings.TrimSuffix(string(b), "\n")))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		ev, err := EvidenceFromValue(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if ev.Statement, err = posture.Validate(ev.Envelope.Payload); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if err := s.restore(ev); err != nil {
			return nil, err
		}
	}
	cps, _ := filepath.Glob(filepath.Join(dir, "private", "checkpoints", "*"))
	for _, f := range cps {
		b, _ := os.ReadFile(f)
		n, err := note.Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		cp, err := note.ParseCheckpoint(n.Text)
		if err != nil {
			return nil, err
		}
		l.history[cp.Size] = string(b)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "public", "checkpoint")); err == nil {
		if err := l.SetLatest(string(b)); err != nil {
			return nil, err
		}
	}
	if nb, err := os.ReadFile(filepath.Join(dir, "private", "nonces.json")); err == nil {
		var ns map[string]struct {
			Subject string `json:"subject"`
			At      string `json:"issued_at"`
			Used    bool   `json:"used"`
		}
		if err := json.Unmarshal(nb, &ns); err != nil {
			return nil, err
		}
		for k, n := range ns {
			at, _ := tsa.ParseTime(n.At)
			if _, err := hex.DecodeString(k); err != nil {
				return nil, errors.New("bad nonce record")
			}
			s.nonces[k] = &issuedNonce{subject: n.Subject, at: at, used: n.Used}
		}
	}
	return s, nil
}
