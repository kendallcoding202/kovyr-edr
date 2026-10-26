// Package dsse implements Dead Simple Signing Envelopes (DSSE v1) with the
// key and signature encodings of package sigs.
//
// The signature covers PAE(payloadType, payload), never the JSON envelope,
// so the envelope's own formatting cannot change what was signed. Envelopes
// are nevertheless stored in canonical JSON because the log hashes them.
package dsse

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

// PayloadTypeInToto is the only payload type this engine signs or accepts.
const PayloadTypeInToto = "application/vnd.in-toto+json"

// Signature is one DSSE signature.
type Signature struct {
	KeyID string
	Sig   []byte
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string
	Payload     []byte
	Signatures  []Signature
}

// PAE is the DSSE v1 pre-authentication encoding:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
func PAE(payloadType string, payload []byte) []byte {
	out := []byte("DSSEv1 ")
	out = strconv.AppendInt(out, int64(len(payloadType)), 10)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = strconv.AppendInt(out, int64(len(payload)), 10)
	out = append(out, ' ')
	return append(out, payload...)
}

// Sign signs payload with each signer in order.
func Sign(payloadType string, payload []byte, signers ...sigs.Signer) (*Envelope, error) {
	if len(signers) == 0 {
		return nil, errors.New("dsse: no signers")
	}
	env := &Envelope{PayloadType: payloadType, Payload: payload}
	pae := PAE(payloadType, payload)
	for _, s := range signers {
		sig, err := s.Sign(pae)
		if err != nil {
			return nil, err
		}
		env.Signatures = append(env.Signatures, Signature{KeyID: s.Public().KeyID(), Sig: sig})
	}
	return env, nil
}

// VerifySignature checks signature i against key: the keyid must name the
// key and the signature must verify over the PAE.
func (e *Envelope) VerifySignature(i int, key *sigs.PublicKey) error {
	if i >= len(e.Signatures) {
		return fmt.Errorf("signature %d missing", i)
	}
	s := e.Signatures[i]
	if s.KeyID != key.KeyID() {
		return fmt.Errorf("signature %d keyid does not match the expected key", i)
	}
	return key.Verify(PAE(e.PayloadType, e.Payload), s.Sig)
}

// Value returns the envelope as a canonical-JSON value.
func (e *Envelope) Value() map[string]any {
	ss := make([]any, len(e.Signatures))
	for i, s := range e.Signatures {
		ss[i] = map[string]any{"keyid": s.KeyID, "sig": base64.StdEncoding.EncodeToString(s.Sig)}
	}
	return map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(e.Payload),
		"payloadType": e.PayloadType,
		"signatures":  ss,
	}
}

// Canonical returns the canonical JSON bytes of the envelope.
func (e *Envelope) Canonical() []byte { return canon.MustEncode(e.Value()) }

// FromValue decodes an envelope from a parsed JSON value, strictly: exactly
// the DSSE keys, canonical base64, at least one signature.
func FromValue(v any) (*Envelope, error) {
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("envelope is not an object")
	}
	if err := exactKeys(o, "payload", "payloadType", "signatures"); err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	pt, ok := o["payloadType"].(string)
	if !ok || canon.CheckString(pt) != nil {
		return nil, errors.New("envelope: payloadType must be a printable ASCII string")
	}
	ps, ok := o["payload"].(string)
	if !ok {
		return nil, errors.New("envelope: payload is not a string")
	}
	payload, err := sigs.DecodeBase64(ps)
	if err != nil {
		return nil, fmt.Errorf("envelope payload: %w", err)
	}
	arr, ok := o["signatures"].([]any)
	if !ok || len(arr) == 0 {
		return nil, errors.New("envelope: signatures must be a non-empty array")
	}
	env := &Envelope{PayloadType: pt, Payload: payload}
	for i, sv := range arr {
		so, ok := sv.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("envelope signature %d is not an object", i)
		}
		if err := exactKeys(so, "keyid", "sig"); err != nil {
			return nil, fmt.Errorf("envelope signature %d: %w", i, err)
		}
		kid, ok1 := so["keyid"].(string)
		sb, ok2 := so["sig"].(string)
		if !ok1 || !ok2 || canon.CheckString(kid) != nil {
			return nil, fmt.Errorf("envelope signature %d: keyid and sig must be printable ASCII strings", i)
		}
		sig, err := sigs.DecodeBase64(sb)
		if err != nil {
			return nil, fmt.Errorf("envelope signature %d: %w", i, err)
		}
		env.Signatures = append(env.Signatures, Signature{KeyID: kid, Sig: sig})
	}
	return env, nil
}

// Parse decodes canonical envelope bytes.
func Parse(b []byte) (*Envelope, error) {
	v, err := canon.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	return FromValue(v)
}

func exactKeys(o map[string]any, keys ...string) error {
	if len(o) != len(keys) {
		return fmt.Errorf("expected exactly the fields %v", keys)
	}
	for _, k := range keys {
		if _, ok := o[k]; !ok {
			return fmt.Errorf("missing field %q", k)
		}
	}
	return nil
}
