package proof

// DSSE v1 envelopes, ported from proof-of-protection/engine/dsse (see the
// TODO in canon.go). The signature covers PAE(payloadType, payload), never
// the JSON envelope, and envelopes travel in canonical JSON.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

// PayloadTypeInToto is the only payload type signed or accepted.
const PayloadTypeInToto = "application/vnd.in-toto+json"

// MaxEnvelopeBytes bounds an envelope on disk and on the wire. A
// sensor_health envelope is about 2 KB.
const MaxEnvelopeBytes = 16 << 10

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

// SignEnvelope signs an in-toto payload with the device key.
func SignEnvelope(payload []byte, s Signer) (*Envelope, error) {
	sig, err := s.Sign(PAE(PayloadTypeInToto, payload))
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &Envelope{
		PayloadType: PayloadTypeInToto,
		Payload:     payload,
		Signatures:  []Signature{{KeyID: s.Public().KeyID(), Sig: sig}},
	}, nil
}

// Verify checks that the envelope has exactly one signature, by key, that
// verifies over the PAE.
func (e *Envelope) Verify(key *PublicKey) error {
	if e.PayloadType != PayloadTypeInToto {
		return fmt.Errorf("payloadType must be %s", PayloadTypeInToto)
	}
	if len(e.Signatures) != 1 {
		return errors.New("a device envelope carries exactly one signature")
	}
	s := e.Signatures[0]
	if s.KeyID != key.KeyID() {
		return errors.New("signature keyid does not name the expected key")
	}
	return key.Verify(PAE(e.PayloadType, e.Payload), s.Sig)
}

// Canonical returns the envelope in canonical JSON.
func (e *Envelope) Canonical() []byte {
	ss := make([]any, len(e.Signatures))
	for i, s := range e.Signatures {
		ss[i] = map[string]any{"keyid": s.KeyID, "sig": base64.StdEncoding.EncodeToString(s.Sig)}
	}
	b, err := EncodeCanonical(map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(e.Payload),
		"payloadType": e.PayloadType,
		"signatures":  ss,
	})
	if err != nil {
		panic("proof: envelope does not encode: " + err.Error()) // only our own values reach here
	}
	return b
}

// ParseEnvelope decodes canonical envelope bytes strictly: size-capped,
// exactly the DSSE keys, canonical base64, at least one signature.
func ParseEnvelope(b []byte) (*Envelope, error) {
	if len(b) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("envelope: larger than %d bytes", MaxEnvelopeBytes)
	}
	o, err := ParseCanonicalObject(b)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	if err := exactKeys(o, "payload", "payloadType", "signatures"); err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	pt, _ := o["payloadType"].(string)
	ps, ok := o["payload"].(string)
	if !ok {
		return nil, errors.New("envelope: payload is not a string")
	}
	payload, err := DecodeBase64(ps)
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
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("envelope signature %d: keyid and sig must be strings", i)
		}
		sig, err := DecodeBase64(sb)
		if err != nil {
			return nil, fmt.Errorf("envelope signature %d: %w", i, err)
		}
		env.Signatures = append(env.Signatures, Signature{KeyID: kid, Sig: sig})
	}
	return env, nil
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
