package proof

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"testing"
)

// The golden heartbeat pins the exact bytes the agent signs and sends.
// Keys come from a fixed seed and ES256 signing is deterministic (RFC
// 6979), so the payload and the whole envelope are reproducible. Any
// change to canonical JSON, DSSE, signing or the statement layout shows
// up here; a change that is meant to alter the wire format regenerates
// the file with -update and says so in its commit.

var update = flag.Bool("update", false, "rewrite testdata/golden-heartbeat.json")

const goldenFile = "testdata/golden-heartbeat.json"

// seededP256 derives a deterministic P-256 key, the way the proof engine's
// test vectors do.
func seededP256(label string) *ecdsa.PrivateKey {
	s := sha256.Sum256([]byte("proof-test-vector-key/v1\n" + label))
	d := s[:]
	for {
		if k, err := ecdh.P256().NewPrivateKey(d); err == nil {
			pub := k.PublicKey().Bytes()
			return &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pub[1:33]), Y: new(big.Int).SetBytes(pub[33:])},
				D:         new(big.Int).SetBytes(d),
			}
		}
		h := sha256.Sum256(d)
		d = h[:]
	}
}

func fill(b []byte, label string) {
	h := sha256.Sum256([]byte(label))
	copy(b, h[:])
}

type golden struct {
	Payload  string `json:"payload"`
	Envelope string `json:"envelope"`
}

func goldenHeartbeat(t *testing.T) golden {
	t.Helper()
	s, err := NewSoftwareSigner(seededP256("kovyr-golden-heartbeat"))
	if err != nil {
		t.Fatal(err)
	}
	h := testHeader(7)
	fill(h.Prev[:], "golden-prev")
	fill(h.Nonce[:], "golden-nonce")
	fill(h.Salt[:], "golden-salt")
	payload, err := BuildStatement(s.Public(), h, SensorHealth{SensorRunning: true, PolicyVersion: 3}, healthyReadings())
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignEnvelope(payload, s)
	if err != nil {
		t.Fatal(err)
	}
	return golden{Payload: string(payload), Envelope: string(env.Canonical())}
}

func TestGoldenHeartbeatBytes(t *testing.T) {
	got := goldenHeartbeat(t)
	if *update {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(goldenFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatal(err)
	}
	var want golden
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if got.Payload != want.Payload {
		t.Errorf("payload bytes changed:\n got %s\nwant %s", got.Payload, want.Payload)
	}
	if got.Envelope != want.Envelope {
		t.Errorf("envelope bytes changed:\n got %s\nwant %s", got.Envelope, want.Envelope)
	}
}
