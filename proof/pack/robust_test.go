package pack_test

import (
	"math/rand"
	"os"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/pack"
)

func miniTrust(t testing.TB) *pack.TrustPolicy {
	b, err := os.ReadFile("../testdata/vectors/mini-trust-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	trust, err := pack.ParseTrustPolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

// A verifier reads files from strangers. Corrupting the pack at random must
// produce errors or failed checks, never a crash or a pass.
func TestMutatedPacksNeverPanicOrPass(t *testing.T) {
	trust := miniTrust(t)
	orig, err := os.ReadFile("../testdata/vectors/mini-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 400; i++ {
		b := append([]byte(nil), orig...)
		for j := 0; j < 1+rng.Intn(3); j++ {
			b[rng.Intn(len(b))] ^= byte(1 + rng.Intn(255))
		}
		p, err := pack.Parse(b)
		if err != nil {
			continue
		}
		if r := pack.Verify(p, trust); r.Verified && string(b) != string(orig) {
			// Only whitespace-like changes inside the container may still pass.
			if q, _ := pack.Parse(orig); q != nil {
				if string(pack.Canonical(p.Summary)) != string(pack.Canonical(q.Summary)) || len(p.Entries) != len(q.Entries) {
					t.Fatalf("mutation %d verified with different content", i)
				}
			}
		}
	}
}

// FuzzParseAndVerify runs with `go test -fuzz=FuzzParseAndVerify ./pack`.
func FuzzParseAndVerify(f *testing.F) {
	orig, err := os.ReadFile("../testdata/vectors/mini-pack.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(orig)
	f.Add([]byte(`{"pack_type":"proof-pack/v1"}`))
	trust := miniTrust(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := pack.Parse(b); err == nil {
			pack.Verify(p, trust)
		}
	})
}
