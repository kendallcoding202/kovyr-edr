package keys

import (
	"path/filepath"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

func TestKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, alg := range []sigs.Alg{sigs.ES256, sigs.Ed25519} {
		kf, err := Generate(alg, "device", "test")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, string(alg)+".key.json")
		if err := kf.Save(p); err != nil {
			t.Fatal(err)
		}
		s, err := LoadSigner(p)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := kf.Signer()
		if s.Public().KeyID() != want.Public().KeyID() {
			t.Fatal("key id mismatch after round trip")
		}
	}
}
