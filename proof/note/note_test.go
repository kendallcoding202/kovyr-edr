package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
)

// The example from c2sp.org/signed-note.
const (
	exampleVKey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
	exampleNote = "This is an example message.\n\n" + dash +
		"example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
)

func TestC2SPExampleNote(t *testing.T) {
	vk, err := ParseVKey(exampleVKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Parse(exampleNote)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.VerifySignedBy(vk); err != nil {
		t.Fatal(err)
	}
	if n.String() != exampleNote {
		t.Fatal("note did not round-trip")
	}
	bad, _ := Parse(strings.Replace(exampleNote, "example message", "exemple message", 1))
	if bad.VerifySignedBy(vk) == nil {
		t.Fatal("modified note verified")
	}
}

func key(seed string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(s[:])
}

func TestCheckpointAndCosignature(t *testing.T) {
	logKey, wKey := key("log"), key("witness")
	cp := Checkpoint{Origin: "example.com/log", Size: 42, Root: merkle.LeafHash([]byte("x"))}
	signed, err := Sign(cp.Body(), "example.com/log", logKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	logVK, _ := ParseVKey(FormatVKey("example.com/log", TypeEd25519, logKey.Public().(ed25519.PublicKey)))
	if err := n.VerifySignedBy(logVK); err != nil {
		t.Fatal(err)
	}
	got, err := ParseCheckpoint(n.Text)
	if err != nil || got != cp {
		t.Fatalf("checkpoint round trip: %v %+v", err, got)
	}

	n.AddSigLine(Cosign(n.Text, "witness.example", wKey, 1793232000))
	wVK, _ := ParseVKey(FormatVKey("witness.example", TypeCosignature, wKey.Public().(ed25519.PublicKey)))
	n2, err := Parse(n.String())
	if err != nil {
		t.Fatal(err)
	}
	ts, err := n2.VerifyCosignature(wVK)
	if err != nil || ts != 1793232000 {
		t.Fatalf("cosignature: %v %d", err, ts)
	}
	// The cosignature must not verify for a different checkpoint.
	other := Checkpoint{Origin: cp.Origin, Size: 43, Root: cp.Root}
	forged := &Note{Text: other.Body(), Sigs: n2.Sigs}
	if _, err := forged.VerifyCosignature(wVK); err == nil {
		t.Fatal("cosignature moved to another checkpoint verified")
	}
	// A cosignature key cannot pass as a log key and vice versa.
	if n2.VerifySignedBy(wVK) == nil {
		t.Fatal("cosignature key accepted as note key")
	}
}

func TestCheckpointStrictness(t *testing.T) {
	for _, bad := range []string{
		"o\n042\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		"o\n1\nAAAA\n",
		"o\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nextension\n",
		"\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
	} {
		if _, err := ParseCheckpoint(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := ParseVKey("example.com/foo+530d903b+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"); err == nil {
		t.Error("vkey with wrong id accepted")
	}
}
