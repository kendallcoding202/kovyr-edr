package witness

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
	"github.com/kendallcoding202/kovyr-edr/proof/tlog"
)

func key(s string) ed25519.PrivateKey {
	h := sha256.Sum256([]byte(s))
	return ed25519.NewKeyFromSeed(h[:])
}

func TestWitnessRefusesForks(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 10, 20, 23, 50, 0, 0, time.UTC) }
	honest, _ := tlog.NewLog("example.com/log", key("log"), clock)
	forked, _ := tlog.NewLog("example.com/log", key("log"), clock)
	for i := 0; i < 20; i++ {
		d := sha256.Sum256([]byte(fmt.Sprint(i)))
		honest.Append(d)
		if i != 7 {
			forked.Append(d)
		}
	}
	w, _ := New("witness.example", key("w"), clock)
	first, _ := honest.SignCheckpoint()
	if _, err := w.Cosign(first, honest.VKey(), nil); err != nil {
		t.Fatal(err)
	}

	// The honest log grows and proves consistency: cosigned.
	for i := 20; i < 25; i++ {
		honest.Append(sha256.Sum256([]byte(fmt.Sprint(i))))
	}
	second, _ := honest.SignCheckpoint()
	p, _ := honest.ConsistencyProof(20, 25)
	line, err := w.Cosign(second, honest.VKey(), p)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := note.Parse(second)
	n.AddSigLine(line)
	vk, _ := note.ParseVKey(w.VKey())
	if _, err := n.VerifyCosignature(vk); err != nil {
		t.Fatal(err)
	}

	// The forked log (an entry deleted) is signed by the real log key but
	// cannot prove consistency, so the witness refuses.
	for forked.Size() < 30 {
		forked.Append(sha256.Sum256([]byte(fmt.Sprint("f", forked.Size()))))
	}
	fork, _ := forked.SignCheckpoint()
	fp, _ := forked.ConsistencyProof(25, 30)
	if _, err := w.Cosign(fork, forked.VKey(), fp); !errors.Is(err, ErrFork) {
		t.Fatalf("witness cosigned a fork: %v", err)
	}
	// Nor will it cosign a smaller tree (rollback).
	small, _ := tlog.NewLog("example.com/log", key("log"), clock)
	small.Append(sha256.Sum256([]byte("0")))
	sc, _ := small.SignCheckpoint()
	if _, err := w.Cosign(sc, small.VKey(), []merkle.Hash{}); !errors.Is(err, ErrFork) {
		t.Fatalf("witness cosigned a rollback: %v", err)
	}
}
