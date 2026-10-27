package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

func TestQueueCapsEntriesDroppingOldest(t *testing.T) {
	q, err := OpenQueue(t.TempDir(), 500, DefaultQueueMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	dropped := 0
	for seq := uint32(1); seq <= 510; seq++ {
		n, err := q.Push(seq, []byte(`{"seq":1}`))
		if err != nil {
			t.Fatal(err)
		}
		dropped += n
	}
	if q.Len() != 500 || dropped != 10 {
		t.Fatalf("len %d dropped %d, want 500 and 10", q.Len(), dropped)
	}
	seq, _, ok, _ := q.Oldest()
	if !ok || seq != 11 {
		t.Fatalf("oldest is %d, want 11 (1-10 dropped)", seq)
	}
	seq, _, _, _ = q.Newest()
	if seq != 510 {
		t.Fatalf("newest is %d", seq)
	}
}

func TestQueueCapsBytes(t *testing.T) {
	const max = proof.MaxEnvelopeBytes * 2
	q, err := OpenQueue(t.TempDir(), 500, max)
	if err != nil {
		t.Fatal(err)
	}
	env := bytes.Repeat([]byte("a"), proof.MaxEnvelopeBytes/2) // 4 fit in max
	for seq := uint32(1); seq <= 9; seq++ {
		if _, err := q.Push(seq, env); err != nil {
			t.Fatal(err)
		}
	}
	if q.Len() != 4 {
		t.Fatalf("len %d, want 4", q.Len())
	}
	seq, _, _, _ := q.Oldest()
	if seq != 6 {
		t.Fatalf("oldest %d, want 6", seq)
	}
	if _, err := q.Push(10, bytes.Repeat([]byte("a"), proof.MaxEnvelopeBytes+1)); err == nil {
		t.Fatal("accepted an oversized envelope")
	}
}

func TestQueueOldestFirstAndIgnoresStrays(t *testing.T) {
	dir := t.TempDir()
	q, _ := OpenQueue(dir, 10, DefaultQueueMaxBytes)
	for _, seq := range []uint32{30, 4, 17} {
		q.Push(seq, []byte{byte(seq)})
	}
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "1.dsse.json"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, ".tmp-0000000001.dsse.json-123"), []byte("x"), 0o600)
	q, _ = OpenQueue(dir, 10, DefaultQueueMaxBytes)
	if _, err := os.Stat(filepath.Join(dir, ".tmp-0000000001.dsse.json-123")); !os.IsNotExist(err) {
		t.Error("leftover temp file was not cleaned up")
	}
	var order []uint32
	for {
		seq, env, ok, err := q.Oldest()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if env[0] != byte(seq) {
			t.Fatalf("seq %d has the wrong content", seq)
		}
		order = append(order, seq)
		q.Remove(seq)
	}
	if len(order) != 3 || order[0] != 4 || order[1] != 17 || order[2] != 30 {
		t.Fatalf("order %v, want [4 17 30]", order)
	}
}

func TestQueueRefusesTinyCaps(t *testing.T) {
	if _, err := OpenQueue(t.TempDir(), 0, DefaultQueueMaxBytes); err == nil {
		t.Error("accepted zero entries")
	}
	if _, err := OpenQueue(t.TempDir(), 10, 100); err == nil {
		t.Error("accepted a byte cap smaller than one envelope")
	}
}
