// Package witness implements an independent checkpoint witness
// (c2sp.org/tlog-cosignature). A witness remembers the latest tree it has
// cosigned for each log and cosigns a new checkpoint only if the log proves
// the new tree extends the old one. A log that rewrites history therefore
// loses its witnesses, and verifiers that require a quorum of witness
// cosignatures reject what it publishes.
package witness

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
)

// Witness is one cosigner.
type Witness struct {
	Name  string
	key   ed25519.PrivateKey
	clock func() time.Time
	Seen  map[string]Seen // by log origin
}

// Seen is the witness's saved tree head for one log.
type Seen struct {
	Size uint64 `json:"size"`
	Root string `json:"root"` // base64
}

// New creates a witness.
func New(name string, key ed25519.PrivateKey, clock func() time.Time) (*Witness, error) {
	if !note.ValidName(name) {
		return nil, fmt.Errorf("invalid witness name %q", name)
	}
	return &Witness{Name: name, key: key, clock: clock, Seen: map[string]Seen{}}, nil
}

// VKey is the witness's cosignature verifier key.
func (w *Witness) VKey() string {
	return note.FormatVKey(w.Name, note.TypeCosignature, w.key.Public().(ed25519.PublicKey))
}

// SetClock replaces the clock.
func (w *Witness) SetClock(c func() time.Time) { w.clock = c }

// ErrFork is returned when a checkpoint does not extend the saved tree.
var ErrFork = errors.New("checkpoint is not consistent with the tree this witness already cosigned; refusing to cosign")

// Cosign checks a signed checkpoint and returns a cosignature line.
// proof must prove consistency from the witness's saved size to the new
// size (it is ignored the first time a witness sees a log).
func (w *Witness) Cosign(signedCheckpoint string, logVKey string, proof []merkle.Hash) (note.SigLine, error) {
	vk, err := note.ParseVKey(logVKey)
	if err != nil {
		return note.SigLine{}, err
	}
	n, err := note.Parse(signedCheckpoint)
	if err != nil {
		return note.SigLine{}, err
	}
	if err := n.VerifySignedBy(vk); err != nil {
		return note.SigLine{}, fmt.Errorf("checkpoint not signed by the log: %w", err)
	}
	cp, err := note.ParseCheckpoint(n.Text)
	if err != nil {
		return note.SigLine{}, err
	}
	if cp.Origin != vk.Name {
		return note.SigLine{}, errors.New("checkpoint origin does not match the log key")
	}
	if old, ok := w.Seen[cp.Origin]; ok {
		oldRoot, err := decodeRoot(old.Root)
		if err != nil {
			return note.SigLine{}, err
		}
		if cp.Size < old.Size {
			return note.SigLine{}, ErrFork
		}
		if err := merkle.VerifyConsistency(old.Size, cp.Size, proof, oldRoot, cp.Root); err != nil {
			return note.SigLine{}, ErrFork
		}
	}
	w.Seen[cp.Origin] = Seen{Size: cp.Size, Root: base64.StdEncoding.EncodeToString(cp.Root[:])}
	return note.Cosign(n.Text, w.Name, w.key, uint64(w.clock().Unix())), nil
}

func decodeRoot(s string) (merkle.Hash, error) {
	var h merkle.Hash
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, errors.New("bad saved root")
	}
	copy(h[:], b)
	return h, nil
}

// SaveState writes the witness's saved tree heads.
func (w *Witness) SaveState(path string) error {
	b, err := json.MarshalIndent(w.Seen, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadState reads saved tree heads; a missing file means a fresh witness.
func (w *Witness) LoadState(path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &w.Seen)
}
