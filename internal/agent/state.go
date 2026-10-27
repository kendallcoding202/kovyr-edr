package agent

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kendallcoding202/kovyr-edr/internal/fsutil"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// stateFile holds the hash-chain head: the last seq signed and the digest
// of its payload. It is written after the envelope is safely queued, so a
// crash can lose at most the state write, which reconcile repairs.
const stateFile = "chain-state.json"

// ChainState is the persisted chain head.
type ChainState struct {
	KeyID string `json:"device_keyid"` // the key this chain belongs to
	Seq   uint32 `json:"seq"`          // last signed seq; 0 before the first statement
	Prev  string `json:"prev"`         // hex PayloadDigest of that statement
}

func newState(keyID string) ChainState {
	return ChainState{KeyID: keyID, Prev: hex.EncodeToString(proof.GenesisPrev[:])}
}

func (s ChainState) prevDigest() (proof.Digest, error) {
	var d proof.Digest
	b, err := hex.DecodeString(s.Prev)
	if err != nil || len(b) != len(d) {
		return d, errors.New("chain state: bad prev digest")
	}
	copy(d[:], b)
	return d, nil
}

func loadState(dir, keyID string) (ChainState, error) {
	b, err := fsutil.ReadFileCapped(filepath.Join(dir, stateFile), 4<<10)
	if errors.Is(err, os.ErrNotExist) {
		return newState(keyID), nil
	}
	if err != nil {
		return ChainState{}, err
	}
	var s ChainState
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return ChainState{}, fmt.Errorf("chain state: %w", err)
	}
	if s.KeyID != keyID {
		// Mixing chains would look like tampering at the receiver. A new
		// key is a new device: its state must start fresh.
		return ChainState{}, errors.New("chain state belongs to a different device key; move the old state directory aside")
	}
	if _, err := s.prevDigest(); err != nil {
		return ChainState{}, err
	}
	return s, nil
}

func saveState(dir string, s ChainState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, stateFile), append(b, '\n'))
}
