package receiver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Device is one enrolled device in the devices file. Label is the owner's
// name for the machine; it is shown in status and never appears in a
// signed statement.
type Device struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"` // base64 SPKI, from `kovyr-agent enroll --print-pubkey`
	Label     string `json:"label,omitempty"`
}

func (d Device) parse() (*proof.PublicKey, error) {
	k, err := proof.ParsePublicKeyBase64(d.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("device %s: %w", d.DeviceID, err)
	}
	if proof.DeviceID(k) != d.DeviceID {
		return nil, fmt.Errorf("device %s: device_id does not match its public key (want %s)", d.DeviceID, proof.DeviceID(k))
	}
	return k, nil
}

// LoadDevices reads {"devices":[...]} from path.
func LoadDevices(path string) ([]Device, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Devices []Device `json:"devices"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, d := range f.Devices {
		if _, err := d.parse(); err != nil {
			return nil, err
		}
	}
	return f.Devices, nil
}

// Record is one line of the store.
type Record struct {
	ReceivedAt time.Time `json:"received_at"`
	DeviceID   string    `json:"device_id"`
	Outcome    string    `json:"outcome"`
	Seq        uint32    `json:"seq,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Events     []Event   `json:"events,omitempty"`
	Envelope   string    `json:"envelope,omitempty"` // canonical DSSE envelope, accepted only
}

// MaxStoreBytes stops the dev store growing without bound; beyond it the
// receiver answers 507 and agents keep their statements queued.
const MaxStoreBytes = 256 << 20

// Store is an append-only JSON-lines file.
type Store struct {
	mu   sync.Mutex
	path string
}

// OpenStore opens (creating) the store file.
func OpenStore(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	return &Store{path: path}, nil
}

// Append writes one record and syncs it.
func (s *Store) Append(rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fi, err := os.Stat(s.path); err == nil && fi.Size() > MaxStoreBytes {
		return errors.New("store is full (dev limit)")
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// Replay calls fn for every stored record, in order.
func (s *Store) Replay(fn func(Record)) error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("%s line %d: %w", s.path, line, err)
		}
		fn(rec)
	}
	return sc.Err()
}
