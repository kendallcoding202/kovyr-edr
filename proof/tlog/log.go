// Package tlog is the transparency log and the ingest server in front of it.
//
// The public log stores commitments only. Each leaf is the 32-byte entry
// digest SHA-256(canonical DSSE envelope); statements carry a 256-bit salt,
// so a digest reveals nothing about the posture inside. The log publishes
// those digests as static files in the C2SP tlog-tiles layout (checkpoint,
// hash tiles and entry bundles), which any web server or bucket can serve.
//
// The full envelopes and their timestamp tokens are evidence. The ingest
// server keeps them in a private store, the firm's app keeps a copy, and
// the firm shares them only inside a Proof Pack.
package tlog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/note"
)

// EntryDigest is the commitment a log leaf holds for an envelope, and also
// the imprint timestamp authorities sign.
func EntryDigest(env *dsse.Envelope) merkle.Hash { return sha256.Sum256(env.Canonical()) }

// LeafHash is the RFC 6962 leaf hash of an entry digest.
func LeafHash(digest merkle.Hash) merkle.Hash { return merkle.LeafHash(digest[:]) }

// Log is an append-only Merkle log of entry digests with signed
// checkpoints.
type Log struct {
	origin  string
	key     ed25519.PrivateKey
	clock   func() time.Time
	tree    *merkle.Tree
	digests []merkle.Hash
	latest  *note.Note
	history map[uint64]string // checkpoint notes by tree size, as cosigned
	vkey    string            // for read-only copies, which have no key
}

// NewLog creates an empty log. The key name is the origin, as is
// conventional for C2SP logs.
func NewLog(origin string, key ed25519.PrivateKey, clock func() time.Time) (*Log, error) {
	if !note.ValidName(origin) {
		return nil, fmt.Errorf("invalid log origin %q", origin)
	}
	return &Log{origin: origin, key: key, clock: clock, tree: merkle.NewTree(), history: map[uint64]string{}}, nil
}

// Origin returns the log origin.
func (l *Log) Origin() string { return l.origin }

// VKey returns the log's verifier key.
func (l *Log) VKey() string {
	if l.key == nil {
		return l.vkey
	}
	return note.FormatVKey(l.origin, note.TypeEd25519, l.key.Public().(ed25519.PublicKey))
}

// Append adds an entry digest and returns its index.
func (l *Log) Append(d merkle.Hash) uint64 {
	l.digests = append(l.digests, d)
	return l.tree.Append(LeafHash(d))
}

// Size is the number of entries.
func (l *Log) Size() uint64 { return l.tree.Size() }

// Digests returns the public leaf data (entry digests).
func (l *Log) Digests() []merkle.Hash { return append([]merkle.Hash(nil), l.digests...) }

// Root returns the tree root at size.
func (l *Log) Root(size uint64) (merkle.Hash, error) { return l.tree.Root(size) }

// InclusionProof proves entry i is in the tree of the given size.
func (l *Log) InclusionProof(i, size uint64) ([]merkle.Hash, error) {
	return l.tree.InclusionProof(i, size)
}

// ConsistencyProof proves the tree of size m is a prefix of size n.
func (l *Log) ConsistencyProof(m, n uint64) ([]merkle.Hash, error) {
	return l.tree.ConsistencyProof(m, n)
}

// SignCheckpoint signs a checkpoint at the current size and makes it the
// latest. Witness cosignatures are added with AddCosignature.
func (l *Log) SignCheckpoint() (string, error) {
	if l.key == nil {
		return "", fmt.Errorf("this copy of the log is read-only (no log key)")
	}
	root, _ := l.tree.Root(l.tree.Size())
	body := note.Checkpoint{Origin: l.origin, Size: l.tree.Size(), Root: root}.Body()
	signed, err := note.Sign(body, l.origin, l.key)
	if err != nil {
		return "", err
	}
	n, _ := note.Parse(signed)
	l.latest = n
	l.history[l.tree.Size()] = signed
	return signed, nil
}

// Latest returns the latest checkpoint with any cosignatures.
func (l *Log) Latest() string {
	if l.latest == nil {
		return ""
	}
	return l.latest.String()
}

// CheckpointAt returns the cosigned checkpoint published at a size.
func (l *Log) CheckpointAt(size uint64) (string, bool) {
	s, ok := l.history[size]
	return s, ok
}

// AddCosignature attaches a witness cosignature line to the latest
// checkpoint. The caller (the witness) has already checked consistency;
// verifiers check the cosignature itself.
func (l *Log) AddCosignature(s note.SigLine) {
	l.latest.AddSigLine(s)
	l.history[l.tree.Size()] = l.latest.String()
}

// SetLatest replaces the latest checkpoint note (used when loading a log
// from disk and by the demo generator's "vendor rewrites history" world).
func (l *Log) SetLatest(signed string) error {
	n, err := note.Parse(signed)
	if err != nil {
		return err
	}
	cp, err := note.ParseCheckpoint(n.Text)
	if err != nil {
		return err
	}
	l.latest = n
	l.history[cp.Size] = signed
	return nil
}

// TilePath encodes a tile index the tlog-tiles way: 1234067 -> x001/x234/067.
func TilePath(n uint64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n /= 1000; n > 0; n /= 1000 {
		s = fmt.Sprintf("x%03d/", n%1000) + s
	}
	return s
}

// WriteTiles publishes the log at its latest checkpoint as static files in
// the C2SP tlog-tiles layout under dir: "checkpoint", "tile/<L>/<N>[.p/<W>]"
// hash tiles and "tile/entries/<N>[.p/<W>]" entry bundles. These files are
// everything the public sees: checkpoints and 32-byte digests.
func (l *Log) WriteTiles(dir string) error {
	if l.latest == nil {
		return fmt.Errorf("no checkpoint to publish")
	}
	cp, err := note.ParseCheckpoint(l.latest.Text)
	if err != nil {
		return err
	}
	size := cp.Size
	write := func(rel string, b []byte) error {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, b, 0o644)
	}
	// Entry bundles: each entry is a big-endian uint16 length and the
	// 32-byte digest.
	for start := uint64(0); start < size; start += 256 {
		end := min(start+256, size)
		var b []byte
		for i := start; i < end; i++ {
			b = binary.BigEndian.AppendUint16(b, 32)
			b = append(b, l.digests[i][:]...)
		}
		if err := write(tileName("entries", start/256, end-start), b); err != nil {
			return err
		}
	}
	// Hash tiles. A level-l hash covers 256^l leaves.
	for level, span := 0, uint64(1); span <= size; level, span = level+1, span*256 {
		count := size / span // complete level-l hashes available
		for start := uint64(0); start < count; start += 256 {
			end := min(start+256, count)
			var b []byte
			for k := start; k < end; k++ {
				var h merkle.Hash
				if span == 1 {
					h = l.tree.LeafHashAt(k)
				} else {
					h, _ = l.tree.SubtreeRoot(k*span, (k+1)*span)
				}
				b = append(b, h[:]...)
			}
			if err := write(tileName(fmt.Sprint(level), start/256, end-start), b); err != nil {
				return err
			}
		}
	}
	return write("checkpoint", []byte(l.latest.String()))
}

func tileName(level string, n, width uint64) string {
	p := "tile/" + level + "/" + TilePath(n)
	if width < 256 {
		p += fmt.Sprintf(".p/%d", width)
	}
	return p
}

// ReadEntryBundles reads every digest back from published tiles. It is used
// by tests to show what an outsider can learn from the public log.
func ReadEntryBundles(dir string, size uint64) ([]merkle.Hash, error) {
	var out []merkle.Hash
	for start := uint64(0); start < size; start += 256 {
		end := min(start+256, size)
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(tileName("entries", start/256, end-start))))
		if err != nil {
			return nil, err
		}
		for len(b) > 0 {
			if len(b) < 2 {
				return nil, fmt.Errorf("truncated entry bundle")
			}
			n := int(binary.BigEndian.Uint16(b))
			if n != 32 || len(b) < 2+n {
				return nil, fmt.Errorf("unexpected entry of %d bytes", n)
			}
			var h merkle.Hash
			copy(h[:], b[2:2+n])
			out = append(out, h)
			b = b[2+n:]
		}
	}
	return out, nil
}

// PublicTree is a read-only view of a log rebuilt from its published
// tiles: what a witness, auditor or mirror sees.
type PublicTree struct {
	Checkpoint string
	Size       uint64
	Tree       *merkle.Tree
}

// ReadPublic loads a published log directory (checkpoint plus tiles) and
// checks that the tiles reproduce the checkpoint's root hash.
func ReadPublic(dir string) (*PublicTree, error) {
	b, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		return nil, err
	}
	n, err := note.Parse(string(b))
	if err != nil {
		return nil, err
	}
	cp, err := note.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, err
	}
	digests, err := ReadEntryBundles(dir, cp.Size)
	if err != nil {
		return nil, err
	}
	t := merkle.NewTree()
	for _, d := range digests {
		t.Append(LeafHash(d))
	}
	if root, _ := t.Root(cp.Size); root != cp.Root {
		return nil, fmt.Errorf("published tiles do not match the checkpoint root")
	}
	return &PublicTree{Checkpoint: string(b), Size: cp.Size, Tree: t}, nil
}
