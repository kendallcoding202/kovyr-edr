// Package note implements the parts of three C2SP specifications the log
// needs:
//
//   - c2sp.org/signed-note: a text note followed by signature lines
//     "— <name> <base64(keyID || signature)>", Ed25519 type 0x01.
//   - c2sp.org/tlog-checkpoint: the note body "<origin>\n<size>\n<root>\n".
//   - c2sp.org/tlog-cosignature: witness cosignatures (type 0x04) over
//     "cosignature/v1\ntime <t>\n" + checkpoint body, encoded as
//     base64(keyID || 8-byte big-endian time || signature).
package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
)

// Signature types from c2sp.org/signed-note.
const (
	TypeEd25519     byte = 0x01
	TypeCosignature byte = 0x04
)

const dash = "\u2014 " // em dash and space, the signature line prefix

// KeyID computes the 4-byte key ID: SHA-256(name || 0x0A || type || key)[:4].
func KeyID(name string, typ byte, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', typ})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
}

// ValidName reports whether name is a valid key name: non-empty, no
// Unicode spaces, no '+'.
func ValidName(name string) bool {
	if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, '+') {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// VerifierKey is a parsed vkey "<name>+<hex keyID>+<base64(type || key)>".
type VerifierKey struct {
	Name string
	ID   uint32
	Type byte
	Key  ed25519.PublicKey
	Vkey string
}

// FormatVKey builds a vkey string.
func FormatVKey(name string, typ byte, pub ed25519.PublicKey) string {
	return fmt.Sprintf("%s+%08x+%s", name, KeyID(name, typ, pub),
		base64.StdEncoding.EncodeToString(append([]byte{typ}, pub...)))
}

// ParseVKey parses and checks a vkey (the key ID must match the key).
func ParseVKey(s string) (*VerifierKey, error) {
	parts := strings.SplitN(s, "+", 3) // base64 may itself contain "+"
	if len(parts) != 3 || !ValidName(parts[0]) || len(parts[1]) != 8 {
		return nil, errors.New("malformed verifier key")
	}
	idb, err := hex.DecodeString(parts[1])
	if err != nil || strings.ToLower(parts[1]) != parts[1] {
		return nil, errors.New("malformed verifier key id")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(raw) != 1+ed25519.PublicKeySize {
		return nil, errors.New("malformed verifier key material")
	}
	typ := raw[0]
	if typ != TypeEd25519 && typ != TypeCosignature {
		return nil, fmt.Errorf("unsupported verifier key type 0x%02x", typ)
	}
	pub := ed25519.PublicKey(raw[1:])
	id := binary.BigEndian.Uint32(idb)
	if id != KeyID(parts[0], typ, pub) {
		return nil, errors.New("verifier key id does not match the key")
	}
	return &VerifierKey{Name: parts[0], ID: id, Type: typ, Key: pub, Vkey: s}, nil
}

// SigLine is one parsed signature line.
type SigLine struct {
	Name string
	ID   uint32
	Sig  []byte // bytes after the key ID
	Line string // the full line, without the trailing newline
}

// Note is a parsed signed note.
type Note struct {
	Text string // includes its final newline
	Sigs []SigLine
}

// Parse splits a signed note into text and signature lines.
func Parse(s string) (*Note, error) {
	if !utf8.ValidString(s) {
		return nil, errors.New("note is not valid UTF-8")
	}
	for _, r := range s {
		if r < 0x20 && r != '\n' {
			return nil, errors.New("note contains a control character")
		}
	}
	if !strings.HasSuffix(s, "\n") {
		return nil, errors.New("note does not end with a newline")
	}
	sep := strings.LastIndex(s, "\n\n")
	if sep < 0 {
		return nil, errors.New("note has no signature block")
	}
	n := &Note{Text: s[:sep+1]}
	for _, line := range strings.Split(strings.TrimSuffix(s[sep+2:], "\n"), "\n") {
		if !strings.HasPrefix(line, dash) {
			return nil, fmt.Errorf("malformed signature line %q", line)
		}
		fields := strings.Split(line[len(dash):], " ")
		if len(fields) != 2 || !ValidName(fields[0]) {
			return nil, fmt.Errorf("malformed signature line %q", line)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(fields[1])
		if err != nil || len(raw) < 5 {
			return nil, fmt.Errorf("malformed signature in line %q", line)
		}
		n.Sigs = append(n.Sigs, SigLine{
			Name: fields[0], ID: binary.BigEndian.Uint32(raw[:4]), Sig: raw[4:], Line: line,
		})
	}
	if len(n.Sigs) == 0 {
		return nil, errors.New("note has no signatures")
	}
	return n, nil
}

// String re-serializes the note.
func (n *Note) String() string {
	var b strings.Builder
	b.WriteString(n.Text)
	b.WriteString("\n")
	for _, s := range n.Sigs {
		b.WriteString(s.Line)
		b.WriteString("\n")
	}
	return b.String()
}

// SignLine produces an Ed25519 (type 0x01) signature line over text.
func SignLine(text, name string, priv ed25519.PrivateKey) SigLine {
	pub := priv.Public().(ed25519.PublicKey)
	id := KeyID(name, TypeEd25519, pub)
	sig := ed25519.Sign(priv, []byte(text))
	raw := binary.BigEndian.AppendUint32(nil, id)
	raw = append(raw, sig...)
	return SigLine{Name: name, ID: id, Sig: sig,
		Line: dash + name + " " + base64.StdEncoding.EncodeToString(raw)}
}

// Sign creates a signed note.
func Sign(text, name string, priv ed25519.PrivateKey) (string, error) {
	if !strings.HasSuffix(text, "\n") {
		return "", errors.New("note text must end with a newline")
	}
	if !ValidName(name) {
		return "", errors.New("invalid key name")
	}
	n := &Note{Text: text, Sigs: []SigLine{SignLine(text, name, priv)}}
	return n.String(), nil
}

// VerifySignedBy checks that the note carries a valid Ed25519 signature
// from vk (type 0x01).
func (n *Note) VerifySignedBy(vk *VerifierKey) error {
	if vk.Type != TypeEd25519 {
		return errors.New("verifier key is not an Ed25519 note key")
	}
	for _, s := range n.Sigs {
		if s.Name == vk.Name && s.ID == vk.ID {
			if len(s.Sig) == ed25519.SignatureSize && ed25519.Verify(vk.Key, []byte(n.Text), s.Sig) {
				return nil
			}
			return errors.New("signature by " + vk.Name + " does not verify")
		}
	}
	return errors.New("no signature by " + vk.Name)
}

// Checkpoint is a c2sp.org/tlog-checkpoint body.
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   merkle.Hash
}

// Body renders the checkpoint note text. This engine emits no extension
// lines.
func (c Checkpoint) Body() string {
	return fmt.Sprintf("%s\n%d\n%s\n", c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Root[:]))
}

// ParseCheckpoint parses a checkpoint body. Extension lines are rejected:
// this engine never writes them and its witnesses never sign them.
func ParseCheckpoint(text string) (Checkpoint, error) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if !strings.HasSuffix(text, "\n") || len(lines) != 3 {
		return Checkpoint{}, errors.New("checkpoint must be exactly origin, size and root hash lines")
	}
	if lines[0] == "" {
		return Checkpoint{}, errors.New("checkpoint origin is empty")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != lines[1] {
		return Checkpoint{}, errors.New("checkpoint size is not a canonical decimal")
	}
	root, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(root) != 32 || base64.StdEncoding.EncodeToString(root) != lines[2] {
		return Checkpoint{}, errors.New("checkpoint root hash is not canonical base64 of 32 bytes")
	}
	var c Checkpoint
	c.Origin, c.Size = lines[0], size
	copy(c.Root[:], root)
	return c, nil
}

// CosignatureMessage is the tlog-cosignature/v1 signed message.
func CosignatureMessage(body string, t uint64) []byte {
	return []byte("cosignature/v1\ntime " + strconv.FormatUint(t, 10) + "\n" + body)
}

// Cosign produces a cosignature/v1 signature line for a checkpoint body.
func Cosign(body, name string, priv ed25519.PrivateKey, t uint64) SigLine {
	pub := priv.Public().(ed25519.PublicKey)
	id := KeyID(name, TypeCosignature, pub)
	sig := ed25519.Sign(priv, CosignatureMessage(body, t))
	raw := binary.BigEndian.AppendUint32(nil, id)
	raw = binary.BigEndian.AppendUint64(raw, t)
	raw = append(raw, sig...)
	return SigLine{Name: name, ID: id, Sig: raw[4:],
		Line: dash + name + " " + base64.StdEncoding.EncodeToString(raw)}
}

// VerifyCosignature finds and checks vk's cosignature on the note and
// returns its timestamp.
func (n *Note) VerifyCosignature(vk *VerifierKey) (uint64, error) {
	if vk.Type != TypeCosignature {
		return 0, errors.New("verifier key is not a cosignature key")
	}
	for _, s := range n.Sigs {
		if s.Name == vk.Name && s.ID == vk.ID {
			if len(s.Sig) != 8+ed25519.SignatureSize {
				return 0, errors.New("malformed cosignature from " + vk.Name)
			}
			t := binary.BigEndian.Uint64(s.Sig[:8])
			if !ed25519.Verify(vk.Key, CosignatureMessage(n.Text, t), s.Sig[8:]) {
				return 0, errors.New("cosignature from " + vk.Name + " does not verify for this checkpoint")
			}
			return t, nil
		}
	}
	return 0, errors.New("no cosignature from " + vk.Name)
}

// AddSigLine appends a signature line, replacing an earlier one from the
// same key.
func (n *Note) AddSigLine(s SigLine) {
	for i, e := range n.Sigs {
		if e.Name == s.Name && e.ID == s.ID {
			n.Sigs[i] = s
			return
		}
	}
	n.Sigs = append(n.Sigs, s)
}
