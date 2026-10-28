package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kendallcoding202/kovyr-edr/internal/fsutil"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Queue caps (CLAUDE.md: cap every queue). At one heartbeat per 15
// minutes, 500 entries cover about five days offline; an envelope is about
// 2 KB, so the byte cap only bites if something is badly wrong.
const (
	DefaultQueueMaxEntries = 500
	DefaultQueueMaxBytes   = 5 << 20
)

// Queue is the on-disk outbox of signed envelopes, one file per seq (the
// agent sends it newest first; see Agent.Flush). When a cap is exceeded
// the oldest entries are dropped; the receiver then sees the missing seqs,
// which is the honest outcome.
type Queue struct {
	dir        string
	maxEntries int
	maxBytes   int64
}

var entryName = regexp.MustCompile(`^[0-9]{10}\.dsse\.json$`)

// OpenQueue opens (and creates) the queue directory.
func OpenQueue(dir string, maxEntries int, maxBytes int64) (*Queue, error) {
	if maxEntries < 1 || maxBytes < proof.MaxEnvelopeBytes {
		return nil, fmt.Errorf("queue caps too small (%d entries, %d bytes)", maxEntries, maxBytes)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, maxEntries: maxEntries, maxBytes: maxBytes}
	q.removeTemps()
	return q, nil
}

type entry struct {
	seq  uint32
	name string
	size int64
}

func (q *Queue) list() ([]entry, error) {
	des, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, de := range des {
		if !de.Type().IsRegular() || !entryName.MatchString(de.Name()) {
			continue
		}
		n, err := strconv.ParseUint(de.Name()[:10], 10, 32)
		if err != nil {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, entry{seq: uint32(n), name: de.Name(), size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out, nil
}

// removeTemps deletes leftovers of interrupted atomic writes.
func (q *Queue) removeTemps() {
	des, _ := os.ReadDir(q.dir)
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".tmp-") {
			os.Remove(filepath.Join(q.dir, de.Name()))
		}
	}
}

// Push stores an envelope and enforces the caps. It returns how many old
// entries were dropped.
func (q *Queue) Push(seq uint32, envelope []byte) (int, error) {
	if len(envelope) > proof.MaxEnvelopeBytes {
		return 0, fmt.Errorf("envelope of %d bytes exceeds the %d byte limit", len(envelope), proof.MaxEnvelopeBytes)
	}
	name := fmt.Sprintf("%010d.dsse.json", seq)
	if err := fsutil.WriteFileAtomic(filepath.Join(q.dir, name), envelope); err != nil {
		return 0, err
	}
	return q.enforceCaps()
}

func (q *Queue) enforceCaps() (int, error) {
	es, err := q.list()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range es {
		total += e.size
	}
	dropped := 0
	for len(es) > 0 && (len(es) > q.maxEntries || total > q.maxBytes) {
		if err := os.Remove(filepath.Join(q.dir, es[0].name)); err != nil && !os.IsNotExist(err) {
			return dropped, err
		}
		total -= es[0].size
		es = es[1:]
		dropped++
	}
	return dropped, nil
}

// Oldest returns the oldest queued envelope.
func (q *Queue) Oldest() (seq uint32, envelope []byte, ok bool, err error) {
	return q.pick(func(es []entry) entry { return es[0] })
}

// Newest returns the newest queued envelope.
func (q *Queue) Newest() (seq uint32, envelope []byte, ok bool, err error) {
	return q.pick(func(es []entry) entry { return es[len(es)-1] })
}

func (q *Queue) pick(choose func([]entry) entry) (uint32, []byte, bool, error) {
	es, err := q.list()
	if err != nil || len(es) == 0 {
		return 0, nil, false, err
	}
	e := choose(es)
	b, err := fsutil.ReadFileCapped(filepath.Join(q.dir, e.name), proof.MaxEnvelopeBytes)
	if err != nil {
		return 0, nil, false, err
	}
	return e.seq, b, true, nil
}

// Seqs returns the queued seqs, oldest first.
func (q *Queue) Seqs() ([]uint32, error) {
	es, err := q.list()
	out := make([]uint32, len(es))
	for i, e := range es {
		out[i] = e.seq
	}
	return out, err
}

// Get reads the entry for seq.
func (q *Queue) Get(seq uint32) ([]byte, error) {
	return fsutil.ReadFileCapped(filepath.Join(q.dir, fmt.Sprintf("%010d.dsse.json", seq)), proof.MaxEnvelopeBytes)
}

// Remove deletes the entry for seq (after delivery or a permanent refusal).
func (q *Queue) Remove(seq uint32) error {
	err := os.Remove(filepath.Join(q.dir, fmt.Sprintf("%010d.dsse.json", seq)))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Len returns the number of queued envelopes.
func (q *Queue) Len() int {
	es, _ := q.list()
	return len(es)
}
