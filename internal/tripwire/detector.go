package tripwire

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Counts are changes per Kind.
type Counts [numKinds]uint32

// Activity is what the rules weigh: renames plus content writes.
func (c Counts) Activity() uint32 { return c[Renamed] + c[ExtensionChanged] + c[Modified] }

// Renames are all renames, with or without an extension change.
func (c Counts) Renames() uint32 { return c[Renamed] + c[ExtensionChanged] }

func (c Counts) total() uint64 {
	var t uint64
	for _, n := range c {
		t += uint64(n)
	}
	return t
}

// Thresholds decide when the tripwire trips. The defaults are
// conservative: a person working, or a sync engine downloading a folder,
// stays far below them (docs/tripwire.md).
type Thresholds struct {
	// Window is the sliding window: one of Windows.
	Window time.Duration
	// Mass extension change: at least MinActivity renames and writes in
	// the window, at least MinExtensionChanged renames to a new
	// extension, and those at least ExtensionChangedPercent of renames.
	MinActivity             uint32
	MinExtensionChanged     uint32
	ExtensionChangedPercent uint32
	// Ransom notes: at least MinSuspiciousCreated ransom-note or random
	// names created while at least NotesActivity renames and writes
	// happen in the window.
	MinSuspiciousCreated uint32
	NotesActivity        uint32
	// Cooldown: at most one immediate tripwire heartbeat per Cooldown.
	// Later trips go into the next heartbeat.
	Cooldown time.Duration
}

// Default thresholds.
const (
	DefaultWindow                  = time.Minute
	DefaultMinActivity             = 100
	DefaultMinExtensionChanged     = 50
	DefaultExtensionChangedPercent = 60
	DefaultMinSuspiciousCreated    = 3
	DefaultNotesActivity           = 30
	DefaultCooldown                = 10 * time.Minute
)

// Windows are the allowed window sizes, with their statement enum.
var Windows = map[time.Duration]proof.TripWindow{
	10 * time.Second: proof.TripWindow10s, 30 * time.Second: proof.TripWindow30s, time.Minute: proof.TripWindow60s,
	2 * time.Minute: proof.TripWindow120s, 5 * time.Minute: proof.TripWindow300s,
}

// maxWindowSeconds sizes the per-second ring: the largest window.
const maxWindowSeconds = 300

// MaxFolders caps how many folders are watched (SPEC 6.5).
const MaxFolders = proof.MaxTripwireFolders

// WithDefaults fills zero values and checks the ranges.
func (t Thresholds) WithDefaults() (Thresholds, error) {
	def := func(v *uint32, d uint32) {
		if *v == 0 {
			*v = d
		}
	}
	if t.Window == 0 {
		t.Window = DefaultWindow
	}
	def(&t.MinActivity, DefaultMinActivity)
	def(&t.MinExtensionChanged, DefaultMinExtensionChanged)
	def(&t.ExtensionChangedPercent, DefaultExtensionChangedPercent)
	def(&t.MinSuspiciousCreated, DefaultMinSuspiciousCreated)
	def(&t.NotesActivity, DefaultNotesActivity)
	if t.Cooldown == 0 {
		t.Cooldown = DefaultCooldown
	}
	switch _, ok := Windows[t.Window]; {
	case !ok:
		return t, fmt.Errorf("tripwire window must be 10s, 30s, 60s, 120s or 300s")
	case t.MinActivity < 20 || t.MinActivity > 100000:
		return t, fmt.Errorf("tripwire min activity must be 20 to 100000")
	case t.MinExtensionChanged < 10 || t.MinExtensionChanged > t.MinActivity:
		return t, fmt.Errorf("tripwire min extension changes must be 10 to the min activity")
	case t.ExtensionChangedPercent < 10 || t.ExtensionChangedPercent > 100:
		return t, fmt.Errorf("tripwire extension change share must be 10 to 100 percent")
	case t.MinSuspiciousCreated < 1 || t.MinSuspiciousCreated > 1000:
		return t, fmt.Errorf("tripwire suspicious creations must be 1 to 1000")
	case t.NotesActivity < 1 || t.NotesActivity > 100000:
		return t, fmt.Errorf("tripwire notes activity must be 1 to 100000")
	case t.Cooldown < time.Minute || t.Cooldown > 24*time.Hour:
		return t, fmt.Errorf("tripwire cooldown must be 1m to 24h")
	}
	return t, nil
}

// rule applies the thresholds to one window's counts.
func (t Thresholds) rule(c Counts) proof.TripReason {
	act := c.Activity()
	ext := c[ExtensionChanged]
	if act >= t.MinActivity && ext >= t.MinExtensionChanged &&
		uint64(ext)*100 >= uint64(t.ExtensionChangedPercent)*uint64(c.Renames()) {
		return proof.TripMassExtensionChange
	}
	if c[SuspiciousCreated] >= t.MinSuspiciousCreated && act >= t.NotesActivity {
		return proof.TripRansomNotes
	}
	return proof.TripNone
}

// Engines measures the write activity of known sync and backup engines
// (OneDrive, Dropbox, Google Drive, backup tools), found by process image
// name. Names stay inside the implementation; only a number comes out.
type Engines interface {
	// WriteOps is the total write operations so far of running engine
	// processes, and whether any engine is running.
	WriteOps() (ops uint64, running bool)
}

// trip is a window that tripped.
type trip struct {
	reason proof.TripReason
	counts Counts
}

// snapshot is the detector's state, published for statements. Immutable
// once published.
type snapshot struct {
	seq        uint64
	state      proof.Availability
	folders    int
	peak       Counts // busiest window since the last statement
	peakSeq    uint64 // first snapshot carrying this peak
	trip       *trip  // the trip since the last statement, if any
	tripSeq    uint64 // first snapshot carrying this trip
	suppressed int
}

// engineSample is the engines' write count at one second.
type engineSample struct {
	at  int64
	ops uint64
}

// Detector counts classified changes in a sliding window, applies the
// thresholds and publishes the result for the next statement.
//
// One goroutine (the watcher) calls SetState, Add, AddN and Flush. Any
// goroutine may call Snapshot. The hand-over is lock-free: the published
// state is an atomic pointer to an immutable snapshot, acknowledgements
// an atomic counter, and the immediate-heartbeat rate limit a
// compare-and-swap on the last trip time.
type Detector struct {
	th      Thresholds
	engines Engines
	now     func() time.Time
	trips   chan struct{}

	// Watcher goroutine only.
	sec     [maxWindowSeconds]int64
	ring    [maxWindowSeconds]Counts
	cur     snapshot
	samples []engineSample

	published atomic.Pointer[snapshot]
	acked     atomic.Uint64
	lastTrip  atomic.Int64 // unix nanoseconds of the last immediate-heartbeat signal
}

// NewDetector makes a detector; until SetState it reports "unknown".
// engines may be nil (no suppression).
func NewDetector(th Thresholds, engines Engines, now func() time.Time) (*Detector, error) {
	th, err := th.WithDefaults()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	d := &Detector{th: th, engines: engines, now: now, trips: make(chan struct{}, 1)}
	d.publish()
	return d, nil
}

// Thresholds returns the thresholds in use.
func (d *Detector) Thresholds() Thresholds { return d.th }

// Trips signals that an immediate tripwire heartbeat is due. It fires at
// most once per Cooldown.
func (d *Detector) Trips() <-chan struct{} { return d.trips }

// SetState records whether the watcher runs and how many folders it
// watches.
func (d *Detector) SetState(s proof.Availability, folders int) {
	if folders > MaxFolders {
		folders = MaxFolders
	}
	d.cur.state, d.cur.folders = s, folders
	d.publish()
}

// Add counts one classified change.
func (d *Detector) Add(k Kind) { d.AddN(k, 1) }

// AddN counts n changes of one kind. Counts saturate; they never wrap.
func (d *Detector) AddN(k Kind, n uint32) {
	if k >= numKinds || n == 0 {
		return
	}
	s := d.now().Unix()
	i := int(s % maxWindowSeconds)
	if d.sec[i] != s {
		d.sec[i], d.ring[i] = s, Counts{}
	}
	d.ring[i][k] = satAdd(d.ring[i][k], n)
}

func satAdd(a, b uint32) uint32 {
	if c := a + b; c >= a {
		return c
	}
	return ^uint32(0)
}

// window sums the last Window seconds.
func (d *Detector) window(now int64) Counts {
	var sum Counts
	w := int64(d.th.Window / time.Second)
	for i := range d.ring {
		if d.sec[i] > now-w && d.sec[i] <= now {
			for k, n := range d.ring[i] {
				sum[k] = satAdd(sum[k], n)
			}
		}
	}
	return sum
}

// Flush evaluates the window after a batch of changes: it keeps the
// busiest window, trips if a rule fires and no sync or backup engine
// explains the burst, and publishes.
func (d *Detector) Flush() {
	d.forgetAcked()
	now := d.now()
	c := d.window(now.Unix())
	d.sampleEngines(now.Unix(), c)
	next := d.cur.seq + 1
	if c.total() > d.cur.peak.total() {
		d.cur.peak, d.cur.peakSeq = c, next
	}
	if r := d.th.rule(c); r != proof.TripNone {
		switch {
		case d.byEngine(c):
			d.cur.suppressed++
		case d.cur.trip == nil:
			d.cur.trip, d.cur.tripSeq = &trip{r, c}, next
			d.signal(now)
		case c.total() > d.cur.trip.counts.total():
			d.cur.trip = &trip{r, c} // same trip, now bigger
		}
	}
	d.publish()
}

// sampleEngines keeps the engines' write count over the last window, but
// only while files are changing, so a quiet machine costs nothing.
func (d *Detector) sampleEngines(now int64, c Counts) {
	if d.engines == nil || c.Activity() == 0 {
		d.samples = d.samples[:0]
		return
	}
	if n := len(d.samples); n > 0 && now-d.samples[n-1].at < 5 {
		return
	}
	ops, running := d.engines.WriteOps()
	if !running {
		d.samples = d.samples[:0]
		return
	}
	d.samples = append(d.samples, engineSample{at: now, ops: ops})
	w := int64(d.th.Window / time.Second)
	for len(d.samples) > 1 && d.samples[1].at <= now-w {
		d.samples = d.samples[1:]
	}
}

// byEngine reports whether a sync or backup engine plausibly made this
// burst: during the window it wrote at least as often as files changed.
// Ransomware writes from its own process, so the engines' count stays low
// even while they upload the encrypted files.
func (d *Detector) byEngine(c Counts) bool {
	if d.engines == nil || len(d.samples) == 0 {
		return false
	}
	ops, running := d.engines.WriteOps()
	if !running || ops < d.samples[0].ops {
		return false
	}
	return ops-d.samples[0].ops >= uint64(c.Activity())
}

// signal asks for an immediate heartbeat, at most once per Cooldown. The
// rate limit is a compare-and-swap on the last signal time.
func (d *Detector) signal(now time.Time) {
	last := d.lastTrip.Load()
	if last != 0 && now.UnixNano()-last < int64(d.th.Cooldown) {
		return
	}
	if !d.lastTrip.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	select {
	case d.trips <- struct{}{}:
	default: // one is already waiting
	}
}

func (d *Detector) publish() {
	d.cur.seq++
	s := d.cur
	d.published.Store(&s)
}

// forgetAcked drops a trip and a peak that a statement has carried, so
// each is reported once.
func (d *Detector) forgetAcked() {
	a := d.acked.Load()
	if d.cur.trip != nil && a >= d.cur.tripSeq {
		d.cur.trip = nil
	}
	if d.cur.peak != (Counts{}) && a >= d.cur.peakSeq {
		d.cur.peak = Counts{}
	}
}

// Snapshot is the tripwire section for the next statement, and the
// function to call once that statement is safely queued. A trip or peak
// already carried by an earlier statement is left out, even if the
// watcher has been quiet since.
func (d *Detector) Snapshot() (proof.Tripwire, func()) {
	s := d.published.Load()
	a := d.acked.Load()
	tw := proof.Tripwire{State: s.state}
	if s.state != proof.AvailOK {
		return tw, func() {}
	}
	tw.Window, tw.FoldersWatched = Windows[d.th.Window], uint8(s.folders)
	var c Counts
	var ack uint64
	switch {
	case s.trip != nil && a < s.tripSeq:
		tw.Triggered, tw.Reason, c, ack = true, s.trip.reason, s.trip.counts, s.tripSeq
	case a < s.peakSeq:
		c, ack = s.peak, s.peakSeq
	}
	tw.Counts = proof.TripCounts{
		Renamed:           proof.BucketOf(c.Renames()),
		ExtensionChanged:  proof.BucketOf(c[ExtensionChanged]),
		Modified:          proof.BucketOf(c[Modified]),
		Deleted:           proof.BucketOf(c[Deleted]),
		SuspiciousCreated: proof.BucketOf(c[SuspiciousCreated]),
		UnknownActivity:   proof.BucketOf(c[Unknown]),
	}
	return tw, func() { d.ack(ack) }
}

func (d *Detector) ack(seq uint64) {
	for {
		cur := d.acked.Load()
		if seq <= cur || d.acked.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// Suppressed is how many bursts were attributed to a sync or backup
// engine instead of tripping (local diagnostics; never in a statement).
func (d *Detector) Suppressed() int { return d.published.Load().suppressed }
