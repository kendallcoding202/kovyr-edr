package tripwire

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var start = time.Date(2026, 10, 26, 22, 0, 0, 0, time.UTC)

func newDet(t *testing.T, eng Engines) (*Detector, *clock) {
	t.Helper()
	c := &clock{t: start}
	d, err := NewDetector(Thresholds{}, eng, c.now)
	if err != nil {
		t.Fatal(err)
	}
	d.SetState(proof.AvailOK, 4)
	return d, c
}

// feed parses buffers the way the watcher does, then flushes.
func feed(d *Detector, p *Parser, recs ...[]byte) {
	p.Parse(buffer(recs...), d.Add)
	d.Flush()
}

func tripped(d *Detector) bool {
	select {
	case <-d.Trips():
		return true
	default:
		return false
	}
}

// Ransomware: hundreds of documents renamed to a new extension within
// seconds, a ransom note in each folder.
func TestRenameBurstTrips(t *testing.T) {
	d, c := newDet(t, nil)
	var p Parser
	for i := 0; i < 300; i++ {
		name := fmt.Sprintf(`Clients\%03d\return-2025.pdf`, i)
		feed(d, &p,
			record(actionModified, name, false),
			record(actionRenamedOldName, name, false),
			record(actionRenamedNewName, name+".k0vyr", true))
		if i%50 == 0 {
			c.add(time.Second)
		}
	}
	if !tripped(d) {
		t.Fatal("a mass rename to a new extension did not trip")
	}
	tw, ack := d.Snapshot()
	want := proof.Tripwire{State: proof.AvailOK, Triggered: true, Reason: proof.TripMassExtensionChange, Window: proof.TripWindow60s,
		FoldersWatched: 4, Counts: proof.TripCounts{Renamed: proof.Bucket100to999, ExtensionChanged: proof.Bucket100to999, Modified: proof.Bucket100to999}}
	if tw != want {
		t.Fatalf("snapshot %+v\nwant     %+v", tw, want)
	}
	ack()
	if tw, _ := d.Snapshot(); tw.Triggered {
		t.Fatal("an acknowledged trip is reported again")
	}
}

func TestRansomNotesDuringABurstTrip(t *testing.T) {
	d, _ := newDet(t, nil)
	var p Parser
	for i := 0; i < 40; i++ { // encrypted in place: writes, no renames
		feed(d, &p, record(actionModified, fmt.Sprintf(`Docs\file%02d.docx`, i), true))
	}
	for i := 0; i < 3; i++ {
		feed(d, &p, record(actionAdded, fmt.Sprintf(`Docs\sub%d\HOW_TO_RESTORE_FILES.txt`, i), true))
	}
	if !tripped(d) {
		t.Fatal("ransom notes during a burst did not trip")
	}
	if tw, _ := d.Snapshot(); tw.Reason != proof.TripRansomNotes || tw.Counts.SuspiciousCreated != proof.Bucket1to9 {
		t.Fatalf("snapshot %+v", tw)
	}
}

// A person at work: saves (Word's temp-file dance), new files, a few
// renames and deletions, over an hour.
func TestNormalEditingDoesNotTrip(t *testing.T) {
	d, c := newDet(t, nil)
	var p Parser
	for minute := 0; minute < 60; minute++ {
		for save := 0; save < 6; save++ { // a save every ten seconds, all hour
			doc := fmt.Sprintf(`Clients\Smith\letter%d.docx`, save)
			feed(d, &p,
				record(actionAdded, `Clients\Smith\~WRD0001.tmp`, false),
				record(actionModified, `Clients\Smith\~WRD0001.tmp`, false),
				record(actionRenamedOldName, doc, false),
				record(actionRenamedNewName, `Clients\Smith\~WRL0001.tmp`, false),
				record(actionRenamedOldName, `Clients\Smith\~WRD0001.tmp`, false),
				record(actionRenamedNewName, doc, false),
				record(actionRemoved, `Clients\Smith\~WRL0001.tmp`, true))
			c.add(10 * time.Second)
		}
		feed(d, &p, record(actionRenamedOldName, `scan.pdf`, false), record(actionRenamedNewName, `Smith signed.pdf`, true))
		feed(d, &p, record(actionAdded, `New Microsoft Excel Worksheet.xlsx`, true))
	}
	if tripped(d) {
		t.Fatal("an hour of normal editing tripped")
	}
	if tw, _ := d.Snapshot(); tw.Triggered || tw.Counts.ExtensionChanged != proof.Bucket0 {
		t.Fatalf("snapshot %+v", tw)
	}
}

// OneDrive restoring a folder: many files arrive and are renamed into
// place from temporary names, and OneDrive's own write count rises.
func TestOneDriveSyncDoesNotTrip(t *testing.T) {
	eng := &FakeEngines{}
	d, c := newDet(t, eng)
	var p Parser
	for i := 0; i < 800; i++ {
		name := fmt.Sprintf(`Documents\Archive\%04d.pdf`, i)
		feed(d, &p,
			record(actionAdded, name+".tmp", false),
			record(actionModified, name+".tmp", false),
			record(actionRenamedOldName, name+".tmp", false),
			record(actionRenamedNewName, name, true))
		eng.Write(6)
		if i%40 == 0 {
			c.add(time.Second)
		}
	}
	if tripped(d) {
		t.Fatal("a OneDrive download tripped")
	}
}

// A sync engine that renames files to new extensions itself (an engine
// converting or restoring versions) would trip the rule; its write count
// explains the burst, so it is suppressed and counted.
func TestEngineWritesSuppressAnExtensionBurst(t *testing.T) {
	eng := &FakeEngines{}
	d, c := newDet(t, eng)
	var p Parser
	eng.Write(1)
	for i := 0; i < 200; i++ {
		feed(d, &p, record(actionRenamedOldName, fmt.Sprintf("v%d.docx", i), false),
			record(actionRenamedNewName, fmt.Sprintf("v%d.docx.v2", i), true))
		eng.Write(5)
		if i%20 == 0 {
			c.add(time.Second)
		}
	}
	if tripped(d) {
		t.Fatal("a burst the engine wrote tripped")
	}
	if d.Suppressed() == 0 {
		t.Fatal("suppression not counted")
	}
}

// Ransomware while OneDrive runs: OneDrive uploads the encrypted files
// (reads) but writes little, so the burst still trips.
func TestRansomwareWhileOneDriveRunsStillTrips(t *testing.T) {
	eng := &FakeEngines{}
	d, c := newDet(t, eng)
	var p Parser
	eng.Write(1)
	for i := 0; i < 300; i++ {
		name := fmt.Sprintf(`OneDrive\Documents\%03d.xlsx`, i)
		feed(d, &p, record(actionModified, name, false), record(actionRenamedOldName, name, false),
			record(actionRenamedNewName, name+".locked", true))
		if i%30 == 0 {
			eng.Write(3) // a few log and database writes
			c.add(time.Second)
		}
	}
	if !tripped(d) {
		t.Fatal("ransomware was suppressed because OneDrive was running")
	}
}

// Changes faster than the buffer: Windows returns an empty buffer. It is
// counted as unknown activity, shown in the statement, and does not trip
// or crash on its own.
func TestBufferOverflowIsUnknownActivity(t *testing.T) {
	d, _ := newDet(t, nil)
	var p Parser
	for i := 0; i < 50; i++ {
		p.Parse(nil, d.Add) // n == 0 from ReadDirectoryChangesW
		d.Add(Unknown)      // what the watcher adds for an overflow
		d.Flush()
	}
	if tripped(d) {
		t.Fatal("overflows alone tripped")
	}
	tw, _ := d.Snapshot()
	if tw.Counts.UnknownActivity != proof.Bucket10to99 || tw.Triggered {
		t.Fatalf("snapshot %+v", tw)
	}
}

func TestOldChangesLeaveTheWindow(t *testing.T) {
	d, c := newDet(t, nil)
	var p Parser
	// 60 extension changes, then a two-minute pause, then 60 more: never
	// 100 in one minute.
	for burst := 0; burst < 2; burst++ {
		for i := 0; i < 60; i++ {
			feed(d, &p, record(actionRenamedOldName, fmt.Sprintf("%d-%d.doc", burst, i), false),
				record(actionRenamedNewName, fmt.Sprintf("%d-%d.doc.x", burst, i), true))
		}
		c.add(2 * time.Minute)
	}
	if tripped(d) {
		t.Fatal("two separate bursts were added together")
	}
}

// At most one immediate heartbeat per cooldown; a second trip in the
// cooldown is still reported, in the next statement.
func TestTripsAreRateLimited(t *testing.T) {
	d, c := newDet(t, nil)
	var p Parser
	burst := func(tag string) {
		for i := 0; i < 150; i++ {
			feed(d, &p, record(actionRenamedOldName, fmt.Sprintf("%s%d.pdf", tag, i), false),
				record(actionRenamedNewName, fmt.Sprintf("%s%d.pdf.locked", tag, i), true))
		}
	}
	burst("a")
	if !tripped(d) {
		t.Fatal("first burst")
	}
	_, ack := d.Snapshot()
	ack()
	c.add(3 * time.Minute)
	burst("b")
	if tripped(d) {
		t.Fatal("a second immediate heartbeat inside the cooldown")
	}
	if tw, _ := d.Snapshot(); !tw.Triggered {
		t.Fatal("the second trip is not reported at all")
	}
	_, ack = d.Snapshot()
	ack()
	c.add(10 * time.Minute)
	burst("c")
	if !tripped(d) {
		t.Fatal("no immediate heartbeat after the cooldown")
	}
}

// The busiest window since the last statement is reported once; after a
// statement carries it, a quiet machine reports zeros.
func TestPeakIsReportedOnce(t *testing.T) {
	d, c := newDet(t, nil)
	var p Parser
	for i := 0; i < 25; i++ {
		feed(d, &p, record(actionModified, fmt.Sprintf("f%d.txt", i), true))
	}
	c.add(5 * time.Minute)
	feed(d, &p, record(actionModified, "late.txt", true))
	tw, ack := d.Snapshot()
	if tw.Counts.Modified != proof.Bucket10to99 {
		t.Fatalf("peak not reported: %+v", tw.Counts)
	}
	ack()
	if tw, _ := d.Snapshot(); tw.Counts != (proof.TripCounts{}) {
		t.Fatalf("an acknowledged peak is reported again: %+v", tw.Counts)
	}
	// Activity after the snapshot but before the ack is kept.
	feed(d, &p, record(actionModified, "a.txt", true))
	_, ack = d.Snapshot()
	feed(d, &p, record(actionModified, "b.txt", true), record(actionModified, "c.txt", true))
	ack()
	if tw, _ := d.Snapshot(); tw.Counts.Modified == proof.Bucket0 {
		t.Fatal("activity after the snapshot was lost by the ack")
	}
}

func TestStatesAndThresholds(t *testing.T) {
	d, err := NewDetector(Thresholds{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tw, _ := d.Snapshot(); tw != (proof.Tripwire{State: proof.AvailUnknown}) {
		t.Fatalf("before watching: %+v", tw)
	}
	d.SetState(proof.AvailNotApplicable, 0)
	if tw, _ := d.Snapshot(); tw != (proof.Tripwire{State: proof.AvailNotApplicable}) {
		t.Fatalf("not applicable: %+v", tw)
	}
	th := d.Thresholds()
	if th.Window != time.Minute || th.MinActivity != 100 || th.MinExtensionChanged != 50 || th.ExtensionChangedPercent != 60 ||
		th.MinSuspiciousCreated != 3 || th.NotesActivity != 30 || th.Cooldown != 10*time.Minute {
		t.Fatalf("defaults %+v", th)
	}
	for name, bad := range map[string]Thresholds{
		"window 45s":      {Window: 45 * time.Second},
		"activity 5":      {MinActivity: 5},
		"ext above total": {MinActivity: 100, MinExtensionChanged: 200},
		"share 5%":        {ExtensionChangedPercent: 5},
		"share 200%":      {ExtensionChangedPercent: 200},
		"cooldown 1s":     {Cooldown: time.Second},
	} {
		if _, err := NewDetector(bad, nil, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for w, e := range Windows {
		if _, err := NewDetector(Thresholds{Window: w}, nil, nil); err != nil || e == 0 {
			t.Errorf("window %v: %v", w, err)
		}
	}
}

// The detector is fed by one goroutine and read by another; run with
// -race.
func TestSnapshotWhileFeeding(t *testing.T) {
	d, c := newDet(t, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var p Parser
		for i := 0; i < 3000; i++ {
			feed(d, &p, record(actionRenamedOldName, fmt.Sprintf("%d.doc", i), false),
				record(actionRenamedNewName, fmt.Sprintf("%d.doc.z", i), true))
		}
	}()
	for i := 0; i < 1000; i++ {
		_, ack := d.Snapshot()
		ack()
		d.Suppressed()
	}
	<-done
	_ = c
}

// Reorganizing a folder: hundreds of plain renames and some format
// conversions. Extension changes are a minority, so it does not trip.
func TestReorganizingWithSomeConversionsDoesNotTrip(t *testing.T) {
	d, _ := newDet(t, nil)
	var p Parser
	for i := 0; i < 240; i++ {
		feed(d, &p, record(actionRenamedOldName, fmt.Sprintf(`Old\%d.docx`, i), false),
			record(actionRenamedNewName, fmt.Sprintf(`2026\Q3\%d.docx`, i), true))
	}
	for i := 0; i < 60; i++ { // e.g. a batch export to PDF renaming outputs
		feed(d, &p, record(actionRenamedOldName, fmt.Sprintf(`2026\%d.docx`, i), false),
			record(actionRenamedNewName, fmt.Sprintf(`2026\%d.pdf`, i), true))
	}
	if tripped(d) {
		t.Fatal("a reorganization with 20% extension changes tripped")
	}
}

// Three downloads with alarming names but no burst around them.
func TestNoteNamesWithoutABurstDoNotTrip(t *testing.T) {
	d, _ := newDet(t, nil)
	var p Parser
	for i := 0; i < 5; i++ {
		feed(d, &p, record(actionAdded, fmt.Sprintf(`Downloads\how_to_decrypt_pgp_%d.txt`, i), true))
		feed(d, &p, record(actionModified, `budget.xlsx`, true))
	}
	if tripped(d) {
		t.Fatal("note-like names without a burst tripped")
	}
}
