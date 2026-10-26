package tripwire

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// The real watcher on this machine, on a temporary folder this test makes
// and fills with its own dummy files: normal edits do not trip, a mass
// rename does, and closing is clean.
func TestRealWatcherTripsOnAMassRename(t *testing.T) {
	dir := t.TempDir()
	const n = 300
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("dummy-%03d.docx", i)), []byte("kovyr tripwire test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := NewDetector(Thresholds{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Start([]string{dir, filepath.Join(dir, "does-not-exist")}, d, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if tw, _ := d.Snapshot(); tw.State != proof.AvailOK || tw.FoldersWatched != 1 {
		t.Fatalf("watching %+v", tw)
	}
	// Normal work: a handful of edits.
	for i := 0; i < 10; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("dummy-%03d.docx", i)), []byte("edited"), 0o600)
	}
	time.Sleep(500 * time.Millisecond)
	select {
	case <-d.Trips():
		t.Fatal("ten edits tripped")
	default:
	}
	// The burst.
	t0 := time.Now()
	for i := 0; i < n; i++ {
		old := filepath.Join(dir, fmt.Sprintf("dummy-%03d.docx", i))
		if err := os.Rename(old, old+".locked"); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-d.Trips():
		t.Logf("tripped %v after the burst began", time.Since(t0).Round(time.Millisecond))
	case <-time.After(10 * time.Second):
		tw, _ := d.Snapshot()
		t.Fatalf("no trip after %d renames; snapshot %+v", n, tw)
	}
	tw, _ := d.Snapshot()
	if !tw.Triggered || tw.Reason != proof.TripMassExtensionChange || tw.Counts.ExtensionChanged < proof.Bucket100to999 {
		t.Fatalf("snapshot %+v", tw)
	}
	done := make(chan struct{})
	go func() { w.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
	w.Close() // twice is fine
}

func TestRealWatcherDropsAVanishedFolder(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "watched")
	os.Mkdir(dir, 0o700)
	d, _ := NewDetector(Thresholds{}, nil, nil)
	w, err := Start([]string{dir}, d, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := os.RemoveAll(dir); err != nil {
		t.Skipf("cannot remove a watched folder here: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if tw, _ := d.Snapshot(); tw.State == proof.AvailUnknown {
			return
		}
		if time.Now().After(deadline) {
			tw, _ := d.Snapshot()
			t.Fatalf("still %+v after the folder was removed", tw)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestUserFoldersAndEngines(t *testing.T) {
	folders := UserFolders()
	t.Logf("%d user folders found", len(folders)) // the paths hold user names; not logged
	for _, f := range folders {
		if fi, err := os.Lstat(f); err != nil || !fi.IsDir() {
			t.Errorf("listed folder is not a directory: %v", err)
		}
	}
	ops, running := SystemEngines().WriteOps()
	t.Logf("sync/backup engines running: %v (write ops %d)", running, ops)
}
