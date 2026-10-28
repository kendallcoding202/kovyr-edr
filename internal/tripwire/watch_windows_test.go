package tripwire

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

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

// makeJunction makes link a directory junction (mount point) to target,
// as a user can without any privilege: an empty folder with a mount-point
// reparse point set on it (FSCTL_SET_REPARSE_POINT).
func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := windows.UTF16FromString(`\??\` + abs) // with its NUL
	prt, _ := windows.UTF16FromString(abs)
	names := append(sub, prt...)
	// REPARSE_DATA_BUFFER: tag, data length, reserved; then the mount
	// point buffer: substitute and print name offsets and lengths (bytes,
	// without the NULs), then the names.
	data := make([]byte, 8+2*len(names))
	binary.LittleEndian.PutUint16(data[0:], 0)
	binary.LittleEndian.PutUint16(data[2:], uint16(2*(len(sub)-1)))
	binary.LittleEndian.PutUint16(data[4:], uint16(2*len(sub)))
	binary.LittleEndian.PutUint16(data[6:], uint16(2*(len(prt)-1)))
	for i, c := range names {
		binary.LittleEndian.PutUint16(data[8+2*i:], c)
	}
	buf := make([]byte, 8, 8+len(data))
	binary.LittleEndian.PutUint32(buf[0:], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:], uint16(len(data)))
	buf = append(buf, data...)
	p, _ := windows.UTF16PtrFromString(link)
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil {
		t.Fatalf("make the junction: %v", err)
	}
	// It must really lead to target, or the tests below prove nothing.
	if _, err := os.Stat(filepath.Join(link, "marker.txt")); err != nil {
		t.Fatalf("the junction does not lead to its target: %v", err)
	}
}

// logRecorder keeps what the watcher logs.
type logRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *logRecorder) logf(format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, a...))
}

func (r *logRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

// startRefused starts a watch on folder and checks that it was refused
// for reason: nothing watched, the state unknown, and the reason in the
// log by number, never the path.
func startRefused(t *testing.T, folder, reason string) {
	t.Helper()
	d, err := NewDetector(Thresholds{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var log logRecorder
	w, err := Start([]string{folder}, d, log.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if tw, _ := d.Snapshot(); tw.State != proof.AvailUnknown || tw.FoldersWatched != 0 {
		t.Errorf("watching %+v, want nothing watched", tw)
	}
	text := log.String()
	if want := "cannot watch folder 1 of 1 (" + reason + ")"; !strings.Contains(text, want) {
		t.Errorf("log %q, want %q", text, want)
	}
	if strings.Contains(strings.ToLower(text), strings.ToLower(filepath.Base(folder))) {
		t.Errorf("the log names the folder: %q", text)
	}
}

func junctionSetup(t *testing.T) (root, target string) {
	t.Helper()
	root = t.TempDir()
	target = filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "marker.txt"), []byte("kovyr tripwire test"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, target
}

// HOST-3: a watch folder that is a junction (a user can replace their own
// Documents with one, between the agent's listing and its open) is not
// followed: the SYSTEM service is never steered to watch its target.
func TestRealWatcherRefusesAJunction(t *testing.T) {
	root, target := junctionSetup(t)
	link := filepath.Join(root, "Documents")
	makeJunction(t, link, target)
	startRefused(t, link, "a junction or link")
}

// A junction on the way to the folder is caught by the final path of the
// opened handle.
func TestRealWatcherRefusesAPathThroughAJunction(t *testing.T) {
	root, target := junctionSetup(t)
	if err := os.Mkdir(filepath.Join(target, "Clients"), 0o700); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(root, "Shared")
	makeJunction(t, via, target)
	startRefused(t, filepath.Join(via, "Clients"), "its path leads somewhere else")
}

// A folder named with short (8.3) names is still the same folder.
func TestRealWatcherAcceptsAShortName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Client Files Folder")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(dir)
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n >= uint32(len(buf)) {
		t.Skipf("no short name: %v", err)
	}
	short := windows.UTF16ToString(buf[:n])
	if strings.EqualFold(short, dir) {
		t.Skip("8.3 names are off on this volume")
	}
	d, _ := NewDetector(Thresholds{}, nil, nil)
	var log logRecorder
	w, err := Start([]string{short}, d, log.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if tw, _ := d.Snapshot(); tw.State != proof.AvailOK || tw.FoldersWatched != 1 {
		t.Fatalf("watching %+v through a short name; log %q", tw, log.String())
	}
}
