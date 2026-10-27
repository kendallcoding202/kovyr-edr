package tripwire

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Read-only watching with ReadDirectoryChangesW: each folder is opened
// with FILE_LIST_DIRECTORY and backup semantics (directories cannot be
// opened otherwise), never for writing; notifications arrive on one I/O
// completion port and one goroutine handles them all. The agent never
// opens, reads or hashes the files themselves.

// notifyFilter: file names (create, delete, rename) and last write
// (modify). Directory names, attributes and security are left out.
const notifyFilter = windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_LAST_WRITE

// bufSize is each notification buffer (about 600 changes). Each folder
// has two: the next read is issued into one before the other is parsed,
// so the gap in which Windows must hold changes is as short as possible.
// When Windows' own buffer still overflows it returns no records, and the
// changes count as unknown activity. 32 folders x 2 x 64 KiB is 4 MiB at
// most; a typical office PC watches 2 to 6 folders.
const bufSize = 64 << 10

const stopKey = ^uintptr(0)

type dirWatch struct {
	h      windows.Handle
	ov     windows.Overlapped
	buf    [2][]uint64 // 8-byte aligned, as the records need DWORD alignment
	cur    int         // the buffer the outstanding read fills
	parser Parser
	dead   bool
}

func (w *dirWatch) bytes(i int) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&w.buf[i][0])), bufSize)
}

// read issues the next read into the other buffer and returns the one
// just filled.
func (w *dirWatch) read() ([]byte, error) {
	filled := w.bytes(w.cur)
	w.cur = 1 - w.cur
	w.ov = windows.Overlapped{}
	return filled, windows.ReadDirectoryChanges(w.h, &w.bytes(w.cur)[0], bufSize, true, notifyFilter, nil, &w.ov, 0)
}

// Watch is a running watcher.
type Watch struct {
	port    windows.Handle
	dirs    []*dirWatch
	det     *Detector
	logf    func(string, ...any)
	once    sync.Once
	closing atomic.Bool
	done    chan struct{}
}

// Start watches folders (at most MaxFolders) and feeds det. A folder that
// cannot be opened is skipped and logged by number, never by path (the
// path can hold a user name). With no folder watched the tripwire's state
// is unknown.
func Start(folders []string, det *Detector, logf func(string, ...any)) (*Watch, error) {
	if len(folders) > MaxFolders {
		folders = folders[:MaxFolders]
	}
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		det.SetState(proof.AvailUnknown, 0)
		return nil, err
	}
	w := &Watch{port: port, det: det, logf: logf, done: make(chan struct{})}
	for i, f := range folders {
		p, err := windows.UTF16PtrFromString(f)
		if err != nil {
			continue
		}
		h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED, 0)
		if err != nil {
			logf("tripwire: cannot watch folder %d of %d (%v)", i+1, len(folders), errClass(err))
			continue
		}
		dw := &dirWatch{h: h, buf: [2][]uint64{make([]uint64, bufSize/8), make([]uint64, bufSize/8)}}
		if _, err := windows.CreateIoCompletionPort(h, port, uintptr(len(w.dirs)), 0); err != nil {
			windows.CloseHandle(h)
			continue
		}
		if _, err := dw.read(); err != nil {
			logf("tripwire: cannot watch folder %d of %d (%v)", i+1, len(folders), errClass(err))
			windows.CloseHandle(h)
			continue
		}
		w.dirs = append(w.dirs, dw)
	}
	if len(w.dirs) == 0 {
		det.SetState(proof.AvailUnknown, 0)
	} else {
		det.SetState(proof.AvailOK, len(w.dirs))
	}
	go w.loop()
	return w, nil
}

func errClass(err error) string {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return "access denied"
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return "not found"
	}
	var en windows.Errno
	if errors.As(err, &en) {
		return fmt.Sprintf("error %d", uint32(en))
	}
	return "error"
}

// loop handles completions. Each folder has one read outstanding at a
// time; the loop returns only when closing and no read is outstanding,
// so Windows never writes into a buffer that is gone.
func (w *Watch) loop() {
	defer close(w.done)
	outstanding := len(w.dirs)
	for {
		if w.closing.Load() && outstanding == 0 {
			return
		}
		var n uint32
		var key uintptr
		var ov *windows.Overlapped
		err := windows.GetQueuedCompletionStatus(w.port, &n, &key, &ov, windows.INFINITE)
		if ov == nil {
			if key == stopKey {
				continue // woken by Close; the check above decides
			}
			if err != nil {
				w.logf("tripwire: completion port failed (%v); watching stopped", errClass(err))
				w.det.SetState(proof.AvailUnknown, 0)
				return
			}
			continue
		}
		if int(key) >= len(w.dirs) {
			continue
		}
		outstanding--
		dw := w.dirs[key]
		if w.closing.Load() {
			continue
		}
		overflow := errors.Is(err, windows.ERROR_NOTIFY_ENUM_DIR) || err == nil && n == 0
		if err != nil && !overflow {
			// The folder went away (deleted, unmounted): stop watching it.
			w.drop(dw)
			continue
		}
		filled, rerr := dw.read() // the next read first, then the parse
		if overflow {
			// Changes came faster than they could be counted. Count them
			// as unknown activity; never a crash.
			w.det.Add(Unknown)
		} else {
			dw.parser.Parse(filled[:n], w.det.Add)
		}
		w.det.Flush()
		if rerr != nil {
			w.drop(dw)
			continue
		}
		outstanding++
	}
}

func (w *Watch) drop(dw *dirWatch) {
	dw.dead = true
	windows.CloseHandle(dw.h)
	w.det.SetState(w.state())
}

func (w *Watch) state() (proof.Availability, int) {
	n := 0
	for _, d := range w.dirs {
		if !d.dead {
			n++
		}
	}
	if n == 0 {
		return proof.AvailUnknown, 0
	}
	return proof.AvailOK, n
}

// Close stops watching. It cancels the outstanding reads and waits until
// Windows has completed them, then closes the handles.
func (w *Watch) Close() {
	w.once.Do(func() {
		w.closing.Store(true)
		for _, d := range w.dirs {
			if !d.dead {
				windows.CancelIoEx(d.h, nil)
			}
		}
		windows.PostQueuedCompletionStatus(w.port, 0, stopKey, nil)
		<-w.done
		for _, d := range w.dirs {
			if !d.dead {
				windows.CloseHandle(d.h)
			}
		}
		windows.CloseHandle(w.port)
	})
}

// skipProfiles are folders under C:\Users that are not people.
var skipProfiles = map[string]bool{"public": true, "default": true, "default user": true, "all users": true, "defaultapppool": true}

// UserFolders lists each user's Desktop and Documents under the profiles
// folder (C:\Users). Junctions and links are skipped. The paths are used
// to open the folders and kept in memory only.
func UserFolders() []string {
	root, err := windows.KnownFolderPath(windows.FOLDERID_UserProfiles, 0)
	if err != nil {
		return nil
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.Type() != os.ModeDir || skipProfiles[strings.ToLower(e.Name())] {
			continue
		}
		for _, sub := range []string{"Desktop", "Documents"} {
			p := filepath.Join(root, e.Name(), sub)
			if fi, err := os.Lstat(p); err == nil && fi.Mode().Type() == os.ModeDir {
				out = append(out, p)
			}
		}
	}
	return out
}

// x/sys/windows has no GetProcessIoCounters; this is the small wrapper
// it lacks. It only fills a caller-owned IO_COUNTERS.
var procGetProcessIoCounters = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIoCounters")

// SystemEngines reads the write counts of running sync and backup engines
// (IsEngine), by process image name. Each call walks the process list
// once; the detector calls it only while files are changing, at most
// every five seconds.
func SystemEngines() Engines { return systemEngines{} }

type systemEngines struct{}

func (systemEngines) WriteOps() (uint64, bool) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var ops uint64
	running := false
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if !IsEngine(windows.UTF16ToString(e.ExeFile[:])) {
			continue
		}
		running = true
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ProcessID)
		if err != nil {
			continue
		}
		var io windows.IO_COUNTERS
		if r, _, _ := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&io))); r != 0 {
			ops += io.WriteOperationCount
		}
		windows.CloseHandle(h)
	}
	return ops, running
}
