// Package logfile is the agent service's log: capped and rotated, so
// logging can never fill the disk (CLAUDE.md section 2: "cap every queue
// and log"). It keeps at most Files files of at most MaxBytes each:
// agent.log, then agent.1.log (newer) to agent.N.log (oldest).
//
// Each Write is one log line. Lines are cut at MaxLine bytes and control
// characters are replaced, so a value that reaches a log line cannot
// forge more lines or grow without bound. What the agent logs is its own
// business only: check names and outcomes, sequence numbers, its server
// URL and its own state directory, never file contents, user names or
// paths outside the agent's directory.
package logfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Limits.
const (
	DefaultMaxBytes = 1 << 20
	DefaultFiles    = 5
	MinMaxBytes     = 64 << 10
	MaxMaxBytes     = 8 << 20
	MaxFiles        = 10
	MaxLine         = 2 << 10
)

// BaseName is the current log file's name.
const BaseName = "agent.log"

// Writer is a size-capped, rotating log file. It is safe for concurrent
// use.
type Writer struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	files    int
	f        *os.File
	size     int64
}

// Open opens (creating) dir/agent.log for appending.
func Open(dir string, maxBytes int64, files int) (*Writer, error) {
	if maxBytes < MinMaxBytes || maxBytes > MaxMaxBytes {
		return nil, fmt.Errorf("log file size must be %d to %d bytes", MinMaxBytes, MaxMaxBytes)
	}
	if files < 1 || files > MaxFiles {
		return nil, fmt.Errorf("log file count must be 1 to %d", MaxFiles)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &Writer{dir: dir, maxBytes: maxBytes, files: files}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) path(i int) string {
	if i == 0 {
		return filepath.Join(w.dir, BaseName)
	}
	return filepath.Join(w.dir, fmt.Sprintf("agent.%d.log", i))
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path(0), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// errDropped means a line was not written because the log could not be
// rotated; the cap is kept rather than the line.
var errDropped = errors.New("log line dropped: the log could not be rotated")

// Write writes one line. It never lets the files grow past their cap: if
// rotation fails, the line is dropped.
func (w *Writer) Write(p []byte) (int, error) {
	line := clean(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	if w.size+int64(len(line)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, errDropped
		}
	}
	n, err := w.f.Write(line)
	w.size += int64(n)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// rotate shifts agent.log to agent.1.log and so on; the rename onto the
// oldest name replaces it (os.Rename replaces on Windows too).
func (w *Writer) rotate() error {
	w.f.Close()
	w.f = nil
	for i := w.files - 1; i >= 1; i-- {
		from, to := w.path(i-1), w.path(i)
		if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
			// Another process holds a file open (Windows); try to keep the
			// cap by emptying the current file instead.
			if i == 1 {
				if terr := os.Truncate(w.path(0), 0); terr != nil {
					return err
				}
			}
		}
	}
	if w.files == 1 {
		if err := os.Truncate(w.path(0), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return w.open()
}

// Close closes the current file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// clean makes p one bounded line: control characters (including CR and
// inner newlines) become '?', and it is cut to MaxLine bytes, ending in a
// newline.
func clean(p []byte) []byte {
	for len(p) > 0 && (p[len(p)-1] == '\n' || p[len(p)-1] == '\r') {
		p = p[:len(p)-1]
	}
	cut := false
	if len(p) > MaxLine-1 {
		p, cut = p[:MaxLine-1-len(" [cut]")], true
	}
	out := make([]byte, 0, len(p)+8)
	for _, c := range p {
		if c < 0x20 && c != '\t' || c == 0x7f {
			c = '?'
		}
		out = append(out, c)
	}
	if cut {
		out = append(out, " [cut]"...)
	}
	return append(out, '\n')
}
