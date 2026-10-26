package logfile

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func totalSize(t *testing.T, dir string) (int64, int) {
	t.Helper()
	var total int64
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		fi, _ := de.Info()
		total += fi.Size()
	}
	return total, len(des)
}

func TestRotationKeepsTheCap(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, MinMaxBytes, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	l := log.New(w, "", 0)
	line := strings.Repeat("x", 1000)
	for i := 0; i < 1000; i++ { // ~1 MB of log through a 192 KB cap
		l.Printf("%05d %s", i, line)
	}
	total, n := totalSize(t, dir)
	if n != 3 || total > 3*MinMaxBytes {
		t.Fatalf("%d files, %d bytes; cap is 3 x %d", n, total, MinMaxBytes)
	}
	for _, name := range []string{"agent.log", "agent.1.log", "agent.2.log"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Size() > MinMaxBytes {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Newest last: the current file ends with the last line, and the
	// oldest kept lines are in agent.2.log.
	cur, _ := os.ReadFile(filepath.Join(dir, "agent.log"))
	if !bytes.HasSuffix(cur, []byte("00999 "+line+"\n")) {
		t.Fatal("current file does not end with the newest line")
	}
	old, _ := os.ReadFile(filepath.Join(dir, "agent.2.log"))
	if bytes.Contains(old, []byte("00999 ")) || bytes.Contains(old, []byte("00000 ")) {
		t.Fatal("agent.2.log holds the wrong lines")
	}
}

func TestOneFileStaysUnderItsCap(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, MinMaxBytes, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		fmt.Fprintf(w, "%s\n", strings.Repeat("y", 500))
	}
	w.Close()
	if total, n := totalSize(t, dir); n != 1 || total > MinMaxBytes {
		t.Fatalf("%d files, %d bytes", n, total)
	}
}

func TestReopenAppendsAndKeepsCounting(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, MinMaxBytes, 2)
	fmt.Fprintln(w, "first run")
	w.Close()
	w, _ = Open(dir, MinMaxBytes, 2)
	defer w.Close()
	fmt.Fprintln(w, "second run")
	b, _ := os.ReadFile(filepath.Join(dir, "agent.log"))
	if string(b) != "first run\nsecond run\n" {
		t.Fatalf("got %q", b)
	}
	for i := 0; i < 400; i++ {
		fmt.Fprintln(w, strings.Repeat("z", 400))
	}
	if total, n := totalSize(t, dir); n != 2 || total > 2*MinMaxBytes {
		t.Fatalf("%d files, %d bytes after reopening", n, total)
	}
}

func TestLinesAreCleanAndBounded(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, MinMaxBytes, 1)
	defer w.Close()
	fmt.Fprintf(w, "check edr: ok\nFORGED LINE\r\x1b[31m\x00\n")
	fmt.Fprintf(w, "%s\n", strings.Repeat("k", 10*MaxLine))
	b, _ := os.ReadFile(filepath.Join(dir, "agent.log"))
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("a write produced more than one line: %q", lines)
	}
	if lines[0] != "check edr: ok?FORGED LINE??[31m?" {
		t.Fatalf("control characters not replaced: %q", lines[0])
	}
	if len(lines[1])+1 > MaxLine || !strings.HasSuffix(lines[1], " [cut]") {
		t.Fatalf("long line is %d bytes", len(lines[1]))
	}
}

func TestOpenRefusesBadCaps(t *testing.T) {
	for _, c := range []struct {
		size  int64
		files int
	}{{1024, 5}, {MaxMaxBytes + 1, 5}, {MinMaxBytes, 0}, {MinMaxBytes, MaxFiles + 1}} {
		if _, err := Open(t.TempDir(), c.size, c.files); err == nil {
			t.Errorf("accepted %d bytes x %d files", c.size, c.files)
		}
	}
}
