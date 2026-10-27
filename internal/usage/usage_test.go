package usage

import (
	"strings"
	"testing"
	"time"
)

func TestSelf(t *testing.T) {
	// Burn a little processor time so CPU is not zero.
	x := 0
	for end := time.Now().Add(30 * time.Millisecond); time.Now().Before(end); {
		x++
	}
	u, err := Self()
	if err != nil {
		t.Fatal(err)
	}
	if u.CPU <= 0 || u.PeakWorkingSet < 1<<20 || u.PeakWorkingSet > 4<<30 {
		t.Fatalf("implausible usage %+v (%d)", u, x)
	}
	line := u.String()
	if !strings.HasPrefix(line, "usage: cpu_ms=") || !strings.Contains(line, " peak_working_set_kb=") || !strings.Contains(line, " peak_private_kb=") {
		t.Fatalf("line %q", line)
	}
}
