// Package usage reads a process's own resource use: processor time and
// peak memory. `kovyr-agent run --once --usage` prints it, and the CI
// resource-budget step reads it (CLAUDE.md section 2: under 1% CPU on
// average and under 50 MB RAM).
package usage

import (
	"fmt"
	"time"
)

// Usage is one process's resource use so far.
type Usage struct {
	CPU            time.Duration // user plus kernel time
	PeakWorkingSet uint64        // bytes; on Linux the peak resident set
	PeakPrivate    uint64        // bytes of peak committed private memory (Windows; 0 elsewhere)
	CurrentWorkSet uint64        // bytes now (Windows; 0 elsewhere)
}

// String is the line `--usage` prints. The budget tool parses it.
func (u Usage) String() string {
	return fmt.Sprintf("usage: cpu_ms=%d peak_working_set_kb=%d peak_private_kb=%d",
		u.CPU.Milliseconds(), u.PeakWorkingSet/1024, u.PeakPrivate/1024)
}
