//go:build !windows

package usage

import (
	"runtime"
	"syscall"
	"time"
)

// Self is this process's use (development only outside Windows).
func Self() (Usage, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return Usage{}, err
	}
	tv := func(t syscall.Timeval) time.Duration {
		return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond
	}
	rss := uint64(ru.Maxrss)
	if runtime.GOOS != "darwin" {
		rss *= 1024 // kilobytes on Linux and the BSDs, bytes on macOS
	}
	return Usage{CPU: tv(ru.Utime) + tv(ru.Stime), PeakWorkingSet: rss}, nil
}
