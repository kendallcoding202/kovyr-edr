package usage

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// x/sys/windows has GetProcessTimes but not GetProcessMemoryInfo; this is
// the small wrapper it lacks (K32GetProcessMemoryInfo, in kernel32 since
// Windows 7). It only fills a caller-owned struct.
var procGetProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

// processMemoryCounters is PROCESS_MEMORY_COUNTERS (psapi.h).
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// Self is this process's use.
func Self() (Usage, error) { return Of(windows.CurrentProcess()) }

// Of is the use of the process behind h, which needs
// PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ.
func Of(h windows.Handle) (Usage, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return Usage{}, err
	}
	var m processMemoryCounters
	m.CB = uint32(unsafe.Sizeof(m))
	if r, _, err := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.CB)); r == 0 {
		return Usage{}, err
	}
	ticks := func(f windows.Filetime) time.Duration {
		return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100
	}
	return Usage{
		CPU:            ticks(kernel) + ticks(user),
		PeakWorkingSet: uint64(m.PeakWorkingSetSize),
		PeakPrivate:    uint64(m.PeakPagefileUsage),
		CurrentWorkSet: uint64(m.WorkingSetSize),
	}, nil
}
