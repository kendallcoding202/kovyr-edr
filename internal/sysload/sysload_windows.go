package sysload

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// golang.org/x/sys/windows does not wrap GetSystemPowerStatus or
// GetSystemTimes, so these are the two small wrappers it lacks. Both
// functions only fill a caller-owned struct; they change nothing.
// NewLazySystemDLL loads kernel32 from the system directory only, never
// from the working directory.
var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemPowerStatus = kernel32.NewProc("GetSystemPowerStatus")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
)

// systemPowerStatus is SYSTEM_POWER_STATUS (winbase.h).
type systemPowerStatus struct {
	ACLineStatus        uint8 // 0 offline (on battery), 1 online, 255 unknown
	BatteryFlag         uint8 // 128: no system battery, 255: unknown
	BatteryLifePercent  uint8
	SystemStatusFlag    uint8
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

const (
	acOffline      = 0
	acOnline       = 1
	batteryMissing = 128
)

// System is this machine's Source.
func System() Source { return windowsSource{} }

type windowsSource struct{}

func (windowsSource) OnBattery() (bool, error) {
	var s systemPowerStatus
	if r, _, err := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&s))); r == 0 {
		return false, err
	}
	return onBattery(s)
}

// onBattery interprets SYSTEM_POWER_STATUS. A desktop without a battery
// is on mains power.
func onBattery(s systemPowerStatus) (bool, error) {
	switch {
	case s.ACLineStatus == acOffline:
		return true, nil
	case s.ACLineStatus == acOnline, s.BatteryFlag == batteryMissing:
		return false, nil
	}
	return false, ErrUnknown
}

func (windowsSource) CPUTimes() (CPUTimes, error) {
	var idle, kernel, user windows.Filetime
	r, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return CPUTimes{}, err
	}
	// Kernel time includes idle time.
	return CPUTimes{Idle: ticks(idle), Total: ticks(kernel) + ticks(user)}, nil
}

func ticks(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
