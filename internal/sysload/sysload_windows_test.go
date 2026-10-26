package sysload

import (
	"testing"
	"time"
	"unsafe"
)

func TestSystemPowerStatusLayout(t *testing.T) {
	// SYSTEM_POWER_STATUS is 4 bytes then two DWORDs: 12 bytes.
	if n := unsafe.Sizeof(systemPowerStatus{}); n != 12 {
		t.Fatalf("SYSTEM_POWER_STATUS is %d bytes, want 12", n)
	}
}

func TestOnBatteryMapping(t *testing.T) {
	for _, c := range []struct {
		ac, flag uint8
		on       bool
		known    bool
	}{
		{0, 0, true, true},       // unplugged laptop
		{1, 0, false, true},      // plugged-in laptop
		{255, 128, false, true},  // desktop, no battery
		{255, 255, false, false}, // unknown
	} {
		on, err := onBattery(systemPowerStatus{ACLineStatus: c.ac, BatteryFlag: c.flag})
		if on != c.on || (err == nil) != c.known {
			t.Errorf("ac %d flag %d: on %v err %v", c.ac, c.flag, on, err)
		}
	}
}

// The real calls on this runner: power status reads, and the processor
// counters move forward with idle time no larger than total time.
func TestRealWindowsConditions(t *testing.T) {
	s := System()
	on, err := s.OnBattery()
	t.Logf("on battery: %v (%v)", on, err)
	a, err := s.CPUTimes()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	b, err := s.CPUTimes()
	if err != nil {
		t.Fatal(err)
	}
	pct, ok := BusyPercent(a, b)
	if !ok {
		t.Fatalf("counters did not advance: %+v -> %+v", a, b)
	}
	t.Logf("processor busy over 200 ms: %d%%", pct)
}
