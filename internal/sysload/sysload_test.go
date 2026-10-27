package sysload

import "testing"

func TestBusyPercent(t *testing.T) {
	for _, c := range []struct {
		from, to CPUTimes
		pct      int
		ok       bool
	}{
		{CPUTimes{Idle: 0, Total: 0}, CPUTimes{Idle: 50, Total: 100}, 50, true},
		{CPUTimes{Idle: 100, Total: 200}, CPUTimes{Idle: 110, Total: 300}, 90, true},
		{CPUTimes{Idle: 100, Total: 200}, CPUTimes{Idle: 200, Total: 300}, 0, true},
		{CPUTimes{Idle: 100, Total: 200}, CPUTimes{Idle: 100, Total: 300}, 100, true},
		{CPUTimes{Idle: 5, Total: 10}, CPUTimes{Idle: 5, Total: 10}, 0, false},  // no time passed
		{CPUTimes{Idle: 5, Total: 10}, CPUTimes{Idle: 1, Total: 20}, 0, false},  // idle went back
		{CPUTimes{Idle: 5, Total: 10}, CPUTimes{Idle: 50, Total: 20}, 0, false}, // more idle than time
		{CPUTimes{Idle: 5, Total: 100}, CPUTimes{Idle: 5, Total: 50}, 0, false}, // total went back
	} {
		pct, ok := BusyPercent(c.from, c.to)
		if pct != c.pct || ok != c.ok {
			t.Errorf("BusyPercent(%v, %v) = %d %v, want %d %v", c.from, c.to, pct, ok, c.pct, c.ok)
		}
	}
}

func TestFake(t *testing.T) {
	f := &Fake{}
	a, _ := f.CPUTimes()
	f.Advance(1000, 85)
	b, _ := f.CPUTimes()
	if pct, ok := BusyPercent(a, b); !ok || pct != 85 {
		t.Fatalf("fake busy %d %v", pct, ok)
	}
	f.SetBattery(true)
	if on, err := f.OnBattery(); !on || err != nil {
		t.Fatal("fake battery")
	}
}

func TestSystemNeverPanics(t *testing.T) {
	s := System()
	s.OnBattery()
	a, errA := s.CPUTimes()
	b, errB := s.CPUTimes()
	if errA == nil && errB == nil && b.Total < a.Total {
		t.Fatal("processor counters went backwards")
	}
}
