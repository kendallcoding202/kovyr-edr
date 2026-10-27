package agent

import (
	"testing"
	"time"
)

func TestBackoffGrowsAndCaps(t *testing.T) {
	lo := Backoff{Base: 5 * time.Second, Max: 15 * time.Minute, Rand: func() float64 { return 0 }}
	hi := lo
	hi.Rand = func() float64 { return 0.999999 }
	wantWindows := []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 900, 900}
	for i, w := range wantWindows {
		w *= time.Second
		attempt := i + 1
		if got := lo.Delay(attempt); got != w/2 {
			t.Errorf("attempt %d: low jitter %v, want %v", attempt, got, w/2)
		}
		if got := hi.Delay(attempt); got <= w/2 || got > w {
			t.Errorf("attempt %d: high jitter %v, want in (%v, %v]", attempt, got, w/2, w)
		}
	}
}

func TestBackoffNeverHotLoopsOrOverflows(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 1 << 62, Rand: func() float64 { return 0.5 }}
	for _, attempt := range []int{-5, 0, 1, 63, 64, 1000, 1 << 30} {
		d := b.Delay(attempt)
		if d < b.Base/2 || d > b.Max {
			t.Errorf("attempt %d: delay %v out of range", attempt, d)
		}
	}
	// Zero config still waits.
	if d := (Backoff{}).Delay(1); d < time.Second {
		t.Errorf("zero config delay %v", d)
	}
	// A broken random source cannot produce zero or negative delays.
	bad := Backoff{Base: time.Second, Max: time.Minute, Rand: func() float64 { return -3 }}
	if d := bad.Delay(1); d < 500*time.Millisecond {
		t.Errorf("bad rand delay %v", d)
	}
}

func TestBackoffJitterSpreads(t *testing.T) {
	b := Backoff{Base: 10 * time.Second, Max: time.Hour}
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		seen[b.Delay(3)] = true
	}
	if len(seen) < 10 {
		t.Errorf("only %d distinct delays in 50 draws; jitter is not working", len(seen))
	}
}
