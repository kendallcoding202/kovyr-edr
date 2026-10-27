package agent

import (
	"math/rand/v2"
	"time"
)

// Backoff computes retry delays: exponential from Base, capped at Max,
// with "equal jitter" (a random point in the upper half of the window) so
// many agents coming back online do not retry in lockstep and no delay is
// ever near zero (no hot loop).
type Backoff struct {
	Base time.Duration
	Max  time.Duration
	// Rand returns a float in [0,1); nil uses math/rand/v2.
	Rand func() float64
}

// Delay returns the wait before retry number attempt (1 for the first).
func (b Backoff) Delay(attempt int) time.Duration {
	base, max := b.Base, b.Max
	if base <= 0 {
		base = 5 * time.Second
	}
	if max < base {
		max = base
	}
	window := base
	for i := 1; i < attempt && window < max; i++ {
		if window > max/2 {
			window = max // doubling would pass max (and could overflow)
			break
		}
		window *= 2
	}
	r := b.Rand
	if r == nil {
		r = rand.Float64
	}
	f := r()
	if f < 0 || f >= 1 {
		f = 0.5
	}
	return window/2 + time.Duration(f*float64(window/2))
}
