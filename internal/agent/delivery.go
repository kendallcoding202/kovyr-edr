package agent

import (
	"sort"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// The tripwire's news (a trip, or the busiest window) is acknowledged only
// once the server has accepted a statement carrying it, and only if that
// statement was still fresh enough to pass ingest's clock check (SPEC 6.5,
// 8). Until then every new statement carries it again. A trip whose
// statement fails to deliver is sent again in a new statement, with a
// fresh nonce, at the next retry (Run): a queued statement goes stale in
// minutes, and the next scheduled heartbeat can be 15 minutes away.

const (
	// serverClockWindow: ingest refuses a statement whose observed_at is
	// more than this from its clock when the statement arrives (SPEC 8).
	serverClockWindow = 5 * time.Minute

	// maxAckAge: a 2xx for a statement older than this does not count as
	// the server taking its tripwire news. halden answers 202 before it
	// checks the clock and may refuse the statement later; a minute's
	// margin allows for the two clocks differing.
	maxAckAge = serverClockWindow - time.Minute

	// tripRefreshAge: once the statement carrying an undelivered trip is
	// this old, the next retry carries the trip in a new statement
	// instead, so it reaches the server well inside the clock window.
	tripRefreshAge = 2 * time.Minute

	// maxPendingAcks bounds the acknowledgements kept for queued
	// statements. Forgetting the oldest is safe: anything it would have
	// acknowledged rides on every newer statement too, so at worst a trip
	// is reported twice.
	maxPendingAcks = 16
)

// delivery is the Agent's record of tripwire news on its way.
type delivery struct {
	pending map[uint32]pendingAck // by seq: statements still queued
	// tripSeq is the newest statement carrying a trip the server has not
	// accepted (0: none is owed). tripAt is when it was made, zero once it
	// has left the queue without being accepted.
	tripSeq uint32
	tripAt  time.Time
}

type pendingAck struct {
	ack func()
	at  time.Time // observed_at
}

// expect records a statement just queued, with the tripwire's
// acknowledgement for it.
func (d *delivery) expect(st *proof.Statement, ack func()) {
	if d.pending == nil {
		d.pending = map[uint32]pendingAck{}
	}
	d.pending[st.Seq] = pendingAck{ack: ack, at: st.ObservedAt}
	if len(d.pending) > maxPendingAcks {
		seqs := make([]uint32, 0, len(d.pending))
		for s := range d.pending {
			seqs = append(seqs, s)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for _, s := range seqs[:len(seqs)-maxPendingAcks] {
			delete(d.pending, s)
		}
	}
	// An unacknowledged trip is in every new statement, so a statement
	// without one means none is owed.
	if st.Readings.Tripwire.Triggered {
		d.tripSeq, d.tripAt = st.Seq, st.ObservedAt
	} else {
		d.tripSeq, d.tripAt = 0, time.Time{}
	}
}

// delivered records that the server accepted (2xx) statement seq at now.
// It reports false when the statement was too old for that to count.
func (d *delivery) delivered(seq uint32, now time.Time) bool {
	p, ok := d.pending[seq]
	delete(d.pending, seq)
	if !ok {
		return true // made before a restart: its tripwire is gone
	}
	if now.Sub(p.at) > maxAckAge {
		if seq == d.tripSeq {
			d.tripAt = time.Time{}
		}
		return false
	}
	p.ack()
	if seq >= d.tripSeq {
		d.tripSeq, d.tripAt = 0, time.Time{}
	}
	return true
}

// undelivered records that statement seq left the queue unaccepted.
func (d *delivery) undelivered(seq uint32) {
	delete(d.pending, seq)
	if seq == d.tripSeq {
		d.tripAt = time.Time{}
	}
}

// tripOwed reports whether a trip still waits for the server.
func (d *delivery) tripOwed() bool { return d.tripSeq != 0 }

// tripNeedsNewStatement reports whether no queued statement can still
// deliver the owed trip in time: the one carrying it left the queue, or
// is tripRefreshAge old.
func (d *delivery) tripNeedsNewStatement(now time.Time) bool {
	return d.tripSeq != 0 && (d.tripAt.IsZero() || now.Sub(d.tripAt) >= tripRefreshAge)
}
