package receiver

import (
	"sort"
	"strings"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Gap is a stretch with no statement for longer than the grace period,
// or a hole in the seq numbers (SPEC 8: statements signed but never
// received), or both.
type Gap struct {
	From            time.Time  `json:"from"`
	To              *time.Time `json:"to,omitempty"` // nil while ongoing
	MissedIntervals int        `json:"missed_intervals"`
	LostStatements  int        `json:"lost_statements"` // seq numbers skipped just before To
	Ongoing         bool       `json:"ongoing"`
}

// DeviceStatus is one device in GET /v0/status.
type DeviceStatus struct {
	DeviceID        string     `json:"device_id"`
	Label           string     `json:"label,omitempty"`
	LastCheckIn     *time.Time `json:"last_check_in,omitempty"` // when the receiver last accepted a statement
	LastObservedAt  *time.Time `json:"last_observed_at,omitempty"`
	LastSeq         uint32     `json:"last_seq"`
	Accepted        int        `json:"accepted"`
	Refused         int        `json:"refused"`
	Overdue         bool       `json:"overdue"`
	MissedIntervals int        `json:"missed_intervals"`
	LostStatements  int        `json:"lost_statements"` // total seq numbers never received
	Gaps            []Gap      `json:"gaps"`
	TamperSignals   []string   `json:"tamper_signals_active"` // from the latest statement
	TamperEvents    int        `json:"tamper_events"`
	Events          []Event    `json:"events"`
	Latest          *Latest    `json:"latest,omitempty"`
}

// Latest is a summary of the newest accepted statement.
type Latest struct {
	Seq                 uint32 `json:"seq"`
	DefenderState       string `json:"defender_state"`
	DefenderRealTime    string `json:"defender_real_time_protection"`
	DefenderTamper      string `json:"defender_tamper_protection"`
	DefenderMode        string `json:"defender_running_mode"`
	SecurityCenterState string `json:"security_center_state"`
	AVEnabled           int16  `json:"antivirus_products_enabled"`
	EDRRunning          int    `json:"edr_agents_running"`
	EDRStopped          int    `json:"edr_agents_not_running"`
	EDRTotal            int    `json:"edr_agents_total"`     // agents found; the list may be capped
	EDRTruncated        bool   `json:"edr_agents_truncated"` // the statement listed only some
	BitLocker           string `json:"bitlocker_os_volume"`
	FirewallProfilesOn  int8   `json:"firewall_profiles_on"`
	DriverBlocklist     string `json:"vulnerable_driver_blocklist"`
	MemoryIntegrity     string `json:"memory_integrity"`
}

// Status is GET /v0/status.
type Status struct {
	GeneratedAt       time.Time      `json:"generated_at"`
	ExpectedIntervalS int64          `json:"expected_interval_s"`
	DevOnly           bool           `json:"dev_only"`
	Devices           []DeviceStatus `json:"devices"`
}

// graceFactor: a check-in later than 1.5 intervals counts as missed.
const graceFactor = 1.5

// Status reports every enrolled device.
func (r *Receiver) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now().UTC()
	out := Status{GeneratedAt: now, ExpectedIntervalS: int64(r.cfg.Interval / time.Second), DevOnly: true, Devices: []DeviceStatus{}}
	for _, d := range r.devices {
		out.Devices = append(out.Devices, r.deviceStatus(d, now))
	}
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].DeviceID < out.Devices[j].DeviceID })
	return out
}

func (r *Receiver) deviceStatus(d *device, now time.Time) DeviceStatus {
	s := DeviceStatus{
		DeviceID: d.enrolled.DeviceID, Label: d.enrolled.Label, LastSeq: d.lastSeq,
		Accepted: d.accepted, Refused: d.refused, Gaps: []Gap{}, TamperSignals: []string{},
		Events: append([]Event{}, d.events...),
	}
	for _, e := range d.events {
		if e.Tamper {
			s.TamperEvents++
		}
	}
	for _, k := range sortedKeys(d.active) {
		s.TamperSignals = append(s.TamperSignals, k)
	}
	s.Gaps, s.MissedIntervals, s.LostStatements = gaps(d.checkins, now, r.cfg.Interval)
	if !d.haveChain {
		s.Overdue = true // enrolled but never checked in
		return s
	}
	recv, obs := d.lastRecv.UTC(), d.lastObs.UTC()
	s.LastCheckIn, s.LastObservedAt = &recv, &obs
	s.Overdue = float64(now.Sub(d.lastRecv)) > graceFactor*float64(r.cfg.Interval)
	if st := d.latest; st != nil {
		s.Latest = summarize(st)
	}
	return s
}

// gaps finds stretches between consecutive statements (by observed_at),
// and since the last one, that exceed the grace period, and holes in the
// seq numbers (lost statements). A hole before the first statement seen
// is a zero-length gap at that statement.
func gaps(checkins []checkin, now time.Time, interval time.Duration) (out []Gap, missed, lost int) {
	out = []Gap{}
	grace := time.Duration(graceFactor * float64(interval))
	if len(checkins) > 0 && checkins[0].seq > 1 {
		at := checkins[0].at.UTC()
		n := int(checkins[0].seq) - 1
		out = append(out, Gap{From: at, To: &at, LostStatements: n})
		lost += n
	}
	for i := 1; i < len(checkins); i++ {
		a, b := checkins[i-1], checkins[i]
		g := Gap{From: a.at.UTC(), LostStatements: int(b.seq) - int(a.seq) - 1}
		if b.at.Sub(a.at) > grace {
			g.MissedIntervals = int(b.at.Sub(a.at)/interval) - 1
			if g.MissedIntervals < 1 {
				g.MissedIntervals = 1
			}
		}
		if g.MissedIntervals == 0 && g.LostStatements <= 0 {
			continue
		}
		if g.LostStatements < 0 {
			g.LostStatements = 0
		}
		to := b.at.UTC()
		g.To = &to
		out = append(out, g)
		missed += g.MissedIntervals
		lost += g.LostStatements
	}
	if len(checkins) > 0 {
		last := checkins[len(checkins)-1].at
		if now.Sub(last) > grace {
			n := int(now.Sub(last) / interval)
			out = append(out, Gap{From: last.UTC(), MissedIntervals: n, Ongoing: true})
			missed += n
		}
	}
	return out, missed, lost
}

func summarize(st *proof.Statement) *Latest {
	rd := st.Readings
	l := &Latest{
		Seq:                 st.Seq,
		DefenderState:       rd.Defender.State.String(),
		DefenderRealTime:    rd.Defender.RealTime.String(),
		DefenderTamper:      rd.Defender.TamperProtection.String(),
		DefenderMode:        rd.Defender.RunningMode.String(),
		SecurityCenterState: rd.SecurityCenter.State.String(),
		AVEnabled:           rd.SecurityCenter.Enabled,
		BitLocker:           rd.BitLocker.String(),
		FirewallProfilesOn:  rd.FirewallProfilesOn,
		DriverBlocklist:     rd.DriverBlocklist.String(),
		MemoryIntegrity:     rd.MemoryIntegrity.String(),
	}
	for _, a := range rd.EDR.Agents {
		if a.Running {
			l.EDRRunning++
		} else {
			l.EDRStopped++
		}
	}
	l.EDRTotal, l.EDRTruncated = st.EDRAgentsTotal, st.EDRAgentsTruncated
	return l
}

// HasSignal reports whether a device has an active tamper signal of kind
// (used by tests).
func (s DeviceStatus) HasSignal(kind string) bool {
	for _, k := range s.TamperSignals {
		if strings.HasPrefix(k, kind+":") {
			return true
		}
	}
	return false
}

// HasEvent reports whether a device has an event of kind.
func (s DeviceStatus) HasEvent(kind string) bool {
	for _, e := range s.Events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}
