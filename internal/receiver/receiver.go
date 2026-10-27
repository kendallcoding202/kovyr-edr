// Package receiver is the development heartbeat receiver: it issues
// nonces, verifies signed statements from enrolled devices, checks the
// nonce, seq continuity and prev chain, stores every envelope in a
// JSON-lines file, and reports per-device check-ins, gaps and tamper
// signals.
//
// It is for local testing only. The production receiver is part of
// Kovyr's halden service, which implements the same API (docs/api.md).
//
// Ingest follows SPEC section 8 and the engine's reference ingest
// (tlog.Server): nonces are issued for one device, used once and expire
// after 10 minutes; observed_at must be within 5 minutes of this clock.
// A seq more than one ahead of the last is accepted, as SPEC 8 says: the
// hole is a lost-statement gap, shown in status (gaps[].lost_statements,
// lost_statements) and raised once as a missing_seq event, so one lost
// upload can never lock a device out.
package receiver

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Event kinds. Tamper signals are the ones an owner must be told about.
const (
	EvProtectionOff    = "protection_off"
	EvTamperOff        = "tamper_protection_off"
	EvEDRNotRunning    = "edr_not_running"
	EvChainBroken      = "chain_broken"
	EvReplayOldSeq     = "replay_old_seq"
	EvReplayNonce      = "replay_nonce"
	EvUnknownNonce     = "unknown_nonce" // not issued here, expired, or issued to another device
	EvMissingSeq       = "missing_seq"
	EvBadSignature     = "bad_signature"
	EvInvalidStatement = "invalid_statement"
	EvFutureTimestamp  = "future_timestamp"
	EvOutOfOrder       = "out_of_order"
	EvStale            = "stale_statement" // info: delivered too late; the next report shows missing_seq
)

// SPEC section 8 limits (as in the engine's tlog.Server).
const (
	NonceLifetime = 10 * time.Minute
	MaxClockSkew  = 5 * time.Minute
)

const (
	maxEventsPerDevice = 500
	maxCheckinsPerDev  = 20000
	maxIssuedNonces    = 100000
)

var tamperKinds = map[string]bool{
	EvProtectionOff: true, EvTamperOff: true, EvEDRNotRunning: true, EvChainBroken: true,
	EvReplayOldSeq: true, EvReplayNonce: true, EvUnknownNonce: true, EvMissingSeq: true,
	EvBadSignature: true, EvInvalidStatement: true, EvFutureTimestamp: true, EvOutOfOrder: true,
}

// Event is one thing that happened to a device.
type Event struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Seq    uint32    `json:"seq,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Tamper bool      `json:"tamper"`
}

// Config tunes the receiver. Zero values get defaults.
type Config struct {
	Interval time.Duration // expected heartbeat interval
	Now      func() time.Time
}

type nonceInfo struct {
	device string
	issued time.Time
	used   bool
}

type device struct {
	enrolled   Device
	key        *proof.PublicKey
	haveChain  bool
	lastSeq    uint32
	lastDigest proof.Digest
	lastObs    time.Time
	lastRecv   time.Time
	checkins   []checkin // accepted statements, in seq order
	latest     *proof.Statement
	active     map[string]bool
	events     []Event
	accepted   int
	refused    int
}

// Receiver holds all state behind one mutex; it is a dev tool.
type Receiver struct {
	mu      sync.Mutex
	cfg     Config
	devices map[string]*device // by keyid
	nonces  map[proof.Nonce]*nonceInfo
	store   *Store
	reload  func() ([]Device, error)
}

// New creates a receiver for the enrolled devices. If store is non-nil,
// its history is replayed first so status survives restarts.
func New(cfg Config, devices []Device, store *Store) (*Receiver, error) {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	r := &Receiver{cfg: cfg, devices: map[string]*device{}, nonces: map[proof.Nonce]*nonceInfo{}, store: store}
	if err := r.setDevices(devices); err != nil {
		return nil, err
	}
	if store != nil {
		if err := store.Replay(r.replay); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// SetReloader lets the receiver re-read the enrolled devices when an
// unknown device shows up (so enrolling does not need a restart).
func (r *Receiver) SetReloader(f func() ([]Device, error)) { r.reload = f }

func (r *Receiver) setDevices(ds []Device) error {
	for _, d := range ds {
		key, err := d.parse()
		if err != nil {
			return err
		}
		if old, ok := r.devices[key.KeyID()]; ok {
			old.enrolled = d
			continue
		}
		r.devices[key.KeyID()] = &device{enrolled: d, key: key, active: map[string]bool{}}
	}
	return nil
}

func (r *Receiver) byDeviceID(id string) *device {
	for _, d := range r.devices {
		if d.enrolled.DeviceID == id {
			return d
		}
	}
	return nil
}

// ErrNotEnrolled is returned for challenges and heartbeats from devices
// that are not in the devices file.
var ErrNotEnrolled = errors.New("device not enrolled")

// IssueNonce returns a fresh one-time challenge for an enrolled device.
func (r *Receiver) IssueNonce(deviceID string) (proof.Nonce, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byDeviceID(deviceID) == nil && r.reload != nil {
		if ds, err := r.reload(); err == nil {
			r.setDevices(ds)
		}
	}
	if r.byDeviceID(deviceID) == nil {
		return proof.Nonce{}, ErrNotEnrolled
	}
	now := r.cfg.Now()
	if len(r.nonces) >= maxIssuedNonces/2 {
		for n, info := range r.nonces {
			// Past its lifetime a nonce is refused anyway, used or not.
			if now.Sub(info.issued) > NonceLifetime {
				delete(r.nonces, n)
			}
		}
		if len(r.nonces) >= maxIssuedNonces {
			return proof.Nonce{}, errors.New("too many outstanding challenges")
		}
	}
	var n proof.Nonce
	if _, err := rand.Read(n[:]); err != nil {
		return n, err
	}
	r.nonces[n] = &nonceInfo{device: deviceID, issued: now}
	return n, nil
}

// Result is the outcome of one POST /v0/heartbeat.
type Result struct {
	Status   int    // HTTP status
	Outcome  string // accepted, duplicate, refused
	DeviceID string
	Seq      uint32
	Events   []Event
	Reason   string
}

// Receive verifies and records one envelope.
func (r *Receiver) Receive(raw []byte) Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	res := r.receive(raw, now, false)
	if r.store != nil && res.DeviceID != "" {
		rec := Record{ReceivedAt: now.UTC(), DeviceID: res.DeviceID, Outcome: res.Outcome, Seq: res.Seq, Events: res.Events, Reason: res.Reason}
		if res.Outcome == "accepted" {
			rec.Envelope = string(raw)
		}
		if err := r.store.Append(rec); err != nil {
			return Result{Status: http.StatusInsufficientStorage, Outcome: "error", Reason: "store: " + err.Error()}
		}
	}
	return res
}

func refuse(status int, d *device, reason string, ev ...Event) Result {
	res := Result{Status: status, Outcome: "refused", Reason: reason, Events: ev}
	if d != nil {
		res.DeviceID = d.enrolled.DeviceID
		d.refused++
		for _, e := range ev {
			d.add(e)
		}
	}
	return res
}

// receive applies every ingest check. replaying re-applies stored history
// after a restart: nonces issued before the restart are unknown then, and
// the clock check used the original receive time.
func (r *Receiver) receive(raw []byte, now time.Time, replaying bool) Result {
	env, err := proof.ParseEnvelope(raw)
	if err != nil {
		return refuse(http.StatusBadRequest, nil, err.Error())
	}
	if len(env.Signatures) != 1 {
		return refuse(http.StatusBadRequest, nil, "a device envelope carries exactly one signature")
	}
	d := r.devices[env.Signatures[0].KeyID]
	if d == nil && r.reload != nil && !replaying {
		if ds, err := r.reload(); err == nil {
			r.setDevices(ds)
			d = r.devices[env.Signatures[0].KeyID]
		}
	}
	if d == nil {
		return refuse(http.StatusForbidden, nil, ErrNotEnrolled.Error())
	}
	ev := func(kind string, seq uint32, detail string) Event {
		return Event{At: now.UTC(), Kind: kind, Seq: seq, Detail: detail, Tamper: tamperKinds[kind]}
	}
	if err := proof.VerifyEnvelope(env, d.key); err != nil {
		return refuse(http.StatusBadRequest, d, "bad signature", ev(EvBadSignature, 0, err.Error()))
	}
	st, err := proof.ValidateStatement(env.Payload)
	if err == nil && st.KeyID != d.key.KeyID() {
		err = errors.New("statement subject is not the signing key")
	}
	if err != nil {
		return refuse(http.StatusUnprocessableEntity, d, err.Error(), ev(EvInvalidStatement, 0, err.Error()))
	}
	digest := proof.PayloadDigest(env.Payload)

	// Replays: an old seq is refused, except an exact re-delivery of the
	// latest statement (the agent retries when a response is lost).
	if d.haveChain && st.Seq <= d.lastSeq {
		if st.Seq == d.lastSeq && digest == d.lastDigest {
			return Result{Status: http.StatusOK, Outcome: "duplicate", DeviceID: d.enrolled.DeviceID, Seq: st.Seq}
		}
		return refuse(http.StatusConflict, d, "old seq",
			ev(EvReplayOldSeq, st.Seq, fmt.Sprintf("seq %d is not after the last accepted seq %d", st.Seq, d.lastSeq)))
	}
	info := r.nonces[st.Nonce]
	switch {
	case info != nil && info.used:
		return refuse(http.StatusConflict, d, "reused nonce", ev(EvReplayNonce, st.Seq, "this nonce was already used"))
	case info != nil && info.device != d.enrolled.DeviceID:
		return refuse(http.StatusConflict, d, "misdirected nonce", ev(EvUnknownNonce, st.Seq, "nonce was issued to a different device"))
	case info == nil && !replaying:
		return refuse(http.StatusConflict, d, "unknown nonce", ev(EvUnknownNonce, st.Seq, "nonce was not issued by this receiver (or has expired)"))
	case info != nil && now.Sub(info.issued) > NonceLifetime:
		return refuse(http.StatusConflict, d, "expired nonce", ev(EvUnknownNonce, st.Seq, "nonce is older than 10 minutes"))
	}
	if skew := now.Sub(st.ObservedAt); !replaying && skew < -MaxClockSkew {
		return refuse(http.StatusUnprocessableEntity, d, "observed_at is in the future",
			ev(EvFutureTimestamp, st.Seq, st.ObservedAt.Format(proof.TimeLayout)))
	} else if !replaying && skew > MaxClockSkew {
		return refuse(http.StatusConflict, d, "statement too old",
			ev(EvStale, st.Seq, "observed_at is more than 5 minutes ago"))
	}
	if info == nil { // replaying history from before a restart
		info = &nonceInfo{device: d.enrolled.DeviceID, issued: st.ObservedAt}
		r.nonces[st.Nonce] = info
	}
	info.used = true

	// Accepted. Judge the chain; problems are flagged, not refused, so the
	// device keeps reporting and the owner sees the break.
	var events []Event
	switch {
	case !d.haveChain && st.Seq == 1:
		if st.Prev != proof.GenesisPrev {
			events = append(events, ev(EvChainBroken, st.Seq, "seq 1 does not start from the genesis value"))
		}
	case !d.haveChain:
		events = append(events, ev(EvMissingSeq, st.Seq, fmt.Sprintf("first statement seen is seq %d; seq 1-%d never arrived", st.Seq, st.Seq-1)))
	case st.Seq == d.lastSeq+1:
		if st.Prev != d.lastDigest {
			events = append(events, ev(EvChainBroken, st.Seq, fmt.Sprintf("prev does not match seq %d", d.lastSeq)))
		}
	default:
		events = append(events, ev(EvMissingSeq, st.Seq, fmt.Sprintf("seq %d-%d missing (lost, dropped or withheld)", d.lastSeq+1, st.Seq-1)))
	}
	if d.haveChain && st.ObservedAt.Before(d.lastObs) {
		events = append(events, ev(EvOutOfOrder, st.Seq, "observed_at is earlier than the previous statement"))
	}
	conds := conditions(st)
	for _, k := range sortedKeys(conds) {
		if !d.active[k] {
			kind, detail, _ := strings.Cut(k, ":")
			events = append(events, ev(kind, st.Seq, detail))
		}
	}
	d.active = conds
	for _, e := range events {
		d.add(e)
	}
	d.haveChain, d.lastSeq, d.lastDigest, d.lastObs, d.lastRecv = true, st.Seq, digest, st.ObservedAt, now
	d.latest = st
	d.accepted++
	d.checkins = append(d.checkins, checkin{at: st.ObservedAt, seq: st.Seq,
		interval: time.Duration(st.Schedule.IntervalS) * time.Second, deferred: time.Duration(st.Schedule.DeferredS) * time.Second})
	if len(d.checkins) > maxCheckinsPerDev {
		d.checkins = d.checkins[len(d.checkins)-maxCheckinsPerDev:]
	}
	return Result{Status: http.StatusOK, Outcome: "accepted", DeviceID: d.enrolled.DeviceID, Seq: st.Seq, Events: events}
}

// checkin is one accepted statement, as gap detection needs it.
type checkin struct {
	at       time.Time // observed_at
	seq      uint32
	interval time.Duration // schedule.interval_s: when the next one is due
	deferred time.Duration // schedule.deferred_s: how late this one was, on purpose
}

func (d *device) add(e Event) {
	d.events = append(d.events, e)
	if len(d.events) > maxEventsPerDevice {
		d.events = d.events[len(d.events)-maxEventsPerDevice:]
	}
}

// conditions are the tamper conditions a statement shows, keyed
// "kind:detail". An event is raised when one appears.
func conditions(st *proof.Statement) map[string]bool {
	c := map[string]bool{}
	rd := st.Readings
	def := rd.Defender
	if def.State == proof.AvailOK && def.RunningMode == proof.ModeNormal {
		// Defender is the active antivirus: any of these off is
		// protection turned off (a classic pre-ransomware step).
		if def.RealTime == proof.ToggleOff {
			c[EvProtectionOff+":defender_real_time_protection"] = true
		}
		if def.Antivirus == proof.ToggleOff {
			c[EvProtectionOff+":defender_antivirus"] = true
		}
		if def.AMService == proof.ToggleOff {
			c[EvProtectionOff+":defender_service"] = true
		}
	}
	if def.State == proof.AvailOK && def.TamperProtection == proof.ToggleOff {
		c[EvTamperOff+":defender"] = true
	}
	if sc := rd.SecurityCenter; sc.State == proof.AvailOK && sc.Products > 0 && sc.Enabled == 0 {
		c[EvProtectionOff+":no_enabled_antivirus"] = true
	}
	if n := rd.FirewallProfilesOn; n >= 0 && n < 3 {
		c[fmt.Sprintf("%s:firewall_%d_of_3_profiles_on", EvProtectionOff, n)] = true
	}
	if rd.EDR.State == proof.AvailOK {
		for _, a := range rd.EDR.Agents {
			if !a.Running {
				c[EvEDRNotRunning+":"+a.Vendor.String()] = true
			}
		}
	}
	return c
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// replay re-applies a stored record after a restart.
func (r *Receiver) replay(rec Record) {
	switch rec.Outcome {
	case "accepted":
		r.receive([]byte(rec.Envelope), rec.ReceivedAt, true)
	case "refused":
		if d := r.byDeviceID(rec.DeviceID); d != nil {
			d.refused++
			for _, e := range rec.Events {
				d.add(e)
			}
		}
	}
}
