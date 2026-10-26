package receiver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/agent"
	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

var t0 = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

type testDev struct {
	s        proof.Signer
	seq      uint32
	prev     proof.Digest
	undoSeq  uint32
	undoPrev proof.Digest
}

// undo forgets the last statement (it was refused, so the chain head
// stays where it was).
func (d *testDev) undo() { d.seq, d.prev = d.undoSeq, d.undoPrev }

func newDev(t *testing.T) *testDev {
	t.Helper()
	k, err := proof.GenerateSoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	s, _ := proof.NewSoftwareSigner(k)
	return &testDev{s: s}
}

func (d *testDev) enrolled(label string) Device {
	return Device{DeviceID: proof.DeviceID(d.s.Public()), PublicKey: d.s.Public().Base64(), Label: label}
}

func healthy() proof.Readings {
	return proof.Readings{
		SecurityCenter: proof.SecurityCenter{State: proof.AvailOK, Products: 1, Enabled: 1, UpToDate: 1},
		Defender: proof.Defender{State: proof.AvailOK, AMService: proof.ToggleOn, Antivirus: proof.ToggleOn,
			RealTime: proof.ToggleOn, BehaviorMonitor: proof.ToggleOn, TamperProtection: proof.ToggleOn,
			RunningMode: proof.ModeNormal},
		EDR:                proof.EDR{State: proof.AvailOK, Agents: []proof.EDRAgent{{Vendor: proof.VendorHuntress, Running: true}}},
		BitLocker:          proof.VolumeOn,
		FirewallProfilesOn: 3,
		DriverBlocklist:    proof.BlocklistDefault,
		MemoryIntegrity:    proof.ToggleOn,
	}
}

type opt struct {
	nonce    *proof.Nonce
	observed time.Time
	readings func(*proof.Readings)
	prev     *proof.Digest
	seq      uint32
}

// next signs the device's next statement, fetching a nonce from r.
func (d *testDev) next(t *testing.T, r *Receiver, c *clock, o opt) []byte {
	t.Helper()
	var n proof.Nonce
	if o.nonce != nil {
		n = *o.nonce
	} else {
		var err error
		if n, err = r.IssueNonce(proof.DeviceID(d.s.Public())); err != nil {
			t.Fatal(err)
		}
	}
	h := proof.Header{Seq: d.seq + 1, Prev: d.prev, Nonce: n, ObservedAt: c.now, AgentVersion: agent.Version}
	if o.seq != 0 {
		h.Seq = o.seq
	}
	if !o.observed.IsZero() {
		h.ObservedAt = o.observed
	}
	if o.prev != nil {
		h.Prev = *o.prev
	}
	h.Salt, _ = proof.NewSalt()
	rd := healthy()
	if o.readings != nil {
		o.readings(&rd)
	}
	payload, err := proof.BuildStatement(d.s.Public(), h, agent.SensorHealth(), rd)
	if err != nil {
		t.Fatal(err)
	}
	env, err := proof.SignEnvelope(payload, d.s)
	if err != nil {
		t.Fatal(err)
	}
	d.undoSeq, d.undoPrev = d.seq, d.prev
	d.seq, d.prev = h.Seq, proof.PayloadDigest(payload)
	return env.Canonical()
}

func newReceiver(t *testing.T, store *Store, devs ...*testDev) (*Receiver, *clock) {
	t.Helper()
	c := &clock{now: t0}
	var ds []Device
	for _, d := range devs {
		ds = append(ds, d.enrolled("Front desk PC"))
	}
	r, err := New(Config{Interval: 15 * time.Minute, Now: c.Now}, ds, store)
	if err != nil {
		t.Fatal(err)
	}
	return r, c
}

func expect(t *testing.T, res Result, status int, outcome string) {
	t.Helper()
	if res.Status != status || res.Outcome != outcome {
		t.Fatalf("got %d %s (%s), want %d %s", res.Status, res.Outcome, res.Reason, status, outcome)
	}
}

func hasEvent(res Result, kind string) bool {
	for _, e := range res.Events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func statusOf(t *testing.T, r *Receiver, d *testDev) DeviceStatus {
	t.Helper()
	for _, s := range r.Status().Devices {
		if s.DeviceID == proof.DeviceID(d.s.Public()) {
			return s
		}
	}
	t.Fatal("device missing from status")
	return DeviceStatus{}
}

func TestHealthyChain(t *testing.T) {
	d := newDev(t)
	r, c := newReceiver(t, nil, d)
	for i := 0; i < 3; i++ {
		res := r.Receive(d.next(t, r, c, opt{}))
		expect(t, res, 200, "accepted")
		if len(res.Events) != 0 {
			t.Fatalf("healthy statement raised %v", res.Events)
		}
		c.now = c.now.Add(15 * time.Minute)
	}
	c.now = c.now.Add(-14 * time.Minute)
	s := statusOf(t, r, d)
	if s.LastSeq != 3 || s.Overdue || len(s.Gaps) != 0 || s.TamperEvents != 0 || s.Label != "Front desk PC" {
		t.Fatalf("status %+v", s)
	}
}

func TestReplayOfAnOldSeqIsRefused(t *testing.T) {
	d := newDev(t)
	r, c := newReceiver(t, nil, d)
	var envs [][]byte
	for i := 0; i < 3; i++ {
		envs = append(envs, d.next(t, r, c, opt{}))
		expect(t, r.Receive(envs[i]), 200, "accepted")
		c.now = c.now.Add(time.Minute)
	}
	// Exact re-delivery of the latest (a lost response): idempotent.
	res := r.Receive(envs[2])
	expect(t, res, 200, "duplicate")
	// Re-sending an older report is a replay.
	res = r.Receive(envs[1])
	expect(t, res, 409, "refused")
	if !hasEvent(res, EvReplayOldSeq) {
		t.Errorf("events %v", res.Events)
	}
	// So is a freshly signed report that reuses an old seq.
	res = r.Receive(d.next(t, r, c, opt{seq: 2}))
	expect(t, res, 409, "refused")
	if !hasEvent(res, EvReplayOldSeq) {
		t.Errorf("events %v", res.Events)
	}
	if s := statusOf(t, r, d); s.LastSeq != 3 || !s.HasEvent(EvReplayOldSeq) {
		t.Errorf("status %+v", s)
	}
}

func TestReusedNonceIsRefused(t *testing.T) {
	d := newDev(t)
	r, c := newReceiver(t, nil, d)
	n, _ := r.IssueNonce(proof.DeviceID(d.s.Public()))
	expect(t, r.Receive(d.next(t, r, c, opt{nonce: &n})), 200, "accepted")
	res := r.Receive(d.next(t, r, c, opt{nonce: &n}))
	expect(t, res, 409, "refused")
	if !hasEvent(res, EvReplayNonce) {
		t.Errorf("events %v", res.Events)
	}
}

func TestUnknownExpiredAndMisdirectedNonces(t *testing.T) {
	a, b := newDev(t), newDev(t)
	r, c := newReceiver(t, nil, a, b)
	var random proof.Nonce
	random[3] = 7
	res := r.Receive(a.next(t, r, c, opt{nonce: &random}))
	expect(t, res, 409, "refused")
	if !hasEvent(res, EvUnknownNonce) {
		t.Errorf("unknown: %v", res.Events)
	}
	a.undo() // that report was refused

	forB, _ := r.IssueNonce(proof.DeviceID(b.s.Public()))
	res = r.Receive(a.next(t, r, c, opt{nonce: &forB}))
	expect(t, res, 409, "refused")
	if !hasEvent(res, EvUnknownNonce) || res.Reason != "misdirected nonce" {
		t.Errorf("misdirected: %v %s", res.Events, res.Reason)
	}
	a.undo()

	old, _ := r.IssueNonce(proof.DeviceID(a.s.Public()))
	c.now = c.now.Add(11 * time.Minute)
	res = r.Receive(a.next(t, r, c, opt{nonce: &old}))
	expect(t, res, 409, "refused")
	if res.Reason != "expired nonce" {
		t.Errorf("expired: %s", res.Reason)
	}
	if _, err := r.IssueNonce("dev_0000000000000000"); err != ErrNotEnrolled {
		t.Errorf("challenge for an unenrolled device: %v", err)
	}
}

func TestBrokenPrevIsFlagged(t *testing.T) {
	d := newDev(t)
	r, c := newReceiver(t, nil, d)
	expect(t, r.Receive(d.next(t, r, c, opt{})), 200, "accepted")
	expect(t, r.Receive(d.next(t, r, c, opt{})), 200, "accepted")
	var wrong proof.Digest
	wrong[0] = 0xee
	res := r.Receive(d.next(t, r, c, opt{prev: &wrong}))
	expect(t, res, 200, "accepted")
	if !hasEvent(res, EvChainBroken) {
		t.Fatalf("events %v", res.Events)
	}
	// seq 1 must start from the genesis value.
	e := newDev(t)
	r2, c2 := newReceiver(t, nil, e)
	if res := r2.Receive(e.next(t, r2, c2, opt{prev: &wrong})); !hasEvent(res, EvChainBroken) {
		t.Fatalf("bad genesis: %v", res.Events)
	}
}

func TestMissingIntervalsAreGaps(t *testing.T) {
	d := newDev(t)
	r, c := newReceiver(t, nil, d)
	expect(t, r.Receive(d.next(t, r, c, opt{})), 200, "accepted")
	c.now = c.now.Add(15 * time.Minute)
	expect(t, r.Receive(d.next(t, r, c, opt{})), 200, "accepted")
	c.now = c.now.Add(60 * time.Minute) // three heartbeats never came
	expect(t, r.Receive(d.next(t, r, c, opt{})), 200, "accepted")
	s := statusOf(t, r, d)
	if len(s.Gaps) != 1 || s.Gaps[0].MissedIntervals != 3 || s.Gaps[0].Ongoing || s.Overdue {
		t.Fatalf("gaps %+v overdue %v", s.Gaps, s.Overdue)
	}
	// Then the device goes silent.
	c.now = c.now.Add(40 * time.Minute)
	s = statusOf(t, r, d)
	if !s.Overdue || len(s.Gaps) != 2 || !s.Gaps[1].Ongoing || s.Gaps[1].MissedIntervals != 2 || s.MissedIntervals != 5 {
		t.Fatalf("silent device: overdue %v gaps %+v missed %d", s.Overdue, s.Gaps, s.MissedIntervals)
	}
	// A device that never checked in is overdue too.
	e := newDev(t)
	r2, _ := newReceiver(t, nil, e)
	if s := statusOf(t, r2, e); !s.Overdue || s.LastCheckIn != nil {
		t.Fatalf("never seen: %+v", s)
	}
}

func TestMissingSeqIsFlagged(t *testing.T) {
	d := newDev(t)
	r, c := newReceiver(t, nil, d)
	expect(t, r.Receive(d.next(t, r, c, opt{})), 200, "accepted")
	d.next(t, r, c, opt{}) // signed but never delivered
	res := r.Receive(d.next(t, r, c, opt{}))
	expect(t, res, 200, "accepted")
	if !hasEvent(res, EvMissingSeq) {
		t.Fatalf("events %v", res.Events)
	}
	// First statement seen is not seq 1 (history before it is missing).
	e := newDev(t)
	r2, c2 := newReceiver(t, nil, e)
	if res := r2.Receive(e.next(t, r2, c2, opt{seq: 5})); !hasEvent(res, EvMissingSeq) {
		t.Fatalf("late start: %v", res.Events)
	}
}

func TestBadSignatureAndUnenrolledKeys(t *testing.T) {
	d, stranger := newDev(t), newDev(t)
	r, c := newReceiver(t, nil, d)
	env := d.next(t, r, c, opt{})
	e, _ := proof.ParseEnvelope(env)
	e.Signatures[0].Sig[10] ^= 1
	res := r.Receive(e.Canonical())
	expect(t, res, 400, "refused")
	if !hasEvent(res, EvBadSignature) {
		t.Errorf("events %v", res.Events)
	}
	// A stranger signing with its own key is not enrolled.
	sn, _ := r.IssueNonce(proof.DeviceID(d.s.Public()))
	expect(t, r.Receive(stranger.next(t, r, c, opt{nonce: &sn})), 403, "refused")
	// The stranger claiming the enrolled device's keyid fails the signature.
	forged := stranger.next(t, r, c, opt{nonce: &sn})
	fe, _ := proof.ParseEnvelope(forged)
	fe.Signatures[0].KeyID = d.s.Public().KeyID()
	expect(t, r.Receive(fe.Canonical()), 400, "refused")
	expect(t, r.Receive([]byte(`{"payload":"x"}`)), 400, "refused")
}

func TestClockChecks(t *testing.T) {
	d := newDev(t)
	r, c := newReceiver(t, nil, d)
	res := r.Receive(d.next(t, r, c, opt{observed: c.now.Add(10 * time.Minute)}))
	expect(t, res, 422, "refused")
	if !hasEvent(res, EvFutureTimestamp) {
		t.Errorf("future: %v", res.Events)
	}
	d.undo()
	res = r.Receive(d.next(t, r, c, opt{observed: c.now.Add(-6 * time.Minute)}))
	expect(t, res, 409, "refused")
	if !hasEvent(res, EvStale) || res.Events[0].Tamper {
		t.Errorf("stale: %v", res.Events)
	}
}

func TestTamperSignalsRaiseOnceAndClear(t *testing.T) {
	d := newDev(t)
	r, c := newReceiver(t, nil, d)
	expect(t, r.Receive(d.next(t, r, c, opt{})), 200, "accepted")
	attack := func(rd *proof.Readings) {
		rd.Defender.RealTime = proof.ToggleOff
		rd.Defender.TamperProtection = proof.ToggleOff
		rd.EDR.Agents[0].Running = false
		rd.FirewallProfilesOn = 1
	}
	res := r.Receive(d.next(t, r, c, opt{readings: attack}))
	expect(t, res, 200, "accepted")
	for _, k := range []string{EvProtectionOff, EvTamperOff, EvEDRNotRunning} {
		if !hasEvent(res, k) {
			t.Errorf("no %s event in %v", k, res.Events)
		}
	}
	res = r.Receive(d.next(t, r, c, opt{readings: attack}))
	if len(res.Events) != 0 {
		t.Errorf("an ongoing condition raised again: %v", res.Events)
	}
	s := statusOf(t, r, d)
	want := []string{ // sorted
		"edr_not_running:huntress",
		"protection_off:defender_real_time_protection",
		"protection_off:firewall_1_of_3_profiles_on",
		"tamper_protection_off:defender",
	}
	if len(s.TamperSignals) != len(want) {
		t.Errorf("active signals %v, want %v", s.TamperSignals, want)
	}
	for i, w := range want {
		if i < len(s.TamperSignals) && s.TamperSignals[i] != w {
			t.Errorf("active signal %d is %q, want %q", i, s.TamperSignals[i], w)
		}
	}
	// Each Defender switch is a signal on its own, and so is Security
	// Center listing antivirus with none of it on.
	for detail, f := range map[string]func(*proof.Readings){
		"defender_antivirus":   func(rd *proof.Readings) { rd.Defender.Antivirus = proof.ToggleOff },
		"defender_service":     func(rd *proof.Readings) { rd.Defender.AMService = proof.ToggleOff },
		"no_enabled_antivirus": func(rd *proof.Readings) { rd.SecurityCenter.Enabled = 0 },
	} {
		st := &proof.Statement{Readings: healthy()}
		f(&st.Readings)
		if !conditions(st)[EvProtectionOff+":"+detail] {
			t.Errorf("%s is not a protection_off signal", detail)
		}
	}
	r.Receive(d.next(t, r, c, opt{}))
	if s := statusOf(t, r, d); len(s.TamperSignals) != 0 {
		t.Errorf("signals did not clear: %v", s.TamperSignals)
	}
	// Passive Defender (another AV is primary) with real-time off is normal.
	res = r.Receive(d.next(t, r, c, opt{readings: func(rd *proof.Readings) {
		rd.Defender.RunningMode = proof.ModePassive
		rd.Defender.RealTime = proof.ToggleOff
	}}))
	if hasEvent(res, EvProtectionOff) {
		t.Errorf("passive Defender flagged: %v", res.Events)
	}
}

func TestRestartReplaysTheStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "envelopes.jsonl")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	d := newDev(t)
	r, c := newReceiver(t, store, d)
	r.Receive(d.next(t, r, c, opt{}))
	c.now = c.now.Add(15 * time.Minute)
	env2 := d.next(t, r, c, opt{})
	r.Receive(env2)
	c.now = c.now.Add(45 * time.Minute)
	r.Receive(d.next(t, r, c, opt{readings: func(rd *proof.Readings) { rd.Defender.TamperProtection = proof.ToggleOff }}))
	r.Receive(env2) // replay, refused and recorded
	before := statusOf(t, r, d)

	r2, err := New(Config{Interval: 15 * time.Minute, Now: c.Now}, []Device{d.enrolled("Front desk PC")}, store)
	if err != nil {
		t.Fatal(err)
	}
	after := statusOf(t, r2, d)
	if after.LastSeq != before.LastSeq || after.Accepted != before.Accepted || after.Refused != before.Refused ||
		len(after.Events) != len(before.Events) || len(after.Gaps) != len(before.Gaps) || !after.HasSignal(EvTamperOff) {
		t.Fatalf("status changed across restart:\nbefore %+v\nafter  %+v", before, after)
	}
	// And the chain continues: an old envelope is still a replay.
	if res := r2.Receive(env2); res.Status != 409 {
		t.Fatalf("after restart, replay got %d", res.Status)
	}
}

// End to end: the real agent (HTTP client, queue, chain) against the real
// handler, over loopback HTTP as --dev-insecure allows.
func TestAgentToReceiverOverHTTP(t *testing.T) {
	k, _ := proof.GenerateSoftwareKey()
	s, _ := proof.NewSoftwareSigner(k)
	dev := Device{DeviceID: proof.DeviceID(s.Public()), PublicKey: s.Public().Base64()}
	r, err := New(Config{}, []Device{dev}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()
	client, err := agent.NewHTTPClient(srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(agent.Config{Dir: t.TempDir()}, s, checks.NewRunner(checks.HealthyFake()), client)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := a.Beat(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := a.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	st := r.Status().Devices[0]
	if st.LastSeq != 3 || st.Accepted != 3 || st.TamperEvents != 0 || a.QueueLen() != 0 {
		t.Fatalf("status %+v queue %d", st, a.QueueLen())
	}
	if st.Latest == nil || st.Latest.DefenderRealTime != "on" || st.Latest.EDRRunning != 1 {
		t.Fatalf("latest %+v", st.Latest)
	}
	// An unenrolled device gets no challenge, so it never spends a seq.
	resp, err := http.Get(srv.URL + "/v0/challenge?device=dev_0000000000000000")
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unenrolled challenge: %v %v", resp.StatusCode, err)
	}
	resp, _ = http.Post(srv.URL+"/v0/enroll", "application/json", nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("enroll stub: %d", resp.StatusCode)
	}
}
