package sample

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/brand"
	"github.com/kendallcoding202/kovyr-edr/proof/dsse"
	"github.com/kendallcoding202/kovyr-edr/proof/merkle"
	"github.com/kendallcoding202/kovyr-edr/proof/pack"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tlog"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
	"github.com/kendallcoding202/kovyr-edr/proof/witness"
)

// Variant selects which version of October the world lives through.
type Variant string

const (
	Genuine  Variant = "genuine"  // what really happened
	Backdate Variant = "backdate" // laptop D07 forges reports to fill its gap
	Replay   Variant = "replay"   // an attacker replays an old all-green report
)

// The fictional firm and its month. Everything here is invented.
const (
	FirmName       = "Maple Street Tax & Bookkeeping (sample)"
	RangeFrom      = "2026-10-01"
	RangeTo        = "2026-10-30"
	GapDevice      = 7 // the laptop that goes quiet
	seedLabel      = "proof-demo-seed/v1"
	savedCPDate    = "2026-10-20" // the checkpoint the firm's app kept
	witnessLabelFm = "Simulated witness %c"
)

var (
	day0       = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	gapStart   = time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	tamperDay  = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	finalCPAt  = time.Date(2026, 10, 31, 5, 0, 0, 0, time.UTC)
	IssuedAt   = time.Date(2026, 10, 31, 6, 5, 0, 0, time.UTC)
	firstCPDay = time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
)

// det derives reproducible pseudo-random bytes. Real agents and servers use
// crypto/rand; the demo must regenerate byte for byte.
func det(parts ...string) [32]byte {
	return sha256.Sum256([]byte(seedLabel + "\n" + strings.Join(parts, "\n")))
}

func detInt(n int, parts ...string) int {
	b := det(parts...)
	return int(binary.BigEndian.Uint32(b[:4]) % uint32(n))
}

type device struct {
	signer sigs.Signer
	number int
	class  posture.DeviceClass
	plat   posture.Platform
	idle   uint16
	admins uint16
}

type firm struct {
	idx       int
	name      string
	tenant    sigs.Signer
	connector sigs.Signer
	staff     sigs.Signer
	scanner   sigs.Signer
	devices   []device
	enrollDay time.Time
}

// Stable IDs of the external checks, in the order the scanner runs them.
var scanChecks = []posture.ScanCheck{"EMAIL-01", "EMAIL-02", "EMAIL-03", "EMAIL-04", "EMAIL-05", "TLS-01", "TLS-02", "TLS-03",
	"HTTP-01", "HTTP-02", "HTTP-03", "DNS-01", "BREACH-01", "BREACH-02"}

type chain struct {
	seq  uint32
	prev posture.Digest
	envs map[uint32]*dsse.Envelope
}

// World is one simulated October.
type World struct {
	Variant     Variant
	Keys        *Keys
	Server      *tlog.Server
	Witnesses   []*witness.Witness
	Trust       *pack.TrustPolicy
	Checkpoints map[string]string // date -> cosigned 23:50 checkpoint
	TenantID    string
	NameSalt    string
	TamperIndex uint64 // log index of laptop D07's Oct 14 report (genuine world)

	ctx    context.Context
	now    time.Time
	firms  []*firm
	chains map[string]*chain
}

func (w *World) clock() time.Time { return w.now }

// Build simulates the world.
func Build(ctx context.Context, k *Keys, v Variant) (*World, error) {
	w := &World{ctx: ctx, Variant: v, Keys: k, Checkpoints: map[string]string{}, chains: map[string]*chain{}}
	lg, err := tlog.NewLog(brand.DemoLogOrigin, mustEd25519(k.Log), w.clock)
	if err != nil {
		return nil, err
	}
	var tsas []tsa.Authority
	var tsaParties []pack.Party
	tsaLabels := []string{
		"Simulated TSA A (stands in for a commercial RFC 3161 timestamp authority)",
		"Simulated TSA B (stands in for Sigstore's open-source timestamp-authority)",
	}
	for i, kf := range k.TSAs {
		name := fmt.Sprintf("tsa-%c.example", 'a'+i)
		offset := time.Duration(i+1) * time.Second
		a, err := tsa.NewSimulated(name, mustSigner(kf), func() time.Time { return w.now.Add(offset) }, 0)
		if err != nil {
			return nil, err
		}
		tsas = append(tsas, a)
		tsaParties = append(tsaParties, pack.Party{Name: name, Kind: tsa.KindSimulated, PublicKey: mustSigner(kf).Public().Base64(), Label: tsaLabels[i], Simulated: true})
	}
	w.Server = tlog.NewServer(lg, tsas, w.clock, nil)
	w.Server.NonceSource = func(subject string, at time.Time) posture.Nonce {
		var n posture.Nonce
		b := det("nonce", subject, at.Format(time.RFC3339))
		copy(n[:], b[:])
		return n
	}
	var wParties []pack.Party
	for i, kf := range k.Witnesses {
		wt, err := witness.New(fmt.Sprintf("witness-%c.example", 'a'+i), mustEd25519(kf), w.clock)
		if err != nil {
			return nil, err
		}
		w.Witnesses = append(w.Witnesses, wt)
		wParties = append(wParties, pack.Party{Name: wt.Name, VKey: wt.VKey(), Label: fmt.Sprintf(witnessLabelFm, 'A'+i), Simulated: true})
	}
	if w.Trust, err = pack.NewTrustPolicy(lg.Origin(), lg.VKey(), wParties, 2, tsaParties, true); err != nil {
		return nil, err
	}
	w.setupFirms()
	w.TenantID = posture.TenantID(w.firms[0].tenant.Public())
	salt := det("display-name-salt")
	w.NameSalt = hex.EncodeToString(salt[:])
	return w, w.run()
}

func (w *World) setupFirms() {
	enroll := []time.Time{
		time.Date(2026, 9, 29, 15, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 22, 15, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 25, 15, 0, 0, 0, time.UTC),
	}
	names := []string{FirmName, "another firm sharing the log (hidden)", "a third firm sharing the log (hidden)"}
	for i, fk := range w.Keys.Firms {
		f := &firm{idx: i, name: names[i], tenant: mustSigner(fk.Tenant), connector: mustSigner(fk.Connector),
			staff: mustSigner(fk.Staff), scanner: mustSigner(w.Keys.Scanner), enrollDay: enroll[i]}
		for j, dk := range fk.Devices {
			d := device{signer: mustSigner(dk), number: j + 1, class: "laptop", plat: "windows", idle: 10, admins: 1}
			if i == 0 {
				switch {
				case j+1 == 9:
					d.plat = "macos"
				case j+1 == 10 || j+1 == 11:
					d.class, d.idle = "desktop", 15
				case j+1 == 12:
					d.class, d.idle, d.admins = "server", 5, 2
				}
			}
			f.devices = append(f.devices, d)
		}
		w.firms = append(w.firms, f)
	}
}

type event struct {
	at    time.Time
	order int
	run   func() error
}

func (w *World) run() error {
	var evs []event
	add := func(at time.Time, f func() error) {
		evs = append(evs, event{at: at, order: len(evs), run: f})
	}
	for _, f := range w.firms {
		f := f
		w.planEnrollment(f, add)
		w.planReports(f, add)
	}
	w.planStaffEvents(w.firms[0], add)
	for d := firstCPDay; !d.After(day0.AddDate(0, 0, 29)); d = d.AddDate(0, 0, 1) {
		at := d.Add(23*time.Hour + 50*time.Minute)
		add(at, func() error { return w.checkpoint(at) })
	}
	add(finalCPAt, func() error { return w.checkpoint(finalCPAt) })
	sort.SliceStable(evs, func(i, j int) bool {
		if !evs[i].at.Equal(evs[j].at) {
			return evs[i].at.Before(evs[j].at)
		}
		return evs[i].order < evs[j].order
	})
	for _, e := range evs {
		if err := e.run(); err != nil {
			return fmt.Errorf("event at %s: %w", e.at.Format(time.RFC3339), err)
		}
	}
	return nil
}

func (w *World) salt(subject string, at time.Time, seq uint32) posture.Salt {
	return posture.Salt(det("salt", subject, at.Format(time.RFC3339), fmt.Sprint(seq)))
}

func (w *World) planEnrollment(f *firm, add func(time.Time, func() error)) {
	t0 := f.enrollDay
	add(t0, func() error {
		key := f.tenant.Public()
		subject := posture.TenantID(key)
		saltHex := w.NameSalt
		if f.idx != 0 {
			s := det("other-name-salt", fmt.Sprint(f.idx))
			saltHex = hex.EncodeToString(s[:])
		}
		w.now = t0.Add(-40 * time.Second)
		nonce, err := w.Server.IssueNonce(subject)
		if err != nil {
			return err
		}
		payload, err := posture.BuildTenantGenesis(key, pack.NameCommitment(f.name, saltHex), t0, nonce, w.salt(subject, t0, 0))
		if err != nil {
			return err
		}
		env, err := posture.Sign(payload, f.tenant)
		if err != nil {
			return err
		}
		w.now = t0.Add(10 * time.Second)
		_, err = w.Server.Submit(w.ctx, env)
		return err
	})
	enrollAttester := func(at time.Time, signer sigs.Signer, info posture.EnrollmentInfo) {
		add(at, func() error {
			subject := posture.AttesterID(info.Kind, signer.Public())
			w.now = at.Add(-40 * time.Second)
			nonce, err := w.Server.IssueNonce(subject)
			if err != nil {
				return err
			}
			payload, err := posture.BuildAttesterEnrollment(f.tenant.Public(), signer.Public(), info, at, nonce, w.salt(subject, at, 0))
			if err != nil {
				return err
			}
			env, err := posture.Sign(payload, f.tenant, signer)
			if err != nil {
				return err
			}
			w.now = at.Add(10 * time.Second)
			if _, err := w.Server.Submit(w.ctx, env); err != nil {
				return err
			}
			w.chains[posture.TenantID(f.tenant.Public())+"/"+subject] = &chain{prev: posture.PayloadDigest(payload), envs: map[uint32]*dsse.Envelope{}}
			return nil
		})
	}
	enrollAttester(t0.Add(12*time.Minute), f.connector, posture.EnrollmentInfo{
		Kind: posture.CloudConnector, KeyProtection: "software", KeyAttestation: "none", Method: "owner_approval",
		DeviceClass: "not_a_device", Platform: "microsoft_365", StaffRole: "none"})
	enrollAttester(t0.Add(15*time.Minute), f.scanner, posture.EnrollmentInfo{
		Kind: posture.ExternalScanner, KeyProtection: "software", KeyAttestation: "none", Method: "owner_approval",
		DeviceClass: "not_a_device", Platform: "vendor_service", StaffRole: "none"})
	for j, d := range f.devices {
		at := t0.Add(time.Hour + time.Duration(j*9)*time.Minute)
		if j >= 8 { // the last few are enrolled the next morning
			at = t0.Add(22*time.Hour + time.Duration((j-8)*9)*time.Minute)
		}
		enrollAttester(at, d.signer, posture.EnrollmentInfo{
			Kind: posture.DeviceAgent, KeyProtection: "software", KeyAttestation: "none", Method: "enrollment_code",
			DeviceClass: d.class, Platform: d.plat, DeviceNumber: uint16(d.number), StaffRole: "none"})
	}
	enrollAttester(t0.Add(23*time.Hour+30*time.Minute), f.staff, posture.EnrollmentInfo{
		Kind: posture.StaffAttester, KeyProtection: "software", KeyAttestation: "none", Method: "owner_approval",
		DeviceClass: "not_a_device", Platform: "mobile_app", StaffRole: "office_manager"})
}

// report makes, signs and submits one posture statement. observed is the
// time the attester claims; submit is when the server receives it.
func (w *World) report(f *firm, signer sigs.Signer, kind posture.AttesterKind, observed, submit time.Time, unchecked bool,
	build func(posture.Header) ([]byte, error)) (*tlog.Evidence, error) {
	subject := posture.AttesterID(kind, signer.Public())
	c := w.chains[posture.TenantID(f.tenant.Public())+"/"+subject]
	w.now = submit.Add(-40 * time.Second)
	nonce, err := w.Server.IssueNonce(subject)
	if err != nil {
		return nil, err
	}
	h := posture.Header{TenantKey: f.tenant.Public(), Attester: signer.Public(), Kind: kind, Seq: c.seq + 1,
		Prev: c.prev, Nonce: nonce, Salt: w.salt(subject, observed, c.seq+1), ObservedAt: observed}
	payload, err := build(h)
	if err != nil {
		return nil, err
	}
	env, err := posture.Sign(payload, signer)
	if err != nil {
		return nil, err
	}
	w.now = submit
	var ev *tlog.Evidence
	if unchecked {
		ev, err = w.Server.AppendWithoutChecks(w.ctx, env)
	} else {
		ev, err = w.Server.Submit(w.ctx, env)
	}
	if err != nil {
		return nil, err
	}
	c.seq++
	c.prev = posture.PayloadDigest(payload)
	c.envs[c.seq] = env
	return ev, nil
}

func (w *World) planReports(f *firm, add func(time.Time, func() error)) {
	first := f.enrollDay.AddDate(0, 0, 1)
	first = time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.UTC)
	if f.idx == 0 {
		first = day0
	}
	for d := first; !d.After(day0.AddDate(0, 0, 29)); d = d.AddDate(0, 0, 1) {
		d := d
		ds := d.Format(pack.DateLayout)
		// The vendor's scanner checks the firm's domain from outside overnight.
		st := d.Add(6*time.Hour + time.Duration(f.idx*7)*time.Minute + time.Duration(detInt(240, "scan", fmt.Sprint(f.idx), ds))*time.Second)
		add(st, func() error {
			_, err := w.report(f, f.scanner, posture.ExternalScanner, st, st.Add(10*time.Second), false, func(h posture.Header) ([]byte, error) {
				return posture.BuildScan(h, w.scanResults(f, d))
			})
			return err
		})
		// The cloud connector reads Microsoft 365 around noon.
		ct := d.Add(12*time.Hour + time.Duration(detInt(300, "conn", fmt.Sprint(f.idx), ds))*time.Second)
		if f.idx != 0 {
			ct = ct.Add(-30 * time.Minute)
		}
		add(ct, func() error {
			_, err := w.report(f, f.connector, posture.CloudConnector, ct, ct.Add(10*time.Second), false, func(h posture.Header) ([]byte, error) {
				return posture.BuildTenantPosture(h, w.tenantPosture(f, d))
			})
			return err
		})
		for _, dev := range f.devices {
			dev := dev
			base := 13*time.Hour + time.Duration(dev.number*13)*time.Minute
			if f.idx != 0 {
				base = 14*time.Hour + time.Duration(dev.number*17)*time.Minute
			}
			at := d.Add(base + time.Duration(detInt(540, "dev", fmt.Sprint(f.idx), fmt.Sprint(dev.number), ds))*time.Second)
			if f.idx == 0 && dev.number == GapDevice {
				w.planGapDevice(f, dev, d, at, add)
				continue
			}
			add(at, func() error {
				_, err := w.report(f, dev.signer, posture.DeviceAgent, at, at.Add(10*time.Second), false, func(h posture.Header) ([]byte, error) {
					return posture.BuildDevice(h, w.deviceChecks(f, dev, d))
				})
				return err
			})
		}
	}
}

// planGapDevice scripts laptop D07: silent on Oct 12-13, back on Oct 14
// with Defender stopped and BitLocker off (a missed check-in raises an alert), fixed
// by Oct 15. The attack variants change only what happens on Oct 14.
func (w *World) planGapDevice(f *firm, dev device, d, at time.Time, add func(time.Time, func() error)) {
	if !d.Before(gapStart) && d.Before(tamperDay) {
		return // silent: no reports at all
	}
	if !d.Equal(tamperDay) {
		add(at, func() error {
			_, err := w.report(f, dev.signer, posture.DeviceAgent, at, at.Add(10*time.Second), false, func(h posture.Header) ([]byte, error) {
				return posture.BuildDevice(h, w.deviceChecks(f, dev, d))
			})
			return err
		})
		return
	}
	back := tamperDay.Add(14*time.Hour + 5*time.Minute + 12*time.Second)
	switch w.Variant {
	case Backdate:
		// Before its real report, the laptop forges green reports dated
		// Oct 12 and Oct 13 and pushes them past a bypassed ingest server.
		for i, fake := range []time.Time{
			gapStart.Add(14*time.Hour + 3*time.Minute + 17*time.Second),
			gapStart.AddDate(0, 0, 1).Add(14*time.Hour + 4*time.Minute + 2*time.Second),
		} {
			fake, submit := fake, tamperDay.Add(13*time.Hour+58*time.Minute+time.Duration(i*65)*time.Second)
			add(submit, func() error {
				_, err := w.report(f, dev.signer, posture.DeviceAgent, fake, submit, true, func(h posture.Header) ([]byte, error) {
					return posture.BuildDevice(h, w.deviceChecks(f, dev, d.AddDate(0, 0, 1))) // all green
				})
				return err
			})
		}
	case Replay:
		// The agent is blocked; instead an attacker re-sends the laptop's
		// all-green report from Oct 4 to keep the alarm quiet.
		add(back, func() error {
			w.now = back.Add(10 * time.Second)
			c := w.chains[posture.TenantID(f.tenant.Public())+"/"+posture.AttesterID(posture.DeviceAgent, dev.signer.Public())]
			_, err := w.Server.AppendWithoutChecks(w.ctx, c.envs[4])
			return err
		})
		return
	}
	add(back, func() error {
		ev, err := w.report(f, dev.signer, posture.DeviceAgent, back, back.Add(10*time.Second), false, func(h posture.Header) ([]byte, error) {
			return posture.BuildDevice(h, w.deviceChecks(f, dev, d))
		})
		if err == nil {
			w.TamperIndex = ev.Index
		}
		return err
	})
}

func (w *World) deviceChecks(f *firm, dev device, d time.Time) posture.DeviceChecks {
	c := posture.DeviceChecks{
		DiskEncryption: posture.EncryptionOn, OSPatch: posture.PatchCurrent, FirewallOn: true, ScreenLockOn: true,
		ScreenLockMaxIdleMin: dev.idle, EDRRunning: true, EDRKind: posture.EDRDefender, LocalAdminCount: dev.admins,
		HeartbeatIntervalS: 300, Heartbeats24h: uint16(286 + detInt(3, "hb", fmt.Sprint(f.idx), fmt.Sprint(dev.number), d.Format(pack.DateLayout))),
	}
	if f.idx != 0 {
		return c
	}
	ds := d.Format(pack.DateLayout)
	switch {
	case dev.number == 4 && (ds == "2026-10-08" || ds == "2026-10-09"):
		c.OSPatch = posture.PatchPending // a routine update waiting for a reboot
	case dev.number == GapDevice && d.Equal(tamperDay):
		// Back after two silent days: Defender stopped, BitLocker off.
		c.DiskEncryption, c.EDRRunning, c.OSPatch, c.Heartbeats24h = posture.EncryptionOff, false, posture.PatchPending, 7
	case dev.number == GapDevice && d.Equal(tamperDay.AddDate(0, 0, 1)):
		c.Heartbeats24h = 288
	}
	return c
}

// scanResults: every external check passes, except that the sample firm's
// DMARC policy is only "monitor" (p=none) until it is enforced on Oct 18.
func (w *World) scanResults(f *firm, d time.Time) posture.ScanResults {
	var r posture.ScanResults
	for _, c := range scanChecks {
		res := posture.ScanResult{CheckID: c, Status: "pass", Severity: "info"}
		if f.idx == 0 && c == "EMAIL-04" && d.Format(pack.DateLayout) < "2026-10-18" {
			res.Status, res.Severity = "warn", "medium"
		}
		r.Results = append(r.Results, res)
	}
	return r
}

func (w *World) tenantPosture(f *firm, d time.Time) posture.TenantPosture {
	n := uint32(len(f.devices))
	t := posture.TenantPosture{AccountsTotal: n - 1, AccountsMFA: n - 1, AccountsPasskey: n - 1, AdminAccounts: 1,
		DevicesKnown: n, DevicesEnrolled: n}
	if f.idx != 0 {
		return t
	}
	t.AccountsTotal, t.AccountsMFA, t.AdminAccounts = 11, 11, 2
	switch ds := d.Format(pack.DateLayout); {
	case ds < "2026-10-15":
		t.AccountsPasskey = 2
	case ds == "2026-10-15":
		t.AccountsPasskey = 4
	default:
		t.AccountsPasskey = 6
	}
	switch d.Format(pack.DateLayout) {
	case "2026-10-21": // a new inbox rule forwarding mail outside the firm
		t.MailboxAlerts24h = []posture.Count[posture.MailboxAlert]{{Kind: "forwarding_rule_external", N: 1}}
		t.MailboxAlertsOpen = 1
	case "2026-10-22":
		t.MailboxAlertsResolved24h = 1
	}
	return t
}

func (w *World) planStaffEvents(f *firm, add func(time.Time, func() error)) {
	vbp := func(at time.Time, v posture.VerifyBeforePay) {
		add(at, func() error {
			_, err := w.report(f, f.staff, posture.StaffAttester, at, at.Add(10*time.Second), false, func(h posture.Header) ([]byte, error) {
				return posture.BuildStaffEvent(h, posture.StaffEvent{VerifyBeforePay: &v})
			})
			return err
		})
	}
	vbp(time.Date(2026, 10, 7, 14, 20, 0, 0, time.UTC), posture.VerifyBeforePay{Requests: 1, CallbackVerified: 1, SecondApprover: 1,
		RequestKinds: []posture.Count[posture.PaymentRequest]{{Kind: "bank_detail_change", N: 1}}})
	drillAt := time.Date(2026, 10, 9, 19, 30, 0, 0, time.UTC)
	add(drillAt, func() error {
		_, err := w.report(f, f.staff, posture.StaffAttester, drillAt, drillAt.Add(10*time.Second), false, func(h posture.Header) ([]byte, error) {
			return posture.BuildStaffEvent(h, posture.StaffEvent{RestoreDrill: &posture.RestoreDrill{
				PerformedAt: drillAt.Add(-25 * time.Minute), Result: posture.DrillSuccess, FilesRestored: 25,
				MinutesToRestore: 18, SecondPersonVerified: true}})
		})
		return err
	})
	vbp(time.Date(2026, 10, 16, 15, 45, 0, 0, time.UTC), posture.VerifyBeforePay{Requests: 1, CallbackVerified: 1, SecondApprover: 1,
		RequestKinds: []posture.Count[posture.PaymentRequest]{{Kind: "refund_redirect", N: 1}}})
	vbp(time.Date(2026, 10, 23, 20, 10, 0, 0, time.UTC), posture.VerifyBeforePay{Requests: 2, CallbackVerified: 2, SecondApprover: 2, Blocked: 1,
		RequestKinds: []posture.Count[posture.PaymentRequest]{{Kind: "bank_detail_change", N: 1}, {Kind: "wire_transfer", N: 1}}})
}

func (w *World) checkpoint(at time.Time) error {
	w.now = at
	signed, err := w.Server.Log.SignCheckpoint()
	if err != nil {
		return err
	}
	for i, wt := range w.Witnesses {
		w.now = at.Add(time.Duration(60+35*i) * time.Second)
		var proof []merkle.Hash
		if seen, ok := wt.Seen[w.Server.Log.Origin()]; ok {
			if proof, err = w.Server.Log.ConsistencyProof(seen.Size, w.Server.Log.Size()); err != nil {
				return err
			}
		}
		line, err := wt.Cosign(signed, w.Server.Log.VKey(), proof)
		if err != nil {
			return err
		}
		w.Server.Log.AddCosignature(line)
	}
	w.Checkpoints[at.Format(pack.DateLayout)] = w.Server.Log.Latest()
	return nil
}

// Pack builds the sample firm's Proof Pack for October 1-30 from this
// world, with the checkpoint the firm's app saved on Oct 20.
func (w *World) Pack() (*pack.Pack, error) {
	return pack.Build(pack.ServerSource{S: w.Server}, w.Trust, w.request())
}

func (w *World) request() pack.Request {
	return pack.Request{TenantID: w.TenantID, DisplayName: FirmName, DisplayNameSalt: w.NameSalt,
		From: RangeFrom, To: RangeTo, IssuedAt: IssuedAt, Sample: true, Earlier: []string{w.Checkpoints[savedCPDate]}}
}

// VendorRewrite simulates the log operator (us) deleting laptop D07's bad
// Oct 14 report from the log, rebuilding the tree and re-signing with the
// real log key. The witnesses, which saw the honest log, refuse to cosign,
// so the operator copies their old cosignatures across in the hope nobody
// checks. Returns the rewritten server and its pack.
func (w *World) VendorRewrite() (*tlog.Server, *pack.Pack, error) {
	if w.Variant != Genuine {
		return nil, nil, fmt.Errorf("vendor rewrite starts from the genuine world")
	}
	lg, err := tlog.NewLog(w.Server.Log.Origin(), mustEd25519(w.Keys.Log), w.clock)
	if err != nil {
		return nil, nil, err
	}
	fork := tlog.NewServer(lg, nil, w.clock, nil)
	for _, ev := range w.Server.Evidence() {
		if ev.Index == w.TamperIndex {
			continue
		}
		if _, err := fork.Import(ev); err != nil {
			return nil, nil, err
		}
	}
	w.now = finalCPAt
	signed, err := lg.SignCheckpoint()
	if err != nil {
		return nil, nil, err
	}
	for _, wt := range w.Witnesses {
		seen := wt.Seen[lg.Origin()]
		proof, _ := lg.ConsistencyProof(min(seen.Size, lg.Size()), lg.Size())
		if _, err := wt.Cosign(signed, lg.VKey(), proof); err == nil {
			return nil, nil, fmt.Errorf("witness %s cosigned a rewritten log", wt.Name)
		}
	}
	genuine, err := noteSigLines(w.Server.Log.Latest())
	if err != nil {
		return nil, nil, err
	}
	for _, l := range genuine[1:] { // copy the witness lines, not the log's own
		lg.AddCosignature(l)
	}
	p, err := pack.Build(pack.ServerSource{S: fork}, w.Trust, w.request())
	return fork, p, err
}
