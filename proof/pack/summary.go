package pack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The summary is the owner-facing claim a pack makes: coverage, every gap
// (a day an enrolled device or service sent no valid report) and every
// lapse (a report showing a protection off). The verifier recomputes it
// from the evidence alone and requires an exact match, so a pack cannot
// hide a bad day in its summary. Only evidence that passed the signature,
// content, enrollment, timestamp and inclusion checks counts.

type gap struct {
	Attester string
	Kind     string
	Number   int64
	From, To time.Time
	Days     int
}

func (g gap) value() map[string]any {
	return map[string]any{
		"attester": g.Attester, "attester_kind": g.Kind, "device_number": g.Number,
		"from": g.From.Format(DateLayout), "to": g.To.Format(DateLayout), "days": int64(g.Days),
	}
}

// LapseChecks lists the protection checks that count as lapses, keyed by
// the check ID used in summaries.
func lapseChecks(it *item) []string {
	st := it.st
	var out []string
	switch st.Str("attester_kind") {
	case "device_agent":
		if st.Str("device.disk_encryption") != "on" {
			out = append(out, "disk_encryption")
		}
		if !st.Bool("device.edr_running") {
			out = append(out, "edr_running")
		}
		if !st.Bool("device.firewall_on") {
			out = append(out, "firewall")
		}
		if p := st.Str("device.os_patch_status"); p == "out_of_date" || p == "unsupported_os" {
			out = append(out, "os_patch")
		}
		if st.Int("device.unapproved_remote_tools.total") > 0 {
			out = append(out, "remote_tools")
		}
		if !st.Bool("device.screen_lock_on") {
			out = append(out, "screen_lock")
		}
	case "cloud_connector":
		if st.Int("tenant_posture.devices_enrolled") < st.Int("tenant_posture.devices_known") {
			out = append(out, "devices_not_enrolled")
		}
		if st.Int("tenant_posture.mailbox_alerts_open") > 0 {
			out = append(out, "mailbox_alert_open")
		}
		if st.Int("tenant_posture.accounts_mfa") < st.Int("tenant_posture.accounts_total") {
			out = append(out, "mfa")
		}
		if st.Int("tenant_posture.devices_unknown_seen") > 0 {
			out = append(out, "unknown_device")
		}
	case "external_scanner":
		items, _ := st.Get("scan.results.items").([]any)
		for _, it := range items {
			if r, _ := it.(map[string]any); r["status"] == "fail" {
				out = append(out, "external_check_failed")
				break
			}
		}
	case "staff_attester":
		if st.Str("staff_event.kind") == "verify_before_pay" &&
			st.Int("staff_event.verify_before_pay.callback_verified") < st.Int("staff_event.verify_before_pay.requests") {
			out = append(out, "payment_not_verified")
		}
		if st.Str("staff_event.kind") == "backup_restore_drill" && st.Str("staff_event.backup_restore_drill.result") != "success" {
			out = append(out, "restore_drill_failed")
		}
	}
	sort.Strings(out)
	return out
}

// expectedDaily are the attester kinds that must report every day; a day
// without a valid report from one of them is a gap.
var expectedDaily = map[string]bool{"device_agent": true, "cloud_connector": true, "external_scanner": true}

func dateOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func summarize(p *Pack, items []*item, attesters map[string]*attester) (map[string]any, []gap) {
	from, _ := time.Parse(DateLayout, p.From)
	to, _ := time.Parse(DateLayout, p.To)
	var evidence []*item
	for _, it := range items {
		if it.posture() && it.sigOK && it.enrolOK && it.tsOK && it.inclOK {
			d := dateOf(it.st.Time("observed_at"))
			if !d.Before(from) && !d.After(to) {
				evidence = append(evidence, it)
			}
		}
	}
	sort.SliceStable(evidence, func(i, j int) bool {
		a, b := evidence[i].st, evidence[j].st
		if !a.Time("observed_at").Equal(b.Time("observed_at")) {
			return a.Time("observed_at").Before(b.Time("observed_at"))
		}
		if a.Str("attester") != b.Str("attester") {
			return a.Str("attester") < b.Str("attester")
		}
		return a.Int("seq") < b.Int("seq")
	})

	coverage := map[string]any{
		"connector_reports": int64(0), "devices_known": int64(0), "devices_enrolled": int64(0),
		"devices_unknown_seen": int64(0), "accounts_total": int64(0), "accounts_mfa": int64(0),
		"accounts_passkey": int64(0), "device_enrollments": int64(0),
	}
	covered := map[string]map[time.Time]bool{}
	lapses := []any{}
	for _, it := range evidence {
		id := it.st.Str("attester")
		if covered[id] == nil {
			covered[id] = map[time.Time]bool{}
		}
		covered[id][dateOf(it.st.Time("observed_at"))] = true
		if it.st.Str("attester_kind") == "cloud_connector" {
			coverage["connector_reports"] = coverage["connector_reports"].(int64) + 1
			for _, k := range []string{"devices_known", "devices_enrolled", "devices_unknown_seen", "accounts_total", "accounts_mfa", "accounts_passkey"} {
				coverage[k] = it.st.Int("tenant_posture." + k) // latest wins (sorted by time)
			}
		}
		if checks := lapseChecks(it); len(checks) > 0 {
			cs := make([]any, len(checks))
			for i, c := range checks {
				cs[i] = c
			}
			lapses = append(lapses, map[string]any{
				"attester": id, "date": dateOf(it.st.Time("observed_at")).Format(DateLayout),
				"seq": it.st.Int("seq"), "checks": cs,
			})
		}
	}

	var list []*attester
	for _, a := range attesters {
		if a.it.enrolOK && a.it.sigOK && a.it.tsOK && a.it.inclOK && expectedDaily[a.kind] {
			list = append(list, a)
		}
		if a.kind == "device_agent" && a.it.enrolOK {
			coverage["device_enrollments"] = coverage["device_enrollments"].(int64) + 1
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].number != list[j].number {
			return list[i].number < list[j].number
		}
		return list[i].id < list[j].id
	})
	var gaps []gap
	for _, a := range list {
		start := dateOf(a.it.st.Time("enrolled_at")).AddDate(0, 0, 1)
		if start.Before(from) {
			start = from
		}
		var run *gap
		for d := start; !d.After(to); d = d.AddDate(0, 0, 1) {
			if covered[a.id][d] {
				run = nil
				continue
			}
			if run == nil {
				gaps = append(gaps, gap{Attester: a.id, Kind: a.kind, Number: a.number, From: d, To: d, Days: 1})
				run = &gaps[len(gaps)-1]
			} else {
				run.To, run.Days = d, run.Days+1
			}
		}
	}
	gv := []any{}
	for _, g := range gaps {
		gv = append(gv, g.value())
	}
	return map[string]any{"coverage": coverage, "gaps": gv, "lapses": lapses}, gaps
}

func verifySummary(s *Step, p *Pack, r *Report) {
	s.Checked = 1
	want := Canonical(r.Computed)
	got := Canonical(p.Summary)
	if got == nil || !bytes.Equal(got, want) {
		s.Status = Fail
		claimed, _ := p.Summary.(map[string]any)
		s.Problems = append(s.Problems, r.diffSummary(claimed)...)
		if len(s.Problems) == 0 {
			s.Problems = append(s.Problems, "The pack's summary does not match what the evidence shows")
		}
		s.Detail = "The summary on this pack does not match the signed evidence"
		return
	}
	if len(r.gaps) == 0 {
		s.Detail = "No gaps: every enrolled device and service reported every day, and the summary matches the evidence"
		return
	}
	parts := make([]string, len(r.gaps))
	for i, g := range r.gaps {
		parts[i] = r.gapText(g)
	}
	s.Detail = fmt.Sprintf("%d gap(s) disclosed, matching the evidence: %s", len(r.gaps), strings.Join(parts, "; "))
}

func (r *Report) gapText(g gap) string {
	span := g.From.Format("Jan 2")
	if g.Days > 1 {
		span += " to " + g.To.Format("Jan 2")
	}
	return fmt.Sprintf("%s sent no reports %s (%d day%s)", r.attesterName(g.Attester), span, g.Days, plural(g.Days))
}

func (r *Report) diffSummary(claimed map[string]any) []string {
	var out []string
	key := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	set := func(v any) map[string]map[string]any {
		m := map[string]map[string]any{}
		arr, _ := v.([]any)
		for _, e := range arr {
			if o, ok := e.(map[string]any); ok {
				m[key(o)] = o
			}
		}
		return m
	}
	describeGap := func(o map[string]any) string {
		days, _ := o["days"].(int64)
		f, _ := time.Parse(DateLayout, fmt.Sprint(o["from"]))
		t, _ := time.Parse(DateLayout, fmt.Sprint(o["to"]))
		id, _ := o["attester"].(string)
		return r.gapText(gap{Attester: id, From: f, To: t, Days: int(days)})
	}
	describeLapse := func(o map[string]any) string {
		id, _ := o["attester"].(string)
		d, _ := time.Parse(DateLayout, fmt.Sprint(o["date"]))
		var checks []string
		arr, _ := o["checks"].([]any)
		for _, c := range arr {
			checks = append(checks, CheckLabel(fmt.Sprint(c)))
		}
		return fmt.Sprintf("%s on %s: %s", r.attesterName(id), d.Format("Jan 2"), strings.Join(checks, ", "))
	}
	ev, cl := set(r.Computed["gaps"]), set(claimed["gaps"])
	for k, o := range ev {
		if cl[k] == nil {
			out = append(out, "The summary hides a gap the evidence shows: "+describeGap(o))
		}
	}
	for k, o := range cl {
		if ev[k] == nil {
			out = append(out, "The summary claims a gap the evidence does not show: "+describeGap(o))
		}
	}
	ev, cl = set(r.Computed["lapses"]), set(claimed["lapses"])
	for k, o := range ev {
		if cl[k] == nil {
			out = append(out, "The summary hides a lapse the evidence shows: "+describeLapse(o))
		}
	}
	for k, o := range cl {
		if ev[k] == nil {
			out = append(out, "The summary claims a lapse the evidence does not show: "+describeLapse(o))
		}
	}
	if key(r.Computed["coverage"]) != key(claimed["coverage"]) {
		out = append(out, "The summary's coverage numbers differ from the evidence")
	}
	sort.Strings(out)
	return out
}

// CheckLabel is the plain-English name of a lapse check.
func CheckLabel(id string) string {
	switch id {
	case "disk_encryption":
		return "disk encryption off"
	case "edr_running":
		return "antivirus/EDR not running"
	case "firewall":
		return "firewall off"
	case "os_patch":
		return "operating system out of date"
	case "remote_tools":
		return "unapproved remote-control tool"
	case "screen_lock":
		return "screen lock off"
	case "devices_not_enrolled":
		return "known devices not enrolled"
	case "mailbox_alert_open":
		return "mailbox-takeover alert open"
	case "mfa":
		return "accounts without MFA"
	case "unknown_device":
		return "unknown device seen"
	case "payment_not_verified":
		return "payment request not called back"
	case "restore_drill_failed":
		return "restore drill failed"
	case "external_check_failed":
		return "an external check failed"
	}
	return id
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func attesterLabel(a *attester) string {
	switch a.kind {
	case "device_agent":
		class := map[string]string{"laptop": "Laptop", "desktop": "Desktop", "server": "Server"}[a.class]
		if class == "" {
			class = "Device"
		}
		return fmt.Sprintf("%s D%02d", class, a.number)
	case "cloud_connector":
		return "Microsoft 365 connector"
	case "external_scanner":
		return "External scan"
	case "staff_attester":
		role := map[string]string{"owner": "Owner", "office_manager": "Office manager", "bookkeeper": "Bookkeeper"}[a.role]
		if role == "" {
			role = "Staff"
		}
		return role + " (staff attestation)"
	}
	return a.id
}

func (r *Report) attesterName(id string) string {
	if l, ok := r.labels[id]; ok {
		return l
	}
	return id
}

func (r *Report) itemLabel(it *item) string {
	if it.st == nil {
		return fmt.Sprintf("Log entry %d", it.index())
	}
	switch {
	case it.st.IsPosture():
		return fmt.Sprintf("%s report #%d (%s)", r.attesterName(it.st.Str("attester")), it.st.Int("seq"), it.st.Time("observed_at").Format("Jan 2"))
	case it.kind() == "tenant_genesis":
		return "The firm's enrollment record"
	default:
		return "Enrollment of " + r.attesterName(it.st.Str("attester"))
	}
}

func fmtTime(t time.Time) string { return t.UTC().Format("Jan 2 15:04 UTC") }

func fmtDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	days := int(d / (24 * time.Hour))
	h := int(d/time.Hour) % 24
	m := int(d/time.Minute) % 60
	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d day%s", days, plural(days)))
	}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%d h", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%d min", m))
	}
	return strings.Join(parts, " ")
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	err := e.Encode(v)
	return buf.Bytes(), err
}
