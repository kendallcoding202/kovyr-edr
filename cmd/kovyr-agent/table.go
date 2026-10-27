package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// row is one line of the `check` table.
type row struct{ name, result, check string }

// describe turns readings into plain English, one row per check, in
// CheckNames order.
func describe(r proof.Readings) map[string]row {
	m := map[string]row{}
	sc := r.SecurityCenter
	switch sc.State {
	case proof.AvailOK:
		m["security_center"] = row{"Windows Security Center", fmt.Sprintf("%d antivirus product(s) registered: %d on, %d up to date", sc.Products, sc.Enabled, sc.UpToDate), ""}
	case proof.AvailNotApplicable:
		m["security_center"] = row{"Windows Security Center", "not applicable (no Security Center, e.g. Windows Server)", ""}
	default:
		m["security_center"] = row{"Windows Security Center", "unknown", ""}
	}
	d := r.Defender
	switch d.State {
	case proof.AvailOK:
		age := "signature age unknown"
		if d.SignatureAgeDays >= 0 {
			age = fmt.Sprintf("signatures %d day(s) old", d.SignatureAgeDays)
		}
		m["defender"] = row{"Microsoft Defender", fmt.Sprintf("mode %s; service %s, antivirus %s, real-time %s, behavior monitoring %s, tamper protection %s; %s",
			d.RunningMode, d.AMService, d.Antivirus, d.RealTime, d.BehaviorMonitor, d.TamperProtection, age), ""}
	case proof.AvailNotApplicable:
		m["defender"] = row{"Microsoft Defender", "not applicable (not installed here)", ""}
	default:
		m["defender"] = row{"Microsoft Defender", "unknown", ""}
	}
	switch r.EDR.State {
	case proof.AvailOK:
		if len(r.EDR.Agents) == 0 {
			m["edr"] = row{"EDR agents", "none of the known agents found", ""}
			break
		}
		var parts []string
		for _, a := range r.EDR.Agents {
			state := "running"
			if !a.Running {
				state = "NOT running"
			}
			parts = append(parts, a.Vendor.String()+" "+state)
		}
		sort.Strings(parts)
		m["edr"] = row{"EDR agents", strings.Join(parts, "; "), ""}
	case proof.AvailNotApplicable:
		m["edr"] = row{"EDR agents", "not applicable", ""}
	default:
		m["edr"] = row{"EDR agents", "unknown", ""}
	}
	bl := map[proof.VolumeProtection]string{proof.VolumeOn: "on", proof.VolumeOff: "OFF",
		proof.VolumeNotApplicable: "not applicable", proof.VolumeUnknown: "unknown (reading it needs administrator rights)"}
	m["bitlocker"] = row{"BitLocker (OS drive)", bl[r.BitLocker], ""}
	fw := "unknown"
	if r.FirewallProfilesOn >= 0 {
		fw = fmt.Sprintf("%d of 3 profiles on (domain, private, public)", r.FirewallProfilesOn)
	}
	m["firewall"] = row{"Windows Firewall", fw, ""}
	db := map[proof.BlocklistState]string{proof.BlocklistOn: "on", proof.BlocklistOff: "OFF",
		proof.BlocklistDefault: "Windows default (on by default since Windows 11 22H2)", proof.BlocklistUnknown: "unknown"}
	m["driver_blocklist"] = row{"Vulnerable driver blocklist", db[r.DriverBlocklist], ""}
	mi := map[proof.Toggle]string{proof.ToggleOn: "on", proof.ToggleOff: "off", proof.ToggleUnknown: "unknown"}
	m["memory_integrity"] = row{"Memory integrity (HVCI)", mi[r.MemoryIntegrity], ""}
	return m
}

func printTable(w io.Writer, r proof.Readings, reports []checks.CheckReport) {
	rows := describe(r)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tRESULT\tHOW IT WENT")
	for _, rep := range reports {
		rw := rows[rep.Name]
		fmt.Fprintf(tw, "%s\t%s\t%s (%v)\n", rw.name, rw.result, rep.Outcome, rep.Duration.Round(time.Millisecond))
	}
	tw.Flush()
}
