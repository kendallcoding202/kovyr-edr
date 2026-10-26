package pack

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kendallcoding202/kovyr-edr/proof/brand"
)

// maxListed caps how many problems are printed per step.
const maxListed = 12

// Text renders the report in plain English for people.
func (r *Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: Proof Pack verification\n\n", brand.Product)
	fmt.Fprintf(&b, "  Firm:    %s  [%s]\n", r.DisplayName, r.TenantID)
	fmt.Fprintf(&b, "  Period:  %s to %s\n", r.From, r.To)
	if r.Sample {
		b.WriteString("  SAMPLE DATA: fictional firm, demo keys. This proves nothing about a real business.\n")
	}
	b.WriteString("\n")
	for i, s := range r.Steps {
		mark := map[Status]string{Pass: "[PASS]", Fail: "[FAIL]", Warn: "[WARN]"}[s.Status]
		fmt.Fprintf(&b, "%s %2d. %s\n", mark, i+1, s.Title)
		if s.Detail != "" {
			fmt.Fprintf(&b, "           %s\n", s.Detail)
		}
		for j, p := range s.Problems {
			if j == maxListed {
				fmt.Fprintf(&b, "         - ... and %d more\n", len(s.Problems)-maxListed)
				break
			}
			fmt.Fprintf(&b, "         - %s\n", p)
		}
		for _, n := range s.Notes {
			fmt.Fprintf(&b, "           note: %s\n", n)
		}
	}
	b.WriteString("\n")
	if r.Verified {
		b.WriteString("RESULT: VERIFIED. Every check passed.")
		if len(r.gaps) > 0 {
			fmt.Fprintf(&b, " %d gap(s) disclosed:", len(r.gaps))
			for _, g := range r.gaps {
				fmt.Fprintf(&b, "\n  - %s", r.gapText(g))
			}
		} else {
			b.WriteString(" No gaps.")
		}
		if lost := r.lostTexts(); len(lost) > 0 {
			fmt.Fprintf(&b, "\n%d lost report run(s) disclosed (never reached the log, or left out of this pack):", len(lost))
			for _, l := range lost {
				fmt.Fprintf(&b, "\n  - %s", l)
			}
		}
		b.WriteString("\n")
	} else {
		var failed []string
		for _, s := range r.Steps {
			if s.Status == Fail {
				failed = append(failed, s.Title)
			}
		}
		fmt.Fprintf(&b, "RESULT: NOT VERIFIED. %d check(s) failed: %s.\n", len(failed), strings.Join(failed, "; "))
	}
	if len(r.Simulated) > 0 {
		fmt.Fprintf(&b, "\nSimulated in this prototype: %s.\n", strings.Join(r.Simulated, ", "))
	}
	return b.String()
}

// JSON renders the report for machines (and for comparing verifiers).
func (r *Report) JSON() []byte {
	b, _ := json.MarshalIndent(r, "", "  ")
	return append(b, '\n')
}
