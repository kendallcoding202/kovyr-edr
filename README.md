# Kovyr EDR

Endpoint protection for small offices that proves it was running.

Ransomware gangs now switch off antivirus and EDR before they strike. On most
products that silence looks the same as "all quiet." Kovyr treats it as the
alarm: every protected computer sends signed check-ins, and a missing or
tampered check-in is flagged off the machine, where an attacker can't hide it.
The same signed record later proves exactly when a computer was protected.

This repository holds the Kovyr endpoint agent. It is built in small steps,
each one useful on its own, toward a full EDR.

## Roadmap

| Stage | What ships | What it is not |
|---|---|---|
| **v0: Protection Alarm** (now) | A read-only Windows agent. It checks that Defender or another antivirus/EDR is running and not tampered with, that disk encryption, firewall and the vulnerable-driver blocklist are on, and it watches each user's Desktop and Documents for the mass renaming that ransomware causes (it reports; it never stops a process or touches a file). It sends signed heartbeats, so a missed or tampered check-in raises an alert. | No remote control, no running commands, no automatic response, no kernel code. |
| **v1: Detection lite** | User-mode detection for the ~30 techniques behind most small-office attacks (Windows event logs, ETW, Sysmon). It sends alerts with a signed record of each detection. macOS agent. | Still no automatic destructive action. |
| **v2: Response** | Opt-in, customer-approved actions: isolate a computer from the network, stop a process, sign a user out of Microsoft 365. Every action is signed into the log. 24/7 coverage through a partner. | No kernel driver. |
| **v3: Full EDR** | Prevention at the deepest level of Windows, after joining the Microsoft Virus Initiative (MVI) and passing independent lab tests. Our own 24/7 team. | |

## How it fits with Kovyr

- **halden** (Kovyr's compliance and monitoring service) receives heartbeats,
  finds gaps, sends the owner's alerts and digest, and keeps the proof log.
  The agent talks to halden over one small, documented API (`docs/api.md`).
- **The proof format** (signed statements, a witnessed log, Proof Packs) is
  shared with halden and the public verifier, so a Proof Pack can be checked
  by anyone without trusting Kovyr.

## Principles

1. **First, do no harm.** The agent must never slow down, break or lock a
   customer's computer. Read-only until v2. No kernel code until v3.
2. **No client data leaves the machine.** Signed statements carry only yes/no
   answers, counts, enums and timestamps.
3. **Silence is a signal.** A computer that stops checking in is reported, not
   ignored.
4. **Prove it.** Every check, detection and action becomes a signed record that
   a third party can verify.

See `CLAUDE.md` for the build rules.
