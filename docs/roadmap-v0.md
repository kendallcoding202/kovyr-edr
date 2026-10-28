# v0 Protection Alarm: roadmap

v0 is a read-only Windows agent that reports protection status in signed
heartbeats, so a missed or tampered check-in raises an alert off the
machine. It ships in small tickets, each reviewed before merge.

## Done

### Ticket 1: checks, signed heartbeat, dev receiver, CI (`claude/protection-alarm-v0`)

* Read-only checks behind `checks.Probes`: Windows Security Center, Microsoft
  Defender, known EDR agents, BitLocker on the OS volume, firewall profiles
  (Group Policy first), vulnerable driver blocklist, memory integrity. A
  failed check reports unknown, every check runs under a deadline, and a
  stuck check is never started twice.
* Statements in the proof-spec format (`internal/proof`): in-toto v1 in
  DSSE, ES256 P1363 low-S, the SPEC 6.4 `sensor_health` section plus
  `protection`, a typed builder, and adversarial privacy tests.
* A software device key (DPAPI machine scope on Windows, dev-only file
  elsewhere) behind `proof.Signer`.
* A heartbeat loop: device-bound server nonce, hash chain, a capped on-disk
  queue, backoff with jitter, HTTPS only, no commands.
* `kovyr-receiver-dev`: nonces, verification, chain/replay checks, gaps,
  tamper signals, JSON-lines store.
* CLI: `check`, `keygen`, `enroll --print-pubkey`, `run`.
* CI on Ubuntu and Windows, including the real Windows checks.

### Ticket 2: one shared proof library and the spec decisions (`claude/proof-engine-vendor`)

* The proof engine is vendored under `proof/` (imported as-is from the
  website repo at `3a2773b`, then changed in separate commits); this copy
  and `proof/SPEC.md` are now canonical. The CLI, the website demo
  generator and the Python/JavaScript implementations stay in the website
  repo (`proof/README.md`).
* `internal/proof` uses the vendored canonical JSON, DSSE and ES256 code;
  the hand port is gone. A golden heartbeat pinned before the swap, and the
  shared vectors, prove the bytes did not change.
* SPEC 6.5 standardizes `endpoint/v1` (`protection`, `agent_version`,
  `sensor_health`), says `tenant` and the seq-1 link come with enrollment,
  makes `edr.agents` a capped result list, accepts lost uploads as
  disclosed gaps (ingest, verifier, summary `lost_reports`) and notes
  TPM-clocked offline records as future work. The agent's builder checks
  its output against that schema; the dev receiver shows lost statements in
  status.

### Ticket 3: the Windows service (`claude/windows-service`)

* `kovyr-agent service install|uninstall|start|stop|status` on x/sys
  `svc` and `svc/mgr`: LocalSystem, automatic delayed start, recovery
  (1, 5, 15 minutes; also on error exits), a 3-second clean stop, admin
  and Program Files checks. See `docs/windows-service.md`.
* Back-off behind `internal/sysload` (fakeable): interval x2 and heavy
  checks skipped on battery, heartbeats deferred (never skipped) while the
  processor is busy. SPEC 6.5 gains `schedule`, so receivers judge silence
  against the announced interval.
* A validated settings file with safe defaults, and capped, rotated logs
  (5 x 1 MB) under `%ProgramData%\Kovyr\logs`.
* CI on `windows-latest` measures the resource budget and drives the real
  service: install, start, status, stop, crash recovery, uninstall.

### Ticket 4: the ransomware tripwire (`claude/ransomware-tripwire`)

* `internal/tripwire`: `ReadDirectoryChangesW` on each user's Desktop and
  Documents plus configured data folders (at most 32), one completion
  port, double-buffered. Changes are classified in memory (extension
  change, ransom-note or random name, temporary-file renames excluded) and
  counted in a sliding window; names are never kept. Read-only: no file is
  opened, and nothing is acted on. See `docs/tripwire.md`.
* Conservative, configurable rules (`mass_extension_change`,
  `ransom_notes`), a 10-minute cooldown with a lock-free rate limiter, and
  suppression of known sync and backup engines by their write counts. A
  buffer overflow counts as unknown activity.
* SPEC 6.5 gains a `tripwire` section (state, trigger, reason, window,
  folders, six bucketed counts), instead of the `tamper_detected` flag
  planned earlier, which stays about the sensor itself. A trip sends an
  extra heartbeat at once, never deferred; the dev receiver raises
  `ransomware_suspected` for it.
* CI on `windows-latest` renames a burst of dummy files the test creates
  in a temporary folder and checks that the tripwire statement reaches the
  receiver, and that no statement or log line names a file.

### The halden receiver (next ticket 5, done in the halden repo)

* Production `/v0` endpoints at `https://agent.kovyr.com/api/agent`
  (challenge and heartbeat; a heartbeat is answered `202`, "received,
  verification pending").
* A verifier worker (`agent-verify`, Railway, behind
  `AGENT_VERIFY_ENABLED=1`): signature, schema, nonce, clock and chain
  checks, gaps and alert episodes.
* Owner alert emails (behind `AGENT_ALERTS_ENABLED=1`): possible
  ransomware at once, protection off after two verified statements in a
  row, and a 7am Mountain-time digest of silent computers and other open
  problems.
* An operator enrollment page (`/admin/<orgId>/agents`): paste
  `kovyr-agent enroll --print-pubkey`, revoke and re-activate.
* Not done yet: logging statements to the public proof log, an alert when
  a new key replaces a silent device, and SPEC 6.3 enrollment codes (still
  next ticket 4 here).

### Installer and test kit (`claude/installer-test-kit`)

* `kovyr-protection-alarm-x64.msi`, built on Linux with wixl
  (`installer/`): binary in Program Files, the agent's own `service
  install --create-key --start` as SYSTEM, clean uninstall that keeps the
  device key (`docs/windows-service.md`).
* CI builds it on Ubuntu and installs, checks, uninstalls and reinstalls
  it on `windows-latest`, running the test kit against the installed
  service. windows/arm64 is compiled but not shipped or tested.
* A test kit for trying the alarm on your own PC or VM:
  `docs/testing-on-your-pc.md` and `scripts/test/`.

## Next tickets

In rough order. Each one gets its own branch and review.

1. ~~**Vendor the proof engine.**~~ Done in Ticket 2.
2. ~~**SPEC additions.**~~ Done in Ticket 2 (see `docs/api.md`, "Spec
   decisions").
3. ~~**Windows service install.**~~ Done in Ticket 3.
4. **Enrollment.** Tenant key, SPEC 6.3 attester enrollment records (tenant
   then device signature), single-use expiring enrollment codes,
   `device_number`, and seq 1 linked to the enrollment payload.
5. ~~**halden receiver.**~~ Done in halden (see "The halden receiver" above), except
   logging to the proof log and an alert when a new key replaces a silent
   device.
6. ~~**Tripwire.**~~ Done in Ticket 4, without decoy files (a founder
   decision: see `docs/tripwire.md`).
7. **Signed updater.** Updates are a code-execution channel: signed and
   verified against a pinned key before they run, rolled out in stages, and
   able to roll back. This needs a security review first. Design for that
   review: [`docs/updater-design.md`](updater-design.md).
8. **TPM-backed key.** A key in the Microsoft Platform Crypto Provider behind
   `proof.Signer`, with TPM attestation. It makes the key `tpm2` instead of
   `software`, and "hardware" strength once the attestation is verified.
9. **Patch status (read-only).** Report whether each computer is keeping up
   with Windows updates, so halden can flag a computer that falls behind and
   a Proof Pack can show "every computer patched within 30 days" (the
   insurance question "do you apply critical patches within 30 days?"). The
   agent only **reads**: it never installs, downloads, searches for or
   schedules updates, and never restarts the computer. Installing updates
   stays with a separate tool the firm or its IT provider runs (for example
   Action1 or Microsoft Intune).
   * **Spec first:** add a `patching` section to SPEC 6.5 `endpoint/v1`.
     Integers, booleans, enums and timestamps only (no update titles or KB
     text), like the rest of the statement.
   * **Proposed fields:** `os_build` and `os_ubr` (the Windows build and its
     monthly update revision), `last_quality_update_at` (day precision),
     `reboot_pending`, `auto_update` (`on`, `notify_only`, `off`,
     `managed`, `unknown`) and `update_service` (`running`, `stopped`,
     `disabled`, `unknown`). Any read that fails reports `unknown`.
   * **Read-only sources:** `CurrentBuild` and `UBR` under
     `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`; the local update
     history from the Windows Update Agent (`QueryHistory`, never `Search`,
     which can contact Microsoft); the standard reboot-pending registry keys;
     the Windows Update policy keys; and the state of the update services.
     Run with the heavy checks, at most every few hours.
   * **halden:** no real-time alert. The digest lists a computer more than
     30 days past its last quality update, or more than one monthly release
     behind (halden keeps a small table of current Windows builds, which the
     security watch can keep up to date). The dashboard shows the same.
   * **Proof:** a claim that, over the pack's period, each computer's last
     quality update was never more than N days old, with any gaps disclosed.
   * **Order:** after the Step 3 re-review and the first pilot computer. The
     macOS equivalent comes with the macOS agent (v1).

## Smaller follow-ups found while building part 1

* Confirm the EDR service names marked "unverified" in
  `internal/checks/mapping.go` on real installs.
* Read Intune (MDM) firewall policy, not just Group Policy and local
  settings.
* Read the vulnerable driver blocklist version for
  `sensor_health.driver_blocklist_version`.
* If BitLocker reports `encryption_required` on real machines, query it
  over a packet-privacy WMI connection.

## Follow-ups found in Ticket 4

* Decide on decoy files (they would make the agent create files).
* Find redirected Desktop and Documents (Group Policy, OneDrive Known Folder
  Move) from each user's known-folder settings, and watch new profiles
  without a restart.
* Confirm the sync and backup engine image names marked unverified in
  `internal/tripwire/engines.go`; consider checking the engines' code
  signatures.
* A rule for copy-then-delete encryption (new file with a new extension,
  original deleted).
* Measure false alarms on real office machines (sync clients, photo tools,
  developer folders) before tuning the defaults.
* Let halden treat a tripwire that goes from `ok` to `unknown` as a signal.

## Follow-ups found in Ticket 3

* Measure the footprint on real laptops and desktops with a third-party
  EDR installed; CI runners are Windows Server without one.
* Restrict the service's privileges to what the checks need, after testing
  WMI and BitLocker queries with the reduced set.
* ~~An installer (MSI) that places the binary in Program Files and installs
  the service.~~ Done on `claude/installer-test-kit`.
* A signed "sensor stopping" heartbeat on a clean stop.

## Follow-ups found in Ticket 2

* Port SPEC 6.5 (`endpoint/v1`) and lost-report gaps to the Python server
  and the JavaScript verifier in the website repo, or have halden use the
  Go library. Until then they reject endpoint statements and would fail a
  pack with a lost report.
* Signed delivery receipts (SPEC 18), so a verifier can tell a report that
  never reached the log from one withheld from a pack.
