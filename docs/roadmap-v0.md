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

## Next tickets

In rough order. Each one gets its own branch and review.

1. ~~**Vendor the proof engine.**~~ Done in Ticket 2.
2. ~~**SPEC additions.**~~ Done in Ticket 2 (see `docs/api.md`, "Spec
   decisions").
3. **Windows service install.** Run as a service (LocalSystem), with an
   install/uninstall command, SCM recovery actions, a clean stop, and logs
   capped in size. Also back off on battery and under load (target under 1%
   CPU and 50 MB RAM).
4. **Enrollment.** Tenant key, SPEC 6.3 attester enrollment records (tenant
   then device signature), single-use expiring enrollment codes,
   `device_number`, and seq 1 linked to the enrollment payload.
5. **halden receiver.** The production `/v0` endpoints, gap alerts by email,
   the owner digest, logging to the proof log, and an alert when a new key
   replaces a silent device.
6. **Tripwire.** Decoy files watched for mass encryption, read-only. Its
   result feeds `sensor_health.tamper_detected` and a new enum.
7. **Signed updater.** Updates are a code-execution channel: signed and
   verified against a pinned key before they run, rolled out in stages, and
   able to roll back. This needs a security review first.
8. **TPM-backed key.** A key in the Microsoft Platform Crypto Provider behind
   `proof.Signer`, with TPM attestation. It makes the key `tpm2` instead of
   `software`, and "hardware" strength once the attestation is verified.

## Smaller follow-ups found while building part 1

* Confirm the EDR service names marked "unverified" in
  `internal/checks/mapping.go` on real installs.
* Read Intune (MDM) firewall policy, not just Group Policy and local
  settings.
* Read the vulnerable driver blocklist version for
  `sensor_health.driver_blocklist_version`.
* If BitLocker reports `encryption_required` on real machines, query it
  over a packet-privacy WMI connection.

## Follow-ups found in Ticket 2

* Port SPEC 6.5 (`endpoint/v1`) and lost-report gaps to the Python server
  and the JavaScript verifier in the website repo, or have halden use the
  Go library. Until then they reject endpoint statements and would fail a
  pack with a lost report.
* Signed delivery receipts (SPEC 18), so a verifier can tell a report that
  never reached the log from one withheld from a pack.
