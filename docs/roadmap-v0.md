# v0 Protection Alarm: roadmap

v0 is a read-only Windows agent that reports protection status in signed
heartbeats, so a missed or tampered check-in raises an alert off the
machine. It ships in small tickets, each reviewed before merge.

## Ticket 1, part 1 (this branch)

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

## Next tickets

In rough order. Each one gets its own branch and review.

1. **Vendor the proof engine.** Replace the port in `internal/proof`
   (canon, sigs, DSSE) with the engine's packages. The statement builder
   stays behind its interface, and the engine's test vectors already pass
   here.
2. **SPEC additions** (with the spec owner): the `endpoint/v1` predicate
   with `protection` and `agent_version`, and the open questions in
   `docs/api.md` (tenant, seq 1, lost uploads, offline recording).
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
