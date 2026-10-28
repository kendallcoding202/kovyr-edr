# Kovyr agent API, v0

This is the one small API between the Kovyr endpoint agent and the service
that receives its heartbeats.

* **Production:** the receiver is part of Kovyr's **halden** service, at
  `https://agent.kovyr.com/api/agent`. halden receives heartbeats, finds
  gaps and sends the owner's alerts and digest. Its routes store each
  heartbeat and answer `202` ("received, verification pending"); a worker
  verifies it within about a minute and records any refusal itself.
* **Development:** `cmd/kovyr-receiver-dev` implements the same API for
  local testing only (in-memory state plus a JSON-lines file, no auth on
  `/v0/status`, no rate limits). Do not expose it to a network.

Statements follow the Kovyr proof spec, [`proof/SPEC.md`](../proof/SPEC.md)
(cited below as "SPEC"). The proof library and SPEC were vendored from the
website repo and this copy is canonical (see `proof/README.md`). Where this
page and SPEC disagree, SPEC wins.

## Rules the agent enforces

* **HTTPS only.** Plain `http://` is accepted only with `--dev-insecure`, and
  only to `localhost`, `127.0.0.0/8` or `::1`. The server URL may not carry
  credentials, a query or a fragment. TLS 1.2 or newer with normal
  certificate verification.
* **No redirects, no proxy.** The agent talks to the configured server and
  nothing else, directly: it ignores `HTTP_PROXY` / `HTTPS_PROXY`.
* **Small, fixed requests.** Every request carries `User-Agent:
  kovyr-alarm/<version>`. Response headers are capped at 16 KiB and the
  challenge body at 256 bytes. The agent's log holds only status codes and
  fixed text, never text a server or the network sent (a content type, a
  body, a malformed header, the names in a certificate).
* **No commands, ever.** The server can give the agent exactly two things: a
  nonce, and an HTTP status code. The challenge response must be exactly
  `{"nonce":"<32 lowercase hex>"}` (anything else, including any extra field,
  is ignored and no statement is made). The heartbeat response body is
  drained unread. The agent has no code path that runs a command, script or
  binary, and a test keeps `os/exec`, `plugin` and `net/rpc` out of every
  package it is built from. Signed agent updates are a later ticket and will
  get their own reviewed channel.

## Authentication

* **Device key.** Every heartbeat is a DSSE envelope signed by the device's
  ECDSA P-256 key (ES256, IEEE P1363 `r||s`, low S; SPEC 4). The receiver
  looks the key up by the envelope's `keyid` (SHA-256 of the SPKI) among
  enrolled devices and verifies the signature. There are no passwords,
  API keys or bearer tokens.
* **Evidence strength.** v0 keys are software keys: "software" strength
  (SPEC 14). On Windows the key is sealed with DPAPI in machine scope under
  `%ProgramData%\Kovyr`, in a directory only SYSTEM and Administrators can
  open. A TPM-backed key (Microsoft Platform Crypto Provider) will replace it
  behind the same `proof.Signer` interface.
* **Enrollment (stub).** v0 has no enrollment protocol. The owner runs
  `kovyr-agent enroll --print-pubkey` and copies `device_id` and `public_key`
  into the receiver's devices file:

  ```json
  {"devices": [
    {"device_id": "dev_1cc3bdff90b0f8ae",
     "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
     "label": "Front desk PC"}
  ]}
  ```

  `device_id` must be derived from the key (`dev_` + first 16 hex of the key
  ID), or the file is rejected. `label` is the owner's name for the machine;
  it is shown in status and never signed. The real flow (SPEC 6.3: an
  `enrollment/v1` attester record signed by the tenant key, then the device
  key, with `key_protection`, enrollment codes, `device_number`) is a later
  ticket. `POST /v0/enroll` answers `501 Not Implemented` until then.

## Endpoints

### `GET /v0/challenge?device=<device ID>`

Returns a one-time nonce issued for that device (SPEC 8).

```
200 OK
Content-Type: application/json

{"nonce":"9f1c0a6b2d4e8f7a1b3c5d7e9f0a2b4c"}
```

The body is canonical JSON (strict-json-c14n/v1, SPEC 3), optionally
followed by one newline. The nonce is single use and expires after 10
minutes. `403` means the device is not enrolled. An unenrolled device
therefore never signs and never spends a sequence number.

### `POST /v0/heartbeat`

The body is one canonical DSSE envelope (`Content-Type: application/json`,
at most 16 KiB):

```json
{"payload":"<base64 statement>","payloadType":"application/vnd.in-toto+json",
 "signatures":[{"keyid":"<64 hex>","sig":"<base64 64-byte P1363 signature>"}]}
```

| Status | Meaning | Agent does |
|---|---|---|
| `200`, `202` | accepted (or an exact re-delivery of the latest statement). `202` means "received, verification pending": halden stores the envelope and verifies it later, so a statement it then refuses also got a `202` | removes it from its queue |
| `400`, `409`, `413`, `422` | refused for good: malformed, bad signature, invalid statement, replayed seq or nonce, unknown/expired/misdirected nonce, stale or future timestamp | drops it (the receiver keeps its own record) |
| `401`, `403`, `404`, `429`, `5xx`, anything else | not now | keeps it queued; retries with exponential backoff and jitter, newest first (see "The queue" below) |

The dev receiver answers with a small JSON body for people using `curl`
(`outcome`, `seq`, `reason`, `events`). The agent never reads it.

### `GET /v0/status` (dev receiver only)

```json
{"generated_at":"2026-10-26T19:57:21Z","expected_interval_s":900,"dev_only":true,
 "devices":[{
   "device_id":"dev_1cc3bdff90b0f8ae","label":"Front desk PC",
   "last_check_in":"2026-10-26T19:57:21Z","last_observed_at":"2026-10-26T19:57:21Z",
   "last_seq":2,"accepted":2,"refused":0,
   "overdue":false,"missed_intervals":0,"lost_statements":0,"gaps":[],
   "tamper_signals_active":[],"tamper_events":0,
   "events":[],
   "latest":{"seq":2,"defender_state":"ok","defender_real_time_protection":"on", "...": "..."}}]}
```

* **Check-ins and gaps.** A gap is a stretch between consecutive statements
  (by `observed_at`) longer than 1.5 times the interval the earlier one
  announced (`schedule.interval_s`) plus the later one's `deferred_s`,
  counted as missed intervals,
  or a hole in the seq numbers, counted as `lost_statements` (SPEC 8:
  statements signed but never received), or both. A hole with no missed
  interval is a gap of its own; a hole before the first statement seen is a
  zero-length gap at that statement. An ongoing gap is the time since the
  last statement. `overdue` means nothing has arrived for 1.5 intervals, or
  the device never checked in. `lost_statements` on the device is the total.
  `latest` also shows `edr_agents_total` and `edr_agents_truncated`, since
  the statement's agent list is capped, the announced schedule
  (`interval_s`, `deferred_s`, `heavy_checks_skipped`) and the tripwire
  (`tripwire_state`, `tripwire_triggered`, `tripwire_reason`,
  `tripwire_window`, `tripwire_folders_watched`, and `tripwire_counts` with
  the six buckets while it is watching).
* **Tamper signals.** Each is raised once, when it first appears:
  * `protection_off`: Defender is the active antivirus (`running_mode`
    `normal`) and its real-time protection, antivirus or service is off;
    or Security Center lists antivirus products and none is on; or fewer
    than 3 firewall profiles are on;
  * `tamper_protection_off`: Defender tamper protection off;
  * `edr_not_running`: a known EDR agent is installed but not running;
  * `ransomware_suspected:<reason>`: the tripwire fired
    (`mass_extension_change` or `ransom_notes`). Unlike the others it is
    raised for **every** statement that carries a trip, since each one is a
    new firing; it stays in `tamper_signals_active` until a quiet statement
    arrives and in `events` after that;
  * chain and replay: `chain_broken` (wrong `prev`), `missing_seq` (seq
    numbers skipped: lost, dropped or withheld; also a lost-statement gap),
    `replay_old_seq`,
    `replay_nonce`, `unknown_nonce`, `bad_signature`, `invalid_statement`,
    `future_timestamp`, `out_of_order`.

  `stale_statement` (delivered more than 5 minutes after it was made) is
  informational. The next statement shows the skipped seq as `missing_seq`.

## The statement

An in-toto Statement v1 (SPEC 6), canonical JSON, one subject:

```json
{"_type":"https://in-toto.io/Statement/v1",
 "predicateType":"https://kovyr.com/attestation/endpoint/v1",
 "subject":[{"digest":{"sha256":"<key ID>"},"name":"dev_<16 hex>"}],
 "predicate":{
   "attester":"dev_<16 hex>","attester_kind":"device_agent",
   "seq":12,"prev":"<64 hex>","nonce":"<32 hex>","salt":"<64 hex>",
   "observed_at":"2026-10-26T19:57:21Z",
   "agent_version":{"major":0,"minor":1,"patch":0},
   "schedule":{"interval_s":900,"deferred_s":0,"heavy_checks_skipped":false},
   "sensor_health":{"sensor_running":true,"tamper_detected":false,
                    "driver_blocklist_version":0,"policy_version":0},
   "protection":{
     "security_center":{"state":"ok","products":1,"enabled":1,"up_to_date":1},
     "defender":{"state":"ok","am_service":"on","antivirus":"on","real_time_protection":"on",
                 "behavior_monitor":"on","tamper_protection":"on",
                 "signature_age_days":0,"running_mode":"normal"},
     "edr":{"state":"ok","agents":{"items":[{"running":true,"vendor":"microsoft_defender_endpoint"}],
                                   "total":1,"truncated":false}},
     "bitlocker_os_volume":"on","firewall_profiles_on":3,
     "vulnerable_driver_blocklist":"default","memory_integrity":"on"},
   "tripwire":{"state":"ok","triggered":false,"reason":"none","window":"60s","folders_watched":4,
               "renamed":"1_9","extension_changed":"0","modified":"10_99","deleted":"0",
               "suspicious_created":"0","unknown_activity":"0"}}}
```

(Keys are sorted in the real bytes; shown grouped here.)

* **Common fields** (`attester` … `observed_at`) have exactly the names and
  formats of the posture/v1 common fields (SPEC 6.2). `prev` is SHA-256 of
  the previous statement's exact payload bytes (SPEC 8). `salt` is 256 fresh
  random bits per statement.
* **`sensor_health`** is exactly the section SPEC 6.4 defines (a test pins
  it to the SPEC text). It describes the Kovyr sensor itself. In v0:
  `sensor_running` is true; `tamper_detected` is false because v0 has no
  self-tamper checks yet (it means "none detected", not "checked and
  clean"); `driver_blocklist_version` is 0 because v0 does not read it; and
  `policy_version` is 0 because there is no policy yet.
* **`protection`** holds the protection checks (SPEC 6.5). Integers use
  `-1` for "unknown or not applicable". Every check that can be absent has a
  `state` (`ok`, `unknown`, `not_applicable`), and when it is not `ok` its
  counts are `-1`, its toggles `unknown`, and `edr` has no `agents`.
  `edr.agents` is a SPEC result list: one record per vendor, sorted by
  vendor, never a service name, at most 8 listed. When more are found, the
  stopped ones are kept first and `truncated` is true; `total` is the
  number found.
* **`schedule`** (SPEC 6.5) says when the next heartbeat is due
  (`interval_s`, doubled on battery), how long this one was deferred
  because the processor was busy (`deferred_s`), and whether the heavy
  checks were skipped to save battery (`heavy_checks_skipped`; BitLocker
  and memory integrity then read `unknown`). See `docs/windows-service.md`.
* **`tripwire`** (SPEC 6.5) is the ransomware tripwire (`docs/tripwire.md`).
  `state` is `ok` while it watches at least one folder, `unknown` when it
  could not watch any (or is turned off in the settings), and
  `not_applicable` outside Windows; when not `ok` it carries only `state`.
  `triggered` says it fired since the last statement the server accepted,
  with a `reason`: a trip is repeated in every statement until one carrying
  it is accepted (SPEC 6.5), so the same trip can arrive more than once.
  The six counts are buckets (`0`, `1_9`, `10_99`, `100_999`,
  `1000_plus`) of the changes in the window that tripped, or in the busiest
  window since the last accepted statement. No path, file name, extension or
  process name is ever in it. When it fires, the agent sends a statement
  at once (at most one per cooldown, ten minutes by default) that
  announces the time left until the scheduled one as `interval_s`.
* **No `tenant`** until endpoint enrollment ships, and `seq` 1 links to the
  all-zero `prev` (SPEC 6.5). Such statements are verified one by one by the
  receiver that holds the device key and cannot go into a Proof Pack.
* `security_center` is `not_applicable` on server editions of Windows:
  Security Center is a client feature, and CI runners have the namespace
  with no products in it.
* Defender for Endpoint (`Sense`) is listed only when the machine is
  onboarded (`OnboardingState` = 1) or the service is running. Windows
  ships the service everywhere, so an un-onboarded machine is not "MDE
  not running".

Content rule (SPEC 6.1, CLAUDE.md section 3): only booleans, integers, enums
and timestamps, plus fixed-format protocol values. The builder takes only
typed values, imports nothing that touches files, network or the OS, and
is checked by an adversarial test. That test walks hundreds of random
statements and fails on any string that is neither a reviewed enum value
nor a fixed-format protocol value.

## Ingest rules

These follow SPEC 8 and the engine's reference ingest (`tlog.Server`):

* the nonce must have been issued by this receiver, to this device, at most
  10 minutes ago, and never used before;
* `observed_at` must be within 5 minutes of the receiver's clock;
* the signature must verify with the enrolled key, and the statement must
  be canonical and schema-valid, with its subject digest equal to the
  signing key's ID;
* `seq` must be after the last accepted one. An exact re-delivery of the
  latest statement is accepted as a duplicate.
* `prev` must match the previous payload. For `seq` 1 it must be the
  genesis value (all zeros until endpoint enrollment, SPEC 6.5).
* A `seq` more than one ahead is accepted (SPEC 8): the hole is a
  lost-statement gap in status and raises `missing_seq`, so one lost upload
  never locks a device out. `prev` cannot be checked across the hole.

**Dev receiver difference:** a broken `prev` between consecutive statements
is accepted and raises `chain_broken`, where SPEC's ingest refuses it. The
dev receiver flags chain problems so you can see them in status.

**Consequence for the agent:** with a 10-minute nonce and a 5-minute clock
window, a statement must be delivered within minutes. So the agent signs
only right after a challenge, and when it is offline it makes no statement:
the receiver sees a gap ("silence is a signal"). Its on-disk queue (500
entries / 5 MB, oldest dropped first) bridges short upload failures, not
long offline periods.

### The queue

The agent sends its queue **newest first**: the newest statement says how
the computer is now, and after an outage it must not wait behind a backlog
that ingest can only refuse (halden also limits each device's uploads per
hour). Before each send, and after each answer:

1. A queued statement signed more than **11 minutes** ago (the 10-minute
   nonce lifetime plus a minute for clock steps) is dropped unsent. Its
   nonce was issued before it was signed, so ingest refuses it whatever the
   clocks say.
2. A queued file that is not a statement signed by this device's key is
   removed unsent.
3. Once the server accepts a statement (`200`/`202`), every older queued
   statement is dropped unsent: ingest refuses a `seq` at or below the last
   one it accepted.
4. A refused statement (`400`/`409`/`413`/`422`) is dropped and the next
   newest is tried; anything else stops the send until the retry.

Every statement dropped this way shows at the receiver as a lost report
(`missing_seq`, halden's `lost_reports_total`), which is the honest outcome.
A statement between 5 and 11 minutes old is still sent, because a clock
difference can make it acceptable.

## Spec decisions (Ticket 2)

The open questions from Ticket 1 are decided and written into SPEC:

| Question | Decision | SPEC |
|---|---|---|
| `protection` and `agent_version` | Standard fields of `endpoint/v1`, same no-free-text rules | 6.5 |
| Tenant and the seq-1 link | Arrive with endpoint enrollment; until then no `tenant` and an all-zero `prev` for seq 1 | 6.5 |
| Lost uploads | Ingest accepts a seq jump and records a lost-report gap; verifiers disclose it (sequence warning, summary `lost_reports`) | 8, 9, 11.3, 13 |
| Offline recording | Offline periods stay gaps; TPM-clock-backed offline records are future work, as lower-strength evidence | 8, 18 |
| `edr.agents` | A result list: capped at 8, sorted by vendor, `total` and `truncated` | 6.5 |

halden must use the vendored validator (or a port of it) for these rules.
The Python and JavaScript implementations in the website repo do not know
them yet.
