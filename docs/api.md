# Kovyr agent API, v0

This is the one small API between the Kovyr endpoint agent and the service
that receives its heartbeats.

* **Production:** the receiver is part of Kovyr's **halden** service. halden
  receives heartbeats, finds gaps, sends the owner's alerts and keeps the
  proof log.
* **Development:** `cmd/kovyr-receiver-dev` implements the same API for
  local testing only (in-memory state plus a JSON-lines file, no auth on
  `/v0/status`, no rate limits). Do not expose it to a network.

Statements follow the Kovyr proof spec, `SPEC.md` in
`kendallcoding202.github.io/proof-of-protection/engine/` (cited below as
"SPEC"). Where this page and SPEC disagree, SPEC wins.

## Rules the agent enforces

* **HTTPS only.** Plain `http://` is accepted only with `--dev-insecure`, and
  only to `localhost`, `127.0.0.0/8` or `::1`. The server URL may not carry
  credentials, a query or a fragment. TLS 1.2 or newer with normal
  certificate verification.
* **No redirects.** The agent talks to the configured server and nothing else.
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
| `200`, `202` | accepted (or an exact re-delivery of the latest statement) | removes it from its queue |
| `400`, `409`, `413`, `422` | refused for good: malformed, bad signature, invalid statement, replayed seq or nonce, unknown/expired/misdirected nonce, stale or future timestamp | drops it (the receiver keeps its own record) |
| `401`, `403`, `404`, `429`, `5xx`, anything else | not now | keeps it queued; retries with exponential backoff and jitter, oldest first |

The dev receiver answers with a small JSON body for people using `curl`
(`outcome`, `seq`, `reason`, `events`). The agent never reads it.

### `GET /v0/status` (dev receiver only)

```json
{"generated_at":"2026-10-26T19:57:21Z","expected_interval_s":900,"dev_only":true,
 "devices":[{
   "device_id":"dev_1cc3bdff90b0f8ae","label":"Front desk PC",
   "last_check_in":"2026-10-26T19:57:21Z","last_observed_at":"2026-10-26T19:57:21Z",
   "last_seq":2,"accepted":2,"refused":0,
   "overdue":false,"missed_intervals":0,"gaps":[],
   "tamper_signals_active":[],"tamper_events":0,
   "events":[],
   "latest":{"seq":2,"defender_state":"ok","defender_real_time_protection":"on", "...": "..."}}]}
```

* **Check-ins and gaps.** A gap is a stretch between consecutive statements
  (by `observed_at`) longer than 1.5 intervals, counted as missed intervals.
  An ongoing gap is the time since the last statement. `overdue` means
  nothing has arrived for 1.5 intervals, or the device never checked in.
* **Tamper signals.** Each is raised once, when it first appears:
  * `protection_off`: Defender is the active antivirus (`running_mode`
    `normal`) and its real-time protection, antivirus or service is off;
    or Security Center lists antivirus products and none is on; or fewer
    than 3 firewall profiles are on;
  * `tamper_protection_off`: Defender tamper protection off;
  * `edr_not_running`: a known EDR agent is installed but not running;
  * chain and replay: `chain_broken` (wrong `prev`), `missing_seq` (seq
    numbers skipped: lost, dropped or withheld), `replay_old_seq`,
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
   "sensor_health":{"sensor_running":true,"tamper_detected":false,
                    "driver_blocklist_version":0,"policy_version":0},
   "protection":{
     "security_center":{"state":"ok","products":1,"enabled":1,"up_to_date":1},
     "defender":{"state":"ok","am_service":"on","antivirus":"on","real_time_protection":"on",
                 "behavior_monitor":"on","tamper_protection":"on",
                 "signature_age_days":0,"running_mode":"normal"},
     "edr":{"state":"ok","agents":[{"running":true,"vendor":"microsoft_defender_endpoint"}]},
     "bitlocker_os_volume":"on","firewall_profiles_on":3,
     "vulnerable_driver_blocklist":"default","memory_integrity":"on"}}}
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
* **`protection`** holds the protection checks. Integers use `-1` for
  "unknown or not applicable". Every check that can be absent has a `state`
  (`ok`, `unknown`, `not_applicable`), and when it is not `ok` its values are
  unknown. `edr.agents` is sorted by vendor, one entry per vendor, and never
  holds a service name.
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
  genesis value (see the deviations below).

**Dev receiver deviation:** SPEC refuses a `seq` that is not exactly one more
than the last. One lost upload would then stop a device from ever reporting
again. The dev receiver accepts the statement and raises a `missing_seq`
tamper signal, and a broken `prev` raises `chain_broken`.

**Consequence for the agent:** with a 10-minute nonce and a 5-minute clock
window, a statement must be delivered within minutes. So the agent signs
only right after a challenge, and when it is offline it makes no statement:
the receiver sees a gap ("silence is a signal"). Its on-disk queue (500
entries / 5 MB, oldest dropped first) bridges short upload failures, not
long offline periods.

## What SPEC must add before halden accepts these statements

SPEC 6.4 lists `sensor_health` as "schema only, not implemented", and
today's verifiers reject the `endpoint/v1` predicate type. Proposed additions
to `posture-schema.json`, in the engine's schema language:

```json
"https://kovyr.com/attestation/endpoint/v1": {"t":"object","fields":{
  "tenant":{"t":"id","prefixes":["tnt_"]},
  "attester":{"t":"id","prefixes":["dev_"]},
  "attester_kind":{"t":"enum","values":["device_agent"]},
  "seq":{"t":"int","min":1,"max":2147483647},
  "prev":{"t":"hex","len":64}, "nonce":{"t":"hex","len":32}, "salt":{"t":"hex","len":64},
  "observed_at":{"t":"timestamp"},
  "agent_version":{"t":"object","fields":{
    "major":{"t":"int","min":0,"max":65535},"minor":{"t":"int","min":0,"max":65535},
    "patch":{"t":"int","min":0,"max":65535}}},
  "sensor_health":"<SPEC 6.4, unchanged>",
  "protection":{"t":"object","fields":{
    "security_center":{"t":"object","fields":{
      "state":{"t":"enum","values":["not_applicable","ok","unknown"]},
      "products":{"t":"int","min":-1,"max":32},"enabled":{"t":"int","min":-1,"max":32},
      "up_to_date":{"t":"int","min":-1,"max":32}},
      "le":[["enabled","products"],["up_to_date","products"]]},
    "defender":{"t":"object","fields":{
      "state":{"t":"enum","values":["not_applicable","ok","unknown"]},
      "am_service":{"t":"enum","values":["off","on","unknown"]},
      "antivirus":{"t":"enum","values":["off","on","unknown"]},
      "real_time_protection":{"t":"enum","values":["off","on","unknown"]},
      "behavior_monitor":{"t":"enum","values":["off","on","unknown"]},
      "tamper_protection":{"t":"enum","values":["off","on","unknown"]},
      "signature_age_days":{"t":"int","min":-1,"max":65535},
      "running_mode":{"t":"enum","values":["edr_block","normal","passive","sxs_passive","unknown"]}}},
    "edr":{"t":"object","fields":{
      "state":{"t":"enum","values":["not_applicable","ok","unknown"]},
      "agents":{"t":"array","min_items":0,"max_items":13,"of":{"t":"object","fields":{
        "vendor":{"t":"enum","values":["bitdefender","carbon_black","cortex_xdr","crowdstrike","eset",
          "huntress","malwarebytes","microsoft_defender_endpoint","sentinelone","sophos","symantec",
          "trend_micro","webroot"]},
        "running":{"t":"bool"}}}}}},
    "bitlocker_os_volume":{"t":"enum","values":["not_applicable","off","on","unknown"]},
    "firewall_profiles_on":{"t":"int","min":-1,"max":3},
    "vulnerable_driver_blocklist":{"t":"enum","values":["default","off","on","unknown"]},
    "memory_integrity":{"t":"enum","values":["off","on","unknown"]}}}}}
```

Questions for the spec owner:

1. **Tenant.** v0 statements have no `tenant`, because there is no tenant key
   until enrollment exists. Add it with the enrollment ticket?
2. **Seq 1.** SPEC links `seq` 1 to the enrollment payload. v0 uses an
   all-zero `prev` (`proof.GenesisPrev`) until then.
3. **Lost uploads.** "A number is spent once signed" plus "ingest refuses
   any seq but last+1" leaves a device stuck after one undeliverable
   statement. Should ingest accept the jump and flag it, as the dev receiver
   does?
4. **Offline recording.** The 10-minute nonce and 5-minute clock window rule
   out recording an offline period for later upload. Is that intended?
5. **`edr.agents`** is an array sorted and unique by `vendor`. The engine's
   `array` type has no sort key, so should it become a SPEC "result list"
   (`items`/`total`/`truncated`, keyed by `vendor`)?
