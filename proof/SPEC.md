# Proof engine specification

Version: prototype, October 2026. Status: draft for review.

This document is language-neutral. It specifies the bytes: statements,
envelopes, the log, checkpoints, witness cosignatures, timestamps, Proof
Packs, trust policies and the verification algorithm. Three implementations
follow it and agree on the shared test vectors:

| Implementation | Location | Role |
|---|---|---|
| Go | `kovyr-edr/proof/` | **canonical**: the library the endpoint agent and its dev receiver use, the reference ingest, log and offline verifier |
| Python | `kendallcoding202.github.io/proof-of-protection/engine/python/` (`proofengine`) | server side: statement building, ingest, log, witnesses, pack build and verify |
| JavaScript | `kendallcoding202.github.io/proof-of-protection/demo/verifier/` | the in-browser verifier (WebCrypto only, no third-party code) |

The Go engine moved into `kovyr-edr/proof/` (imported from the website repo
at commit `3a2773b`); that copy and this file are now canonical. The
Python and JavaScript implementations follow this specification as it was
at the import. They do not yet implement the `endpoint/v1` predicate (6.5),
lost-report gaps (8, 13) or the production scanner's check IDs (6.2).

Normative data files: `proof/testdata/vectors/posture-schema.json` (the
statement schema, generated from `proof/posture/schema.go`) and the test
vectors next to it. Where this text and the schema disagree, the schema wins
and this text is a bug.

---

## 1. Brand-dependent constants

The product may be renamed. Only these values carry the brand, and each lives
in exactly one place per language:

| Constant | Current value | Go | Python | JavaScript |
|---|---|---|---|---|
| Brand name | `Kovyr` | `brand.Name` | `brand.NAME` | `BRAND.name` (generated `demo/brand.js`) |
| Product name | `Kovyr Proof` (placeholder) | `brand.Product` | `brand.PRODUCT` | `BRAND.product` |
| Posture predicate type | `https://kovyr.com/attestation/posture/v1` | `brand.PredicatePosture` | `brand.PREDICATE_POSTURE` | `ProofSchema.predicate_types.posture` (generated) |
| Enrollment predicate type | `https://kovyr.com/attestation/enrollment/v1` | `brand.PredicateEnrollment` | `brand.PREDICATE_ENROLLMENT` | `ProofSchema.predicate_types.enrollment` (generated) |
| Endpoint predicate type | `https://kovyr.com/attestation/endpoint/v1` | `brand.PredicateEndpoint` | not ported yet | `ProofSchema.predicate_types.endpoint` (generated, once ported) |
| Demo log origin | `kovyr.com/proof/demo-log` | `brand.DemoLogOrigin` | n/a | `BRAND.logOrigin` |

To rename: edit `proof/brand/brand.go` and `engine/python/proofengine/brand.py`,
then regenerate (the vectors with
`go test ./proof/internal/vectors -run TestVectorsAreUpToDate -update`; the
website demo with `proofctl demo generate` in the website repo; the Python
schema with `python3 -I sync_schema.py`). Statements embed the predicate type and
checkpoints embed the origin, so data signed before a rename keeps the old
values and stays verifiable; a verifier that must accept both lists both.

Every other identifier is brand-neutral: `strict-json-c14n/v1`,
`proof-pack/v1`, `proof-trust-policy/v1`, `simulated-tsa/v1`,
`tenant-name-commitment/v1`.

---

## 2. Conventions

* **Base64** is standard RFC 4648 section 4 with padding. Decoders must reject
  non-canonical input: decode, re-encode, and compare.
* **Hex** is lowercase.
* **Timestamps** are UTC with second precision, exactly `YYYY-MM-DDTHH:MM:SSZ`.
  No offsets, no fractions.
* **Dates** are `YYYY-MM-DD` and mean UTC calendar days.
* **SHA-256** is the only hash function.

## 3. Canonical JSON: `strict-json-c14n/v1`

Everything signed, timestamped or hashed is canonical JSON:

1. Values are objects, arrays, strings, integers, `true` and `false`. `null`
   and non-integer numbers are forbidden.
2. Integers are plain decimal (`0`, `-7`, `42`; never `-0`, `07`, `1.0` or
   `1e2`) within ±(2^53 − 1), so JavaScript represents them exactly.
3. Strings and object keys use only printable ASCII, 0x20 to 0x7E, except `"`
   and `\`. No escape sequence can appear, so every string has exactly one
   encoding. Keys are non-empty.
4. Object keys are unique and sorted by byte value.
5. No whitespace outside strings.
6. Nesting depth is at most 32.

**Acceptance rule:** bytes are canonical if and only if parsing them and
re-encoding the value reproduces them byte for byte. That single comparison
rejects duplicate keys, unsorted keys, whitespace, escapes and number
variants. Parsers must not fold key case. A `__proto__` key is ordinary data.

Signed bytes are stored verbatim forever and never re-serialized. A future
`strict-json-c14n/v2` would get a new name; v1 verifiers stay in service.

**Container JSON** (Proof Pack and trust policy files, which are not signed
as a whole) is ordinary UTF-8 JSON with these restrictions: valid UTF-8, no
duplicate keys, integers only (safe range), no `null`, no lone surrogates,
nothing after the top-level value. Objects inside a container that are
hashed (envelopes, timestamp tokens) are re-encoded canonically and must
contain only canonical strings.

## 4. Keys and signatures

| Algorithm | Name in records | Used by |
|---|---|---|
| ECDSA P-256 with SHA-256 (ES256) | `ecdsa-p256-sha256` | device agents, the firm's key, staff attesters. TPM 2.0 and the Apple Secure Enclave support P-256, so hardware-bound device keys use it. |
| Ed25519 | `ed25519` | the vendor's service keys (cloud connector, external scanner), the log, witnesses, simulated timestamp authorities |

**Public keys** are DER SubjectPublicKeyInfo (SPKI), base64-encoded where
they appear in JSON. Only two exact encodings are accepted:

* Ed25519: 44 bytes, prefix `302a300506032b6570032100` then the 32-byte key.
* P-256: 91 bytes, prefix `3059301306072a8648ce3d020106082a8648ce3d03010703420004`
  then X and Y (32 bytes each); the point must be on the curve.

**Key ID** (DSSE `keyid`): lowercase hex SHA-256 of the SPKI bytes.

**Signature encoding:** every signature is exactly 64 bytes.

* Ed25519: RFC 8032.
* ES256: ECDSA over SHA-256(message), encoded as IEEE P1363 `r || s` (each 32
  bytes, big-endian, zero-padded) with **low S** (s ≤ n/2, n the P-256 group
  order). Verifiers reject high-S signatures and DER. Signers that produce
  DER (most libraries, Go's `crypto.Signer`, the Secure Enclave, cloud KMS)
  convert: parse r and s, replace s with n − s if s > n/2, then pad. Windows
  CNG emits P1363 natively. Low S makes each signed statement's envelope
  unique, so nobody can create a second valid encoding of a report.

## 5. Identifiers

All identifiers are derived from keys; none is chosen by a person.

| Identifier | Format |
|---|---|
| Tenant (a firm) | `tnt_` + first 16 hex characters of the tenant key ID |
| Device agent | `dev_` + first 16 hex of its key ID |
| Cloud connector | `con_` + … |
| Staff attester | `stf_` + … |
| External scanner | `scn_` + … |

Devices are shown to people as `D01`, `D02`, … from the `device_number`
assigned at enrollment. The firm's app may map D07 to "Maria's laptop"
locally; that mapping is never signed or logged.

## 6. Statements

Every statement is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md):

```json
{"_type":"https://in-toto.io/Statement/v1",
 "predicate":{...},
 "predicateType":"<posture, endpoint or enrollment predicate type>",
 "subject":[{"digest":{"sha256":"<key ID of the attester (or tenant)>"},"name":"<attester or tenant ID>"}]}
```

Exactly one subject: the key-holder the statement is about. Its `name` is the
attester ID (posture, endpoint) or the enrolled tenant or attester ID
(enrollment), and its digest is that key's key ID.

### 6.1 The content rule

**Statements carry only booleans, integers, enums and timestamps**, plus
fixed-format protocol fields (key-derived IDs, hex nonces and digests, salts,
public keys, constant URIs). Nothing can hold a file name, path, host name,
user name, email content or any other free text. This is enforced twice:

* **Builders** take typed values only (enum members, integers, booleans,
  times, keys), never a string or a path, validate their own output against
  the schema, and live in modules that do not import file system, network or
  OS packages. Each implementation has a test that checks this structurally
  (by import graph and API shape), so it does not depend on reviewer
  diligence. Collectors that do see paths must classify into these types
  before calling a builder.
* **Validators** (every verifier and the ingest server) reject any field the
  schema does not list, any value outside its type, and any non-canonical
  payload.

Further conventions:

* **Caps with a `truncated` flag.** Lists are capped. A *counted list* is
  `{"items":[{"count":n,"kind":k},...],"total":n,"truncated":b}`: enum plus
  count instead of prose, items sorted by kind and unique, `total` exact. If
  more kinds were seen than fit, the most frequent are kept and `truncated` is
  `true` (then the list is full and `total` exceeds the listed counts;
  otherwise `total` equals their sum). A *result list* has the same envelope
  with fixed-shape records sorted and unique by a key field; `total` is the
  true record count.
* **Approximate classifications** are enum values ending in `_approx` (for
  example `signin_unusual_country_approx`, from IP geolocation). Displays
  must say they are approximate.
* **No floats anywhere.** Durations are integer seconds or minutes.
* **Salt.** Every posture and enrollment predicate carries `salt`, 256 random
  bits (64 hex). The public log publishes only a hash of each statement
  (section 9); without the salt, the few booleans and counts in a statement
  could be recovered by brute force.

### 6.2 Posture predicate (`.../posture/v1`)

Common fields:

| Field | Type |
|---|---|
| `tenant` | tenant ID |
| `attester` | attester ID; must equal the subject name; its prefix must match `attester_kind` |
| `attester_kind` | enum `device_agent`, `cloud_connector`, `staff_attester`, `external_scanner` |
| `seq` | integer 1 to 2^31 − 1, this attester's report number |
| `prev` | hex SHA-256 of the previous report's payload bytes (for `seq` 1: of the attester's enrollment payload) |
| `nonce` | 32 hex: the one-time server challenge |
| `salt` | 64 hex: 256 random bits |
| `observed_at` | timestamp: when the attester made the report (its own clock) |

Plus exactly one section, chosen by `attester_kind`:

**`device`** (device agent). Evidence strength: *software* in this prototype;
*hardware* once the key is TPM- or Secure Enclave-bound and its attestation is
verified.

| Field | Type |
|---|---|
| `disk_encryption` | enum `on`, `off`, `suspended`, `unknown` |
| `os_patch_status` | enum `current`, `updates_pending`, `out_of_date`, `unsupported_os`, `unknown` |
| `firewall_on`, `screen_lock_on`, `edr_running` | boolean |
| `screen_lock_max_idle_min` | integer 0 to 1440 |
| `edr_kind` | enum `defender`, `third_party`, `none` |
| `local_admin_count` | integer 0 to 64 |
| `unapproved_remote_tools` | counted list (max 4 items) of `anydesk`, `other_remote_tool`, `rustdesk`, `screenconnect`, `splashtop`, `teamviewer`, `ultraviewer`, `vnc` |
| `heartbeat_interval_s` | integer 30 to 3600 |
| `heartbeats_24h` | integer 0 to 2880 |

**`tenant_posture`** (cloud connector reading Microsoft 365). Strength: *platform*.

| Field | Type |
|---|---|
| `source` | enum `microsoft_365` |
| `accounts_total`, `accounts_mfa`, `accounts_passkey`, `admin_accounts` | integers; the last three must not exceed `accounts_total` |
| `devices_known`, `devices_enrolled`, `devices_unknown_seen` | integers |
| `mailbox_alerts_24h` | counted list (max 5) of `forwarding_rule_external`, `impossible_travel_approx`, `new_admin_role`, `new_auth_method`, `signin_unusual_country_approx` |
| `mailbox_alerts_open`, `mailbox_alerts_resolved_24h` | integers |

**`scan`** (the vendor's external scanner checking the firm's own domain from
outside: email authentication, TLS, HTTP headers, breach exposure). Signed
with the vendor's service key. Strength: *scan-verified*. The domain is never
named; the tenant is.

| Field | Type |
|---|---|
| `source` | enum `external_scan` |
| `results` | result list (max 32), sorted by `check_id`, of `{check_id, status, severity}` |
| `results.items[].check_id` | enum of stable IDs from the scanner's check catalog (table below). IDs are never reused; new checks get new IDs. |
| `results.items[].status` | enum `pass`, `warn`, `fail`, `error`, `not_applicable` |
| `results.items[].severity` | enum `info`, `low`, `medium`, `high`, `critical` |

The check IDs are the catalog of the vendor's production scanner (halden's
`checks` table). Most name an *outcome*, not a test: one test, for example
SPF, reports exactly one of its outcome IDs per scan (EMAIL-01, -02, -03 or
-09), sometimes with a second (EMAIL-10). So a statement lists the outcomes
the scan found, and `total` is the number of results the scan produced. A
scanner never leaves a result out because the enum lacks its ID: the ID is
added here first.

| ID | The scan found |
|---|---|
| `DNS-01` | the domain has no A or AAAA record |
| `DNS-02` | the domain has no MX record |
| `EMAIL-01` | no SPF record |
| `EMAIL-02` | an SPF policy that does not restrict senders |
| `EMAIL-03` | a restrictive SPF record (`-all` or `~all`) |
| `EMAIL-04` | no usable DMARC record (none, or several, which receivers ignore) |
| `EMAIL-05` | DMARC published but not enforced (`p=none`, or a policy that acts on no mail) |
| `EMAIL-06` | DMARC enforced (`quarantine` or `reject`), possibly on only part of the mail |
| `EMAIL-07` | DKIM published on at least one common selector |
| `EMAIL-08` | no DKIM record on the common selectors probed |
| `EMAIL-09` | several SPF records, so receivers ignore SPF |
| `EMAIL-10` | an SPF record that needs more than 10 DNS lookups, so receivers treat it as failed |
| `CT-00` | the Certificate Transparency lookup could not be completed |
| `CT-01` | subdomains named in Certificate Transparency logs |
| `BREACH-00` | the breach-exposure check was not run, or could not reach the breach service |
| `BREACH-01` | the breach service's domain search answered: `fail` if accounts on the domain are in known breaches, `pass` if none are |
| `BREACH-02` | the breach service found no accounts on the domain |
| `BREACH-03` | the breach service refused the search: domain ownership is not verified there |
| `BREACH-04` | the breach service gave an unexpected answer |
| `WEB-00` | the website could not be reached over HTTPS |
| `WEB-01` | the website's TLS certificate failed validation |
| `WEB-02` | some of the checked HTTP security headers are missing |
| `WEB-03` | all of the checked HTTP security headers are present |
| `WEB-04` | response headers disclose software versions |
| `TLS-01` … `TLS-03`, `HTTP-01` … `HTTP-03` | prototype IDs, used only in sample data and test vectors. The production scanner reports TLS and HTTP header results as `WEB-xx`. Kept because IDs are never reused. |

`status` is the scanner's verdict on that result: `pass` (checked, nothing to
fix), `warn` (a weakness worth fixing), `fail` (a serious problem: missing or
broken), `error` (the check could not be completed, so it says nothing either
way) or `not_applicable` (the domain has nothing for the check to look at).
`severity` is the scanner's rating of the result; it is `info` for `pass`,
`error` and `not_applicable`.

**`staff_event`** (a person's signed record). Strength: *staff-attested*.
`kind` is `verify_before_pay` or `backup_restore_drill`, with the matching
sub-object:

* `verify_before_pay`: `requests` (1 to 1000), `callback_verified`,
  `second_approver`, `blocked` (each ≤ `requests`), `request_kinds` (counted
  list of `bank_detail_change`, `payroll_change`, `refund_redirect`,
  `vendor_invoice_change`, `wire_transfer`).
* `backup_restore_drill`: `performed_at` (timestamp), `result` (`success`,
  `partial`, `failed`), `files_restored`, `minutes_to_restore` (integers),
  `second_person_verified` (boolean).

### 6.3 Enrollment predicate (`.../enrollment/v1`)

Common: `kind` (`tenant_genesis` or `attester`), `tenant`, `enrolled_at`,
`nonce`, `salt`.

* **`tenant_genesis`** creates a firm. Fields: `tenant_key` (SPKI),
  `tenant_key_alg`, `display_name_commitment` (64 hex, section 11.2). Signed
  by the tenant key.
* **`attester`** binds a key to the firm. Fields: `attester`,
  `attester_kind`, `attester_key` (SPKI), `attester_key_alg`,
  `key_protection` (`software`, `tpm2`, `secure_enclave`), `key_attestation`
  (`none`, `tpm2_quote`, `apple_mda`), `enrollment_method`
  (`enrollment_code`, `owner_approval`), `device_class` (`laptop`,
  `desktop`, `server`, `not_a_device`), `platform` (`windows`, `macos`,
  `microsoft_365`, `mobile_app`, `vendor_service`), `device_number` (0 to
  9999), `staff_role` (`none`, `owner`, `office_manager`, `bookkeeper`).
  Signed by the tenant key **then** by the attester key (proof of
  possession). The enrollment code itself (issued by the server side,
  single-use, expiring) is never logged.

One key may be enrolled in several tenants (the vendor's scanner key is):
registries, sequence numbers and chains are per (tenant, attester).

### 6.4 Future statement types (schema only, not implemented)

For the endpoint agent's later stages, in the same schema language and under
the same rules (no free text, no paths, no host names). These would be new
sections of the endpoint predicate (6.5); they are not accepted by today's
verifiers. `sensor_health`, listed here first, is now a standard field of
the endpoint predicate (6.5) with exactly this schema.

```json
"detection": {"t":"object","fields":{
  "rule_id":  {"t":"enum","values":["DET-0001","DET-0002","..."]},
  "technique":{"t":"enum","values":["T1003.001","T1059.001","T1219","T1486","T1490","..."]},
  "severity": {"t":"enum","values":["info","low","medium","high","critical"]},
  "action":   {"t":"enum","values":["alerted","blocked","process_killed","quarantined","host_isolated"]},
  "count":    {"t":"int","min":1,"max":100000},
  "first_seen":{"t":"timestamp"}, "last_seen":{"t":"timestamp"}}}

"response": {"t":"object","fields":{
  "action":       {"t":"enum","values":["isolate","kill_process","revoke_sessions","restore"]},
  "outcome":      {"t":"enum","values":["succeeded","failed","partial","pending"]},
  "approver_kind":{"t":"enum","values":["automatic_policy","owner","it_provider","vendor_soc"]},
  "requested_at": {"t":"timestamp"}, "completed_at": {"t":"timestamp"}}}

"sensor_health": {"t":"object","fields":{
  "sensor_running":           {"t":"bool"},
  "tamper_detected":          {"t":"bool"},
  "driver_blocklist_version": {"t":"int","min":0,"max":9007199254740991},
  "policy_version":           {"t":"int","min":0,"max":9007199254740991}}}
```

Rule and technique IDs are enums maintained with the detection content (a new
rule gets a new ID; the verifier's schema is updated with the rule pack).
Process names, command lines, file paths and user names stay on the device.
Response actions require an approval bound to a hardware key; the approval
would be its own statement, linked by sequence and `prev` like every other.

### 6.5 Endpoint predicate (`.../endpoint/v1`)

The Kovyr endpoint agent's heartbeat: the agent's own health and the
protection status of the machine it runs on. One statement per heartbeat
interval (and extra ones when the agent has something urgent to say).
Evidence strength: *software* while device keys are software keys
(section 14).

**Status: draft.** Until enrollment for endpoint agents ships, statements of
this type are development-only and are never logged; fields may still be
added without a new version, and older development statements need not stay
valid.

Common fields, with the names and formats of the posture common fields
(6.2):

| Field | Type |
|---|---|
| `attester` | device ID (`dev_` + 16 hex); must equal the subject name and be derived from the subject digest (the signing key's ID) |
| `attester_kind` | enum `device_agent` |
| `seq`, `prev`, `nonce`, `salt`, `observed_at` | as in 6.2 |
| `agent_version` | `{"major","minor","patch"}`, integers 0 to 65535 (never a version string) |
| `sensor_health` | the 6.4 schema, unchanged: `sensor_running`, `tamper_detected` (booleans), `driver_blocklist_version`, `policy_version` (integers 0 to 2^53 − 1) |
| `schedule` | when the agent reports, below |
| `protection` | the protection checks, below |
| `tripwire` | the ransomware tripwire, below |

**No tenant yet.** `tenant` (6.2) and the link from `seq` 1 to the
attester's enrollment record arrive with endpoint enrollment. Until then an
endpoint statement has no `tenant` field and `seq` 1 carries `prev` = 64
zeros. Such a statement is verified on its own (schema, a signature by the
enrolled device key, the chain and nonce rules of section 8) by the ingest
server that holds the device's key. It cannot be bound to a firm, so it never
appears in a Proof Pack, and pack verifiers refuse it (`enrollment` step).
The enrollment change adds `tenant` as a required field.

**`schedule`.** The agent backs off on battery and under load, so it says
in each statement what it is doing:

| Field | Type |
|---|---|
| `interval_s` | integer 60 to 3600: how long the agent plans to wait before its next heartbeat |
| `deferred_s` | integer 0 to 3600: how long this heartbeat was put off because the computer was busy |
| `heavy_checks_skipped` | boolean: slow checks were skipped this time to save battery; they report `unknown` |

A receiver judges silence against the `interval_s` the previous statement
announced (allowing for the next statement's `deferred_s`), so a laptop
that lengthens its interval on battery is not reported as missing
heartbeats. `interval_s` is capped, so an agent cannot announce a long
silence in advance.

**`protection`.** Integers use `-1` for "unknown or not applicable". Each
multi-value check has a `state` (`ok`, `unknown`, `not_applicable`). A check
that did not run claims no values: when `state` is not `ok`, its counts are
`-1`, its toggles are `unknown`, and `edr` has no `agents` field. The schema
expresses this with a switch on `state`.

| Field | Type |
|---|---|
| `security_center` | `state`; `products`, `enabled`, `up_to_date`: integers 0 to 32 when `ok` (`enabled`, `up_to_date` ≤ `products`), else `-1` |
| `defender` | `state`; `am_service`, `antivirus`, `real_time_protection`, `behavior_monitor`, `tamper_protection`: enum `on`, `off`, `unknown` (only `unknown` when not `ok`); `signature_age_days`: integer −1 to 65535 (−1 when not `ok`); `running_mode`: enum `normal`, `passive`, `edr_block`, `sxs_passive`, `unknown` (only `unknown` when not `ok`) |
| `edr` | `state`; when `ok`, `agents`: result list (6.1, at most 8 items) of `{vendor, running}`, sorted and unique by `vendor` |
| `edr.agents.items[].vendor` | enum `bitdefender`, `carbon_black`, `cortex_xdr`, `crowdstrike`, `eset`, `huntress`, `malwarebytes`, `microsoft_defender_endpoint`, `sentinelone`, `sophos`, `symantec`, `trend_micro`, `webroot` |
| `edr.agents.items[].running` | boolean |
| `bitlocker_os_volume` | enum `on`, `off`, `not_applicable`, `unknown` |
| `firewall_profiles_on` | integer −1 to 3 |
| `vulnerable_driver_blocklist` | enum `on`, `off`, `default` (registry value absent: Windows' own default applies), `unknown` |
| `memory_integrity` | enum `on`, `off`, `unknown` |

`edr.agents` lists each known EDR or antivirus agent found installed, one
record per vendor, never a service or process name; `total` is the number of
vendors found. If more are found than fit, agents that are **not** running
are kept first (they are the alarm), then the rest by vendor name, and
`truncated` is `true`.

**`tripwire`.** The agent watches a bounded set of folders (each user's
Desktop and Documents and any configured data folders, at most 32) for the
file activity ransomware causes. It is read-only: it receives the operating
system's change notifications, counts them in a sliding window and never
opens, reads, hashes or creates a file. `state` is `ok` (watching),
`unknown` (it could not watch) or `not_applicable`; a tripwire that is not
watching claims nothing else. When `ok`:

| Field | Type |
|---|---|
| `triggered` | boolean: the tripwire fired since the last statement the ingest server accepted (below) |
| `reason` | enum `none`, `mass_extension_change`, `ransom_notes`; `none` exactly when `triggered` is false |
| `window` | enum `10s`, `30s`, `60s`, `120s`, `300s`: the sliding window |
| `folders_watched` | integer 0 to 32 |
| `renamed`, `extension_changed`, `modified`, `deleted`, `suspicious_created`, `unknown_activity` | bucket enum `0`, `1_9`, `10_99`, `100_999`, `1000_plus` |

The buckets count the changes in the window that tripped (when `triggered`)
or in the busiest window since the last accepted statement. `renamed` counts all
renames and `extension_changed` the renames to a different extension
(temporary-file renames excluded); `suspicious_created` counts files created
with a ransom-note or random-looking name; `unknown_activity` counts
notification-buffer overflows, when changes came too fast to count. A
statement never carries a path, a file name, an extension or a process name,
and counts are bucketed so it does not show how much a person works.

When the tripwire fires the agent sends a statement at once, between its
scheduled heartbeats (at most one such statement per cooldown, ten minutes by
default); later trips are reported in the next heartbeat.

A trip (and the busiest window) counts as reported only once the ingest
server has accepted a statement carrying it, delivered while still inside
the clock window of section 8. Until then every new statement carries it
again, so one lost or late upload cannot hide it. A receiver can therefore
see the same trip in more than one statement (for example when an upload
arrived but its answer was lost) and treats them as one episode.

## 7. Envelopes

Statements travel in [DSSE v1](https://github.com/secure-systems-lab/dsse)
envelopes with `payloadType` `application/vnd.in-toto+json`:

```json
{"payload":"<base64 statement bytes>","payloadType":"application/vnd.in-toto+json",
 "signatures":[{"keyid":"<key ID>","sig":"<base64 64-byte signature>"}]}
```

Signatures are over `PAE(type, body) = "DSSEv1" SP len(type) SP type SP
len(body) SP body` (lengths in ASCII decimal). The payload must be canonical
JSON. Envelopes are stored and hashed in canonical JSON. Posture statements
and tenant genesis have exactly one signature; attester enrollments exactly
two (tenant, then attester).

## 8. Chains, nonces and replay

* **Sequence.** Each attester numbers its reports 1, 2, 3, … per tenant. A
  number is spent once signed, even if the upload fails.
* **Lost reports.** A report that is signed but never reaches the log (the
  upload failed for good, the attester's queue dropped it, or ingest refused
  it) leaves a hole in the numbering. Ingest accepts the next report anyway
  and records the hole as a **lost-report gap**, so one lost upload cannot
  stop a device from ever reporting again. Verifiers disclose every hole
  (section 13); offline, a report that never reached the log and a report
  left out of a pack look the same, so both are disclosed, neither hidden.
* **Hash chain.** `prev` is SHA-256 of the previous report's exact payload
  bytes; report 1 points at the enrollment payload. Deleting, reordering or
  inserting a report breaks the chain. Across a hole, `prev` names a report
  the checker never saw and cannot be checked; the next contiguous pair is
  checked again.
* **Server nonce.** Before each report the attester asks the ingest server
  for a 128-bit nonce, issued for that attester and used once. The server
  refuses unknown, reused, expired (older than 10 minutes) or misdirected
  nonces, and statements whose `observed_at` is more than 5 minutes from its
  clock. Offline, verifiers check that no nonce appears twice in a pack.
* **Offline periods are gaps.** Because of the nonce and the clock window,
  an attester that cannot reach the ingest server makes no report at all;
  the silence shows as a gap (section 13). Nothing is signed offline for
  later upload (see section 18 for a possible lower-strength offline
  record).

## 9. The log

The log is a public, append-only Merkle tree of **commitments**:

* **Entry digest** = SHA-256(canonical envelope bytes). This is the leaf data
  (32 bytes), and also the imprint timestamp authorities sign.
* **Tree hashing** is RFC 6962 / RFC 9162: leaf hash SHA-256(0x00 ‖ digest),
  node hash SHA-256(0x01 ‖ left ‖ right). Inclusion and consistency proofs
  are RFC 9162 §2.1.3 and §2.1.4.
* **Checkpoints** follow [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint)
  and [c2sp.org/signed-note](https://c2sp.org/signed-note): body
  `<origin>\n<size>\n<base64 root>\n`, no extension lines, signed with the
  log's Ed25519 key (key name = origin; key ID SHA-256(name ‖ 0x0A ‖ 0x01 ‖
  key)[:4]; signature line `— <name> <base64(keyID ‖ sig)>`).
* **Publication** is static files in the
  [c2sp.org/tlog-tiles](https://c2sp.org/tlog-tiles) layout: `checkpoint`,
  hash tiles `tile/<L>/<N>[.p/<W>]` and entry bundles
  `tile/entries/<N>[.p/<W>]`, each entry a big-endian uint16 length (32) and
  the digest. These files are everything the public sees.
* **Ingest checks** (before anything is logged): canonical, schema-valid
  statement; a known, matching enrollment; valid signature(s); fresh unused
  nonce; `seq` greater than the last accepted one; `prev` matching when
  `seq` is exactly one more; clock within ±5 minutes. Then two timestamps are
  requested and the digest is appended. A `seq` more than one ahead is
  accepted and its hole recorded as a lost-report gap (section 8); a `seq` at
  or below the last is a replay and refused.
* **Evidence.** The envelope, its timestamp tokens and its leaf index form
  the private evidence record, kept by the server (encrypted at rest in
  production) and by the firm's app.

## 10. Witnesses and timestamps

**Witnesses** ([c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature))
keep the last tree head they cosigned for each log and cosign a new
checkpoint only if the log proves consistency from it. A cosignature signs
`cosignature/v1\ntime <unix seconds>\n<checkpoint body>` with Ed25519; key ID
uses type byte 0x04; the line is `— <name> <base64(keyID ‖ 8-byte BE time ‖
sig)>`. Verifiers require a quorum of distinct trusted witnesses.

**Timestamp tokens.** Each log entry gets tokens from at least two independent
authorities over the entry digest. Production uses RFC 3161 (for example
Sigstore's timestamp-authority and a commercial TSA): `{"kind":"rfc3161",
"token":"<base64 DER TimeStampToken>"}`. This prototype uses only simulated
authorities:

```json
{"kind":"simulated-tsa/v1","sig":"<base64>",
 "tst":{"gen_time":"2026-10-14T14:05:23Z","imprint":"<hex entry digest>","serial":1792…,"tsa":"tsa-a.example"}}
```

`sig` is Ed25519 over `simulated-tsa/v1\n` ‖ canonical(`tst`). The verifier
dispatches on `kind`; adding RFC 3161 means one new branch (CMS SignedData
verification against pinned TSA certificates) and nothing else.

## 11. Proof Packs

### 11.1 Format (`proof-pack/v1`)

```json
{
 "pack_type": "proof-pack/v1",
 "canonicalization": "strict-json-c14n/v1",
 "product": "Kovyr Proof",
 "sample": true,
 "issued_at": "2026-10-31T06:05:00Z",
 "range": {"from": "2026-10-01", "to": "2026-10-30"},
 "tenant": {"display_name": "...", "display_name_salt": "<64 hex>", "id": "tnt_..."},
 "log": {"checkpoint": "<signed note with cosignatures>",
         "earlier_checkpoints": [{"checkpoint": "<note>", "consistency_proof": ["<base64>", ...]}],
         "origin": "<log origin>"},
 "entries": [{"envelope": {...}, "inclusion_proof": ["<base64>", ...], "index": 123, "timestamps": [{...}, {...}]}],
 "summary": {"coverage": {...}, "gaps": [...], "lapses": [...]}
}
```

* `entries`: the firm's tenant genesis, every attester enrollment, and every
  posture statement whose `observed_at` falls in the range, each with its log
  index, timestamp tokens and an inclusion proof against `log.checkpoint`.
* `earlier_checkpoints`: checkpoints the firm's app (or the recipient) saved
  before, with consistency proofs to the current one.
* `product` and `sample` are display hints. `sample: true` means demo data.
* The pack is shared privately by the firm. It is the only place the full
  statements appear outside the firm's app and the ingest server.

### 11.2 Firm name commitment

The name is never in a statement. Genesis carries
`display_name_commitment = hex(SHA-256("tenant-name-commitment/v1\n" ‖ salt
‖ "\n" ‖ UTF-8 name))` with a random 32-byte salt (as 64 hex). The pack
reveals the name and salt; verifiers recompute the commitment.

### 11.3 Summary

The owner-facing claims, recomputed by every verifier from the evidence and
required to match exactly (canonical JSON equality):

* `coverage`: from the latest valid connector report in range:
  `devices_known`, `devices_enrolled`, `devices_unknown_seen`,
  `accounts_total`, `accounts_mfa`, `accounts_passkey`; plus
  `connector_reports` (count) and `device_enrollments` (enrolled device agents
  in the pack).
* `gaps`: `[{attester, attester_kind, device_number, from, to, days}]`.
* `lost_reports`: `[{attester, attester_kind, device_number, first_seq,
  last_seq, count, next_report}]`, one per hole in an attester's numbering
  between two evidence reports: the missing numbers, how many, and the date
  of the report after the hole. Sorted by attester, then `first_seq`. The key
  is present only when the list is not empty, so a summary without lost
  reports is unchanged from earlier versions.
* `lapses`: `[{attester, date, seq, checks}]`, where `checks` is the sorted
  list of failing checks in one valid report: `disk_encryption` (not `on`),
  `edr_running`, `firewall`, `screen_lock`, `os_patch` (`out_of_date` or
  `unsupported_os`), `remote_tools` (total > 0), `mfa`, `mailbox_alert_open`,
  `unknown_device`, `devices_not_enrolled`, `external_check_failed` (any scan
  result `fail`), `payment_not_verified`, `restore_drill_failed`.

## 12. Trust policy (`proof-trust-policy/v1`)

```json
{"policy_type":"proof-trust-policy/v1","demo_only":true,
 "log":{"origin":"...","vkey":"<name>+<id>+<base64(0x01||key)>"},
 "witnesses":[{"name":"...","vkey":"<name>+<id>+<base64(0x04||key)>","label":"...","simulated":true}],
 "witness_quorum":2,
 "timestamp_authorities":[{"name":"...","kind":"simulated-tsa/v1","public_key":"<SPKI>","label":"...","simulated":true}],
 "timestamp_quorum":2,
 "limits":{"max_report_delay_s":900,"max_clock_skew_s":300,"max_tsa_spread_s":300}}
```

The verifier pins this; a pack never supplies its own roots. A policy must
require at least one witness and at least two timestamp authorities.

## 13. Verification

Verification is offline and never stops early: all ten steps run, so a
tampered pack shows every check it breaks. Step IDs and order are shared by
all implementations.

| # | ID | Passes when |
|---|---|---|
| 1 | `signatures` | Genesis is signed by its own tenant key; each enrollment is signed by the pack's tenant key then by the enrolled key; each posture statement has exactly one signature, by the key enrolled for its attester, valid over the PAE. |
| 2 | `content` | Every payload is canonical, has an accepted predicate type, and obeys the schema (section 6). |
| 3 | `enrollment` | Exactly one genesis, for the pack's tenant; tenant ID derived from its key; name commitment matches; each attester ID derived from its key and kind; enrollments after genesis; every posture statement from an attester enrolled in this pack (same tenant and kind, enrolled earlier in the log and in time); no endpoint statement without a tenant (6.5); the pack holds at least as many device enrollments as the latest connector report says are enrolled. |
| 4 | `sequence` | No nonce appears twice (an identical payload logged twice is a replay); per attester, no sequence number appears twice, each `prev` matches the previous payload where that report is present (or the enrollment for `seq` 1), and order agrees with log index and time. A hole in the numbering is a lost-report gap: it makes this step a **warning** (not a failure) and is disclosed in the summary's `lost_reports`. |
| 5 | `timestamps` | Each entry has valid tokens from at least `timestamp_quorum` distinct trusted authorities over its entry digest, agreeing within `max_tsa_spread_s`; the earliest token time is no more than `max_report_delay_s` after the claimed time (`observed_at` or `enrolled_at`) and no more than `max_clock_skew_s` before it. |
| 6 | `inclusion` | Each entry's leaf (from its envelope) is proven in the checkpoint's tree at its index; no two entries share an index. |
| 7 | `checkpoint` | The checkpoint parses, its origin is the trusted log's, and the trusted log key signed it. |
| 8 | `consistency` | Each earlier checkpoint is signed by the log, no larger than today's, and proven consistent with it. With no earlier checkpoint the step is a **warning**, not a pass. |
| 9 | `witnesses` | At least `witness_quorum` distinct trusted witnesses cosigned this exact checkpoint. |
| 10 | `gaps` | The pack's `summary` equals the summary recomputed from the evidence. |

**Evidence** for step 10 is posture statements that individually passed steps
1, 3, 5 and 6, dated (UTC) within the range. **Gaps**: for each enrolled
attester that must report daily (`device_agent`, `cloud_connector`,
`external_scanner`), every range day after its enrollment day without a
valid report; consecutive days form one gap. Staff attesters report on events
and have no gaps. **Lost reports**: for each attester, every hole in the
sequence numbers between two consecutive evidence reports. A gap is not a
failure: a pack verifies with gaps and lost reports disclosed.

The pack **verifies** when no step fails.

## 14. Evidence strength

| Level | Meaning | In this prototype |
|---|---|---|
| Hardware | Signed by a key locked in the device's TPM 2.0 or Secure Enclave, with the chip maker's attestation chain verified. | Never granted: device keys are software keys and attestation chains are not verified yet. |
| Platform | Read from Microsoft 365's own APIs by the read-only cloud connector. Trusts the vendor's connector to report what the API said. | Yes |
| Scan-verified | Checked from outside against the firm's own domain by the vendor's scanner. Trusts the scanner. | Yes |
| Staff-attested | A person's signed, time-stamped record (a call-back, a restore drill). A person's word, not a machine check. | Yes |
| Software | Signed by a software key on the device. Anyone with admin rights on that device could take the key. | All device facts |

## 15. What a Proof Pack proves and does not prove

**It proves**, for the listed range:

* each report came from a key enrolled for this firm, and was not changed
  after it was signed;
* when each report was made, within minutes, by two independent clocks (so
  it was not backdated);
* no report was removed, replayed, reordered or inserted, and days with no
  report are disclosed as gaps;
* the log holding the reports was not rewritten since checkpoints the firm
  or a quorum of independent witnesses saw;
* how many of the devices Microsoft 365 knows about are enrolled (for
  example "12 of 12 known devices enrolled; 0 unknown devices seen").

**It does not prove:**

* that the firm cannot be breached, or that a protection was effective, only
  that it was measurably on;
* anything about devices that are not enrolled ("enrollment completeness" is
  only as good as the platform's device list), or about days outside the
  range;
* that a compromised device told the truth. Hardware keys raise the bar; a
  software key can be stolen by someone with admin rights on that device;
* whether a lost report never reached the log or was left out of the pack:
  both show as the same disclosed hole in the device's numbering (section
  18 describes how signed delivery receipts could tell them apart);
* that staff-attested events happened as recorded;
* the firm's legal identity: the name is bound at onboarding, outside this
  protocol;
* in this prototype: timestamps and witnesses are simulated with local keys.

## 16. Threat model

| Attack | In plain words | Defense | Caught by |
|---|---|---|---|
| Wrong device or tenant | "Who says this came from that firm's laptops?" | Keys come from enrollment records signed by the firm's key plus proof of possession, in the log. Production: TPM or Secure Enclave keys with the maker's attestation. | `enrollment`, `signatures` |
| Edited report | Flip "encryption off" to "on" | Signature over the exact payload; chain hash; entry digest in TSA tokens and the log | `signatures`, `sequence`, `timestamps`, `inclusion`, `gaps` |
| Replay | Re-send last spring's all-green report | One-time server nonce, sequence numbers, chain hash; TSA time | `sequence`, `timestamps` (and ingest) |
| Backdating | Set the clock back to fill a gap | Two independent TSA tokens over the entry digest; ingest clock check | `timestamps` |
| Quiet erasure (firm) | Delete the bad day from the pack | Hash chain and sequence: the hole is disclosed as lost reports, and as a gap if the day has no other report; summary recomputed. Disclosed, no longer a failure, since lost uploads are accepted (section 8) | `sequence` (warning), `gaps` |
| Lost upload | One heartbeat never arrives; strict numbering would lock the device out for good | Ingest accepts the next report and records the hole; verifiers disclose it | `sequence` (warning), `gaps` |
| Quiet erasure (vendor) | Delete the bad day from the log and re-sign | The device's hash chain (the hole is disclosed); the firm's saved checkpoints; witnesses refuse inconsistent checkpoints | `sequence` (warning), `consistency`, `witnesses` |
| Split view (cheating vendor) | Show the insurer a different history from the owner | A quorum of independent witnesses must cosign the same tree | `witnesses` |
| Hidden gap or lapse | Edit the one-page summary | Summary recomputed from evidence | `gaps` |
| Omitted device | Enroll or pack only the good laptops | Connector's enrolled count must be covered; coverage against the platform's known devices is disclosed | `enrollment` (count), disclosure |
| Data leak through statements | An agent bug sends file names or host names | Typed builders with no string inputs; schema validation everywhere; structural tests | builder, `content`, ingest |
| Public log as a target list | Read "firm X has MFA off" from the log | Leaves are salted commitments; no names or IDs in public files | design (tests assert it) |
| Signature malleability | A second valid encoding of a signed report | Low-S ES256, 64-byte signatures only, canonical everything | `signatures` |
| Parser differential | A file read differently by two verifiers | Strict JSON (no duplicates, no floats), canonical bytes, shared vectors | `content`, parsing |
| Forged trust roots | A pack carrying its own "witness" keys | Trust policy pinned by the verifier, never read from the pack | all log steps |
| Compromised ingest server | Accepts replays or backdated reports | Every ingest check is re-done offline by verifiers | `sequence`, `timestamps` |
| Stolen device key | Sign fake reports as that device | Hardware-bound keys (production); a key cannot be in two places, so a fork shows as duplicate sequence numbers | partly: `sequence` (equivocation) |
| Lost device state | Delete the agent's state to start a fresh history | A new key is a new enrollment, visible in the pack, and the old device shows gaps; the server should alert on a new device that replaces a silent one (not built yet) | disclosure |

## 17. Privacy

* **The public log holds only fingerprints.** Its files are a signed
  checkpoint and 32-byte SHA-256 digests of salted statements. No firm name,
  tenant or device ID, posture value or timing of an individual firm can be
  read from them (tests in Go and Python assert this on the published tiles).
* **Results stay private until shared.** Full statements exist in the firm's
  app, in the ingest server's evidence store, and in Proof Packs the firm
  chooses to share.
* **The vendor sees statements at ingest.** The server validates each report
  before logging it, so it sees the yes/no answers and counts (never file
  names or content: the content rule applies here too). A future mode can
  have devices log commitments directly and send evidence only to the firm,
  at the cost of server-side validation.
* **Identifiers are pseudonymous** (key fingerprints), and only appear inside
  statements, never in public files.

**Selective disclosure (future work).** Today a pack reveals whole
statements. Per-field salted commitments in the style of SD-JWT (each field
replaced by the hash of a salt, its name and value, with the salts disclosed
only for chosen fields) would let an owner show an insurer "encryption on 12
of 12" and nothing else, while the signature and log proofs still hold. The
canonical form and schema are designed so that this can be added as a new
predicate version.

## 18. Other future work

* **Offline records backed by the TPM clock.** Today an offline device makes
  no report, and the silence is a gap (section 8). A device with a TPM could
  sign records while offline, each bound to the TPM's monotonic clock and
  reset counter (a TPM2_Quote or a signed TPM2_GetTime), and upload them
  later. Without a server nonce or timestamps from the time they were made,
  such records prove less than a live report: they would form a separate,
  lower evidence strength (for example *offline, TPM-clocked*), be shown as
  such, and never close a gap by themselves.
* **Decoy files.** A tripwire could also plant decoy files ("canaries") in
  the watched folders and alarm when one is touched, which catches
  ransomware sooner and with fewer false alarms. It means creating files on
  the customer's machine, which the read-only rule forbids; it needs its own
  decision.
* **Signed delivery receipts.** Each report could carry the highest `seq`
  the ingest server acknowledged. A verifier could then tell a report that
  never reached the log (disclosed as lost) from one the log holds but a
  pack left out (a failure), which section 8 cannot do today.
* Verify TPM 2.0 key attestation and Apple Managed Device Attestation, then
  grant *hardware* strength.
* RFC 3161 timestamp tokens; real independent witnesses speaking the
  [tlog-witness](https://c2sp.org/tlog-witness) protocol.
* Key rotation and revocation records; device retirement.
* Issue packs as W3C Verifiable Credentials.

## 19. Test vectors

`proof/testdata/vectors/` (regenerate with
`go test ./proof/internal/vectors -run TestVectorsAreUpToDate -update`; Go
tests fail if they drift; keys derive from fixed seeds and all signatures
are deterministic): `canonicalization.json`, `dsse.json`, `merkle.json`,
`note.json`, `statement.json` (posture, scan and endpoint statements),
`mini-pack.json` with `mini-trust-policy.json` and
`mini-pack-expected.json`, and `posture-schema.json`. See the README in that
folder. The Go implementation passes them all; the Python and JavaScript
implementations passed them as of the import and do not yet know the
endpoint vectors or lost-report gaps.
