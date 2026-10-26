# Proof engine specification

Version: prototype, October 2026. Status: draft for review.

This document is language-neutral. It specifies the bytes: statements,
envelopes, the log, checkpoints, witness cosignatures, timestamps, Proof
Packs, trust policies and the verification algorithm. Three implementations
follow it and agree on the shared test vectors:

| Implementation | Location | Role |
|---|---|---|
| Go | `engine/` (`proofctl`) | library for the future endpoint agent, demo generator, offline verifier CLI |
| Python | `engine/python/` (`proofengine`) | server side: statement building, ingest, log, witnesses, pack build and verify |
| JavaScript | `demo/verifier/` | the in-browser verifier (WebCrypto only, no third-party code) |

Normative data files: `engine/testdata/vectors/posture-schema.json` (the
statement schema, generated from `engine/posture/schema.go`) and the test
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
| Demo log origin | `kovyr.com/proof/demo-log` | `brand.DemoLogOrigin` | n/a | `BRAND.logOrigin` |

To rename: edit `engine/brand/brand.go` and `engine/python/proofengine/brand.py`,
then regenerate (`proofctl demo generate`, `proofctl vectors`,
`python3 -I sync_schema.py`). Statements embed the predicate type and
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
 "predicateType":"<posture or enrollment predicate type>",
 "subject":[{"digest":{"sha256":"<key ID of the attester (or tenant)>"},"name":"<attester or tenant ID>"}]}
```

Exactly one subject: the key-holder the statement is about. Its `name` is the
attester ID (posture) or the enrolled tenant or attester ID (enrollment), and
its digest is that key's key ID.

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
| `results.items[].check_id` | enum of stable IDs: `EMAIL-01` … `EMAIL-05`, `TLS-01` … `TLS-03`, `HTTP-01` … `HTTP-03`, `DNS-01`, `BREACH-01`, `BREACH-02`. IDs are never reused; new checks get new IDs. |
| `results.items[].status` | enum `pass`, `warn`, `fail`, `error`, `not_applicable` |
| `results.items[].severity` | enum `info`, `low`, `medium`, `high`, `critical` |

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
sections of the posture predicate for `attester_kind` `device_agent`, or a new
predicate type `.../endpoint/v1`; they are not accepted by today's verifiers.

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
* **Hash chain.** `prev` is SHA-256 of the previous report's exact payload
  bytes; report 1 points at the enrollment payload. Deleting, reordering or
  inserting a report breaks the chain.
* **Server nonce.** Before each report the attester asks the ingest server
  for a 128-bit nonce, issued for that attester and used once. The server
  refuses unknown, reused, expired (older than 10 minutes) or misdirected
  nonces, and statements whose `observed_at` is more than 5 minutes from its
  clock. Offline, verifiers check that no nonce appears twice in a pack.

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
  nonce; `seq` exactly one more than the last; `prev` matching; clock within
  ±5 minutes. Then two timestamps are requested and the digest is appended.
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
| 3 | `enrollment` | Exactly one genesis, for the pack's tenant; tenant ID derived from its key; name commitment matches; each attester ID derived from its key and kind; enrollments after genesis; every posture statement from an attester enrolled in this pack (same tenant and kind, enrolled earlier in the log and in time); the pack holds at least as many device enrollments as the latest connector report says are enrolled. |
| 4 | `sequence` | No nonce appears twice (an identical payload logged twice is a replay); per attester, sequence numbers are contiguous with no duplicates, each `prev` matches the previous payload (or the enrollment for `seq` 1), and order agrees with log index and time. |
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
and have no gaps. A gap is not a failure: a pack verifies with gaps disclosed.

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
| Quiet erasure (firm) | Delete the bad day from the pack | Hash chain and sequence; summary recomputed | `sequence`, `gaps` |
| Quiet erasure (vendor) | Delete the bad day from the log and re-sign | The device's hash chain; the firm's saved checkpoints; witnesses refuse inconsistent checkpoints | `sequence`, `consistency`, `witnesses` |
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

* Verify TPM 2.0 key attestation and Apple Managed Device Attestation, then
  grant *hardware* strength.
* RFC 3161 timestamp tokens; real independent witnesses speaking the
  [tlog-witness](https://c2sp.org/tlog-witness) protocol.
* Key rotation and revocation records; device retirement.
* Issue packs as W3C Verifiable Credentials.

## 19. Test vectors

`engine/testdata/vectors/` (regenerate with `proofctl vectors`; Go tests fail
if they drift; keys derive from fixed seeds and all signatures are
deterministic): `canonicalization.json`, `dsse.json`, `merkle.json`,
`note.json`, `statement.json`, `mini-pack.json` with
`mini-trust-policy.json` and `mini-pack-expected.json`, and
`posture-schema.json`. See the README in that folder. The Go, Python and
JavaScript implementations all pass them.
