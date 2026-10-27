# The signed updater: design for review

Status: **draft for review** (roadmap Ticket 7). This page is the design
only. There is no updater code yet, and none should be written until this
page is reviewed.

The build rules (CLAUDE.md section 2) say: "Updates are a code-execution
channel. Agent updates must be signed and verified against a pinned key
before they run, rolled out in stages, and able to roll back." This page
proposes how to do that, and says plainly what it does not protect against.
The facts checked on the web while writing are linked under "Sources" at the
end. Claims marked *(unverified)* still need checking.

## In plain English

### What it does

A second, small Kovyr service runs on each computer: the **updater**. A
few times a day it asks Kovyr's server whether a newer Protection Alarm
exists. When there is one, and it is this computer's turn, the updater:

1. downloads it from the same server the heartbeats go to;
2. checks two signatures. The first is Kovyr's own update signature, made
   with a key that lives on a hardware token in the founder's hands and
   never on a server. The second is the Windows publisher signature
   (Authenticode);
3. puts the new version in its own folder next to the current one, which
   it keeps;
4. tells the Windows service manager to run the new version instead of the
   old one;
5. watches the new version for a while. It switches back to the previous
   version by itself if the new one does not start, keeps crashing, has
   its heartbeats refused, or uses far more processor or memory than the
   budget allows.

New versions reach computers gradually: the founder's own machines first,
a few early customers a day later, then everyone else over the following
days. The agents enforce that pace themselves, whatever the server says.
When halden sees a new version being rolled back, it stops offering that
version and emails the founder.

### Why it is safe

* **The server cannot give orders.** It can offer files, and the updater
  accepts only files signed by Kovyr's offline keys. A hacked server, CDN
  or domain can at worst hold updates back. It cannot install anything.
* **The keys that matter are not online.** The keys that approve a
  release, and the keys that decide which release keys to trust, sit on
  hardware tokens that need a PIN and a touch. No server, CI system or
  GitHub account holds them.
* **Two independent signatures.** An attacker needs both Kovyr's release
  key and Kovyr's Windows publisher identity. These are held in different
  places and by different companies' systems.
* **No going back.** Agents refuse older versions and older update
  documents, so an old file can't be replayed to reopen a fixed hole.
* **Nothing but the agent is ever run.** No scripts, installers or
  commands. The only thing the updater can do is switch the Kovyr service
  between two Kovyr-signed copies of the agent, through the Windows
  service manager. Neither program contains code that starts a process.
* **A bad release stops itself.** Three things limit how many computers a
  bad release reaches: the gradual pace, automatic rollback on each
  computer, and an automatic halt on the server. None of them needs anyone
  to react within hours.

### What it costs the founder to run

| | |
|---|---|
| One time | Five hardware security keys (YubiKey 5 or similar, roughly $50 to $100 each *(unverified)*); one offline key ceremony, about 2 hours |
| Every month | A Windows code-signing service. Azure Artifact Signing has a Basic tier with a monthly fee; its price did not load when checked *(unverified)* |
| Each release | 30 to 45 minutes: review the changes, check the rebuild, sign with the hardware key (PIN and touch), upload |
| A month with no release | 5 minutes to re-sign the current release so it does not expire |
| Once a year | 1 to 2 hours: re-sign the root document offline and check that every key still works |
| On-call | None. If the founder does nothing, computers stay on the version they have |
| Bandwidth | About 6 MB per computer per release. Today's agent is 10.7 MB, or 5.9 MB compressed (measured at this commit) |

### What it will never do

The updater never:

* runs a script, a command, an installer or any program other than the
  Kovyr agent;
* installs other software;
* changes any Windows setting except which copy of the agent the Kovyr
  service runs;
* restarts the computer;
* touches customer files;
* accepts anything that is not signed by Kovyr's offline-held keys;
* sends anything to the server.

---

## 1. Scope

**In scope:** the agent's own binary on Windows (amd64 now, arm64 later).
Later, the same channel will carry the updater itself (section 7.8) and v1's
detection rule packs. Here a content change counts as a code change and
gets the same signatures and the same pace. Public post-incident reports
say the July 2024 CrowdStrike outage came from a content update that went to
every machine at once.

**Out of scope:** the first install (the MSI, a Ticket 3 follow-up), macOS,
and anything that changes settings on the machine. Response actions stay a
v2 decision.

## 2. Threat model

### 2.1 What we protect

* **Customers' computers.** The update channel can run code as SYSTEM on
  every enrolled computer of every customer. It is the most dangerous
  thing Kovyr will operate.
* **The alarm.** A broken update silences the alarm. Someone must notice
  it, and it must be undone.
* **The office's work.** Updating must never slow down or lock a
  computer, during tax season or at any other time.

### 2.2 Threats and verdicts

Verdicts: **Stopped** (the attack fails), **Bounded** (it succeeds only in
part, for a limited time or on a limited number of computers), **Detected**
(someone gets told), **Not stopped**.

| Threat | What the attacker tries | Defense | Verdict |
|---|---|---|---|
| Compromised update server or CDN (halden, its hosting or storage) | Serve a malicious binary or document | Every document must be signed by keys the server never holds; binaries must match the signed SHA-256 and length, and carry Kovyr's Authenticode signature | Install: **Stopped**. Withholding updates: see "Freeze" |
| DNS hijack or hostile network with a valid TLS certificate (an attacker who controls DNS can get one) | Same as above, from a look-alike server | Same: TLS is only transport, and trust comes from the signatures. Heartbeats also go to the attacker, so halden sees every device go silent | **Stopped** (install); **Detected** (silence) |
| Stolen release key, alone | Sign a malicious release | The binary also needs Kovyr's Authenticode identity, pinned by subject in the root document | **Stopped** |
| Stolen release key **and** Authenticode identity, plus a way to serve files | Ship malware as a release | The agents' own pace (founder's machines first, everyone after a week); halden alerts on any release number or version the founder never published; root rotation revokes the key; halden auto-halt | **Bounded** and **Detected**, not stopped. One customer singled out through its own network path: **Not stopped** until release transparency (Ticket U8) |
| Stolen root keys (a threshold of them) | Replace every trusted key | Offline, threshold 2 of 3, PIN-locked hardware, used about once a year | **Not stopped.** Recovery means reinstalling on every computer |
| Stolen Authenticode identity, alone | Ship an update | Cannot: no release signature. It could sign look-alike malware for phishing, so revoke it with Microsoft or the CA | **Stopped** (for updates) |
| Malicious insider: a future contractor with GitHub, CI or hosting access | Ship code | No release key, so cannot | **Stopped** |
| Malicious insider: the founder (or a coerced founder) | Ship code | Review, reproducible builds and (later) a public release log make it detectable afterwards | **Not stopped** |
| Compromised GitHub account or CI | Change source, workflows or release assets | Cannot sign releases. The release ritual (section 10) shows the diff since the last signed release, rebuilds locally and compares, and checks the root embedded in the updater against the founder's offline copy | **Stopped** directly; **Bounded** if the founder signs a tampered build without noticing |
| Downgrade or rollback | Replay an old, validly signed release to bring back a fixed bug | The updater remembers the highest root version, release number and agent version it has seen, and refuses anything lower. Versions must strictly increase | **Stopped** (a local administrator can still downgrade: out of scope) |
| Freeze | Keep serving an old, valid document, or nothing, so a fix never arrives | Release documents expire after 45 days and root documents after a year. The heartbeat reports `stale`; halden alerts on devices that fall behind the current release | **Bounded** and **Detected**, not stopped: anyone who can block traffic can block updates |
| Mix and match | Combine a binary from one release with a document from another, or an old root with a new release | One release document lists every target by hash; roots form a signed chain; two different documents with the same release number are reported as equivocation | **Stopped** |
| Fast-forward | Use a stolen release key to sign release number 2^31-1, so legitimate releases look old | When a root changes the release keys, the stored release high-water mark resets (the TUF rule) | **Bounded** (until the next root ceremony) |
| Endless data, slow retrieval | Feed a huge or very slow download to fill the disk or hold the updater | Size caps on every document and binary, the length from the signed document, deadlines on every request | **Stopped** |
| Kaseya/ScreenConnect-style "one compromise reaches every customer" | Take over the vendor's server and push code to every agent | Section 2.3 | **Bounded**. Only a root key compromise reaches everyone at once |
| Legitimate but broken release (the CrowdStrike case) | (No attacker) A release crashes or silences agents | Pace, per-computer health checks with automatic rollback, halden's automatic halt | **Bounded** |
| Local user without admin rights | Swap the staged file, or plant a DLL next to the binary | Everything lives in folders only SYSTEM and Administrators can write. Files are verified at their final location through a handle that blocks writes. Windows DLLs load from the system folder only (`NewLazySystemDLL`, as the agent does today) | **Stopped** |
| The updater used as an attacker's tool ("living off the land") | Use Kovyr's signed updater to download and run the attacker's file | It has no flag or command to install a given URL or file; it installs only release-signed agent binaries chained to the embedded root | **Stopped** |
| Bug in the updater's parsing | Exploit the updater with crafted bytes before the signature check | Small pre-signature surface: Go's TLS, the existing canonical-JSON and DSSE parsers, size caps. The payload is interpreted only after its signatures verify. Fuzzing (section 11) | **Bounded** |
| Clock manipulation on the computer | Accept expired documents | Needs admin rights. A clock running fast only blocks updates (safe); a slow clock re-opens freeze, nothing more | **Bounded** |
| The update channel turned into remote control | Use the documents to give orders | There is no command vocabulary: the schema is closed and its only meaning is "this signed binary is version X". The updater only sends GET requests | **Stopped** by design |

### 2.3 "One compromise reaches every customer"

Kaseya VSA (2021) and ScreenConnect (2024) show the pattern CLAUDE.md warns
about. A remote-management server exists to run scripts on every agent, so
whoever takes the server reaches every customer at once. This design
differs in four ways:

1. **There is no command channel at all.** halden holds no key that the
   agents obey. Taking halden yields fake dashboards and withheld updates,
   not code on customers' machines.
2. **The release key is offline and needs a human.** It sits on a hardware
   token with PIN and touch. Nobody can use it remotely, at scale, at
   3 a.m.
3. **Two independent signatures.** The release key and the Authenticode
   identity are separate secrets held in separate systems.
4. **The agents set the pace, not the signer.** Even a validly signed
   malicious release reaches only the canary computers on day one. It
   reaches the early ring after a day, and everyone else only after three
   days, spread over four more (section 8.2). Each step gives the founder,
   halden's alerts and (later) the public release log a chance to catch
   it.

What remains: someone holding the release key, the Authenticode identity
and a way to serve files reaches every customer within about a week unless
caught. Someone holding the root keys reaches everyone as fast as they like,
which is why root keys are offline, split and rarely used.

The Notepad++ incident (2025) is the other half of the lesson. Attackers who
took over its hosting redirected selected users' update requests to
malicious servers. The updater did not check the installer's signature
against the real publisher, so a forged update manifest was enough. Here,
every check is against keys pinned on the device, never against values the
server supplies.

### 2.4 What this design does not stop

* The founder signing a malicious or broken build, knowingly or not. Review,
  local rebuilds, the pace and rollback limit the damage; they do not
  prevent it.
* Someone holding the root keys.
* Someone holding the release key and the Authenticode identity, until
  caught. Against one customer singled out through its own network path,
  this holds until release transparency ships (U8).
* Freeze and denial of service: anyone who controls the network can stop
  updates. The design makes this visible; it can't prevent it.
* A local administrator, who can downgrade, replace or disable anything on
  their own computer. The silence and the version lag show at halden.
* Bugs in Windows, in Go's TLS and crypto, or in our verifier.
* Vulnerabilities in the installed version until the fix arrives, which
  takes up to a week under the pace rules.

## 3. Options and recommendation

### 3.1 The two ends

**A minimal pinned-key manifest.** One Ed25519 key is compiled into the
agent. A manifest `{version, sha256, length}` is signed with it. This is about
150 lines on the Go standard library, and the founder runs almost nothing.
But the pinned key is used every month from an everyday laptop, and it can't
be rotated or revoked without shipping a new binary signed by that same key.
If the key is stolen, the attacker can do exactly the same, so the only clean
recovery is reinstalling everywhere. There is no expiry (freeze), no
threshold, and no room for rollout rules without inventing them anyway.

**Full TUF** (The Update Framework). It has four roles: *root* (which keys
are trusted for each role, offline, threshold-signed), *targets* (which
files are valid), *snapshot* (which version of every metadata file is
current, so files cannot be mixed and matched) and *timestamp* (a short-lived
freshness signature from an online key, against freeze). It adds delegations,
consistent snapshots and a precise client workflow. It is a well-reviewed
design with independent implementations. The costs here are:

* Snapshot and timestamp metadata expire within days, so an online signing
  service must run around the clock. If it stops, every client sees expired
  metadata.
* Delegations and snapshots solve problems of repositories with many files
  and many publishers. Kovyr has one publisher and, per release, two or
  three files.
* TUF metadata is its own JSON format with its own canonicalization. That
  is a second format next to the proof spec, which CLAUDE.md section 4
  forbids.
* `go-tuf` v2 pulls in `go-securesystemslib`, `sigstore/sigstore` and
  their dependencies (seen in an older revision of its `go.mod`; the
  current v2.4.2 list is not checked). All of that code would run in a
  SYSTEM service. That is the kind of dependency the repo rules ask us to
  justify, and it replaces no risk the standard library cannot cover.

### 3.2 Recommendation: TUF's rules, the proof spec's format

Take the parts of TUF that matter for one publisher and a small fleet.
Write them in the format the agent already speaks, on the standard library
and the vendored proof engine:

* **Two roles, one document each.** A **root** document, signed offline
  with a threshold, names the trusted keys and pins the Authenticode
  publisher. A **release** document, signed by the release key, lists every
  target binary by hash and length with its version and rollout rules.
* **Snapshot is dropped.** One release document lists everything, so there
  is nothing to mix and match.
* **Timestamp is deferred.** The release document expires after 45 days.
  The heartbeat reports a stale updater, and halden alerts on version lag.
  An online freshness key can be added later through a root change if the
  fleet grows (open question 4).
* **Kept from TUF:** the root chain rules (each new root is signed by a
  threshold of the old root keys *and* of its own), version high-water
  marks, expiry, thresholds over distinct keys, resetting the high-water
  mark when keys rotate, and exact length and hash checks.
* **Added beyond TUF:** rings and an agent-enforced pace, health-gated
  rollback on each computer, a second independent signature (Authenticode),
  and, later, a witnessed public release log.
* **Format:** in-toto Statement v1 in DSSE envelopes, strict-json-c14n/v1,
  SPEC 4 keys and signatures. The vendored `proof/canon`, `proof/dsse` and
  `proof/sigs` already parse and verify these strictly and are tested in CI.
  The update predicates become a new SPEC section, and per CLAUDE.md section
  4 the SPEC changes first (Ticket U1).

| | Minimal pinned key | Full TUF (`go-tuf`) | Recommended |
|---|---|---|---|
| Rotate or revoke a key without reinstalling | No | Yes | Yes (root) |
| Key used monthly from a laptop can be revoked | No | Yes | Yes |
| Threshold signing | No | Yes | Root: 2 of 3 |
| Freeze defense | None | Timestamp role (online key, daily) | 45-day expiry, version-lag alerts |
| Rollback defense | Only if added | Yes | Yes |
| Mix and match | Not applicable (one file) | Snapshot role | One release document |
| Staged rollout, health rollback | Not included | Not included | Included |
| New dependencies | None | `go-tuf`, `go-securesystemslib`, `sigstore/sigstore`, ... | None |
| Format | New | TUF JSON (a second format) | The proof spec's |
| Online keys to keep running | None | Timestamp and snapshot | None |
| Founder's routine work | Lowest | Highest | Per release, monthly re-sign, yearly ceremony |
| Main risk | One stolen key ends it | Operations and dependency weight | A hand-written verifier: this review, TUF's known bug classes as tests, fuzzing, mutation checks |

The honest cost of the recommendation is that Kovyr writes its own verifier.
It stays small (an estimated 600 to 900 lines, with no OS or network access
in the verification code). It follows TUF's client workflow step by step.
Its tests encode the bugs TUF implementations have had over the years:
counting the same key twice toward a threshold, trusting a key ID without
checking it names the key, accepting a new root signed only by its own keys,
and keeping a high-water mark across a key rotation.

### 3.3 Keys

| Key | Signs | Where it lives | Used | If lost | If stolen |
|---|---|---|---|---|---|
| **Root A, B, C** (threshold 2 of 3) | The root document: which keys are trusted for what, thresholds, the Authenticode publisher pin, expiry | Three YubiKeys (PIV applet, key generated on the token, PIN and touch required). A at home; B and C in two separate places off-site (a bank box, a trusted person) | Yearly re-sign and key changes, on a computer booted from a live USB with networking off | One loss is survived; replace it at the next ceremony | One key: nothing (two are needed, each behind a PIN). Two keys: catastrophic, reinstall everywhere |
| **Release R1, spare R2** (threshold 1 of 2) | Release documents | YubiKeys. R1 at the founder's desk, R2 in the home safe | Each release and the monthly re-sign | Use R2; replace R1 at the next root ceremony | Remove it at a root ceremony (the revocation). Until then the attack is bounded by Authenticode, the pace and halden's alerts |
| **Authenticode identity** | `.exe` and `.msi` files (the Windows publisher signature) | Azure Artifact Signing (keys held by Microsoft) or a CA-issued certificate on a hardware token | Each release, from the founder's computer | Not applicable (cloud) or reissue | Revoke with Microsoft or the CA. Useless for updates on its own |
| halden's TLS certificate | HTTPS | Hosting provider | Always | Not applicable | Lets an attacker impersonate the server: freeze only |
| *Timestamp (deferred)* | Short-lived freshness | Would be online | Not in v1 | | Would allow freeze only |

**Algorithm.** Use ES256 (P-256) for the hardware-token keys. Every YubiKey
5 supports P-256 in its PIV applet, while Ed25519 in PIV needs newer
firmware *(unverified: 5.7 or later)*. AWS KMS supports both (Ed25519 since
November 2025). SPEC 4 already allows both algorithms, and `proof/sigs` verifies both
with the exact encodings and low-S rule, so the verifier costs nothing extra.
`sigs.NewSigner` wraps any `crypto.Signer`, so a token that returns DER
signatures plugs into the existing low-S conversion. Ed25519 stays allowed
for test keys and any future software or KMS key.

**Hardware token or cloud KMS?** A cloud KMS key (AWS KMS, Google Cloud
KMS) cannot be lost in a fire and logs every signature, which is a real
plus. But whoever controls the cloud account can sign, so the account
*becomes* the key. It is also a new vendor and account for the founder to
secure, and it invites automated signing from CI, which brings back the
compromised-GitHub path. A YubiKey costs no account, cannot be used
remotely, and fits a monthly human ritual. **Recommendation:** YubiKeys
now; reconsider KMS only if signing is ever automated.

**Rotation.** A key changes only in a new root document (version N+1),
signed by 2 of the 3 root keys listed in root N and 2 of the 3 listed in
N+1. Agents walk the chain one version at a time on every check. Rotate the
release key at least every two years, or at once if exposed. Root keys
change when a token is lost, retired or suspected.

**Revocation.** Removing a key from the root revokes it on the next check of
every agent that can reach the server. Changing the release keys also resets
the stored release high-water mark, which undoes a fast-forward. A bad
*release* is revoked by publishing a newer one; the updater also remembers
every digest that failed its checks locally and never retries it.

**The trust anchor.** Root version 1 is compiled into the updater and
delivered by the Authenticode-signed MSI. A fresh install trusts what that
MSI contains, which is the usual first-install trust. Later roots are fetched
and stored; the compiled-in root is the floor.

## 4. The documents (a proposed SPEC section)

Both documents are in-toto Statement v1 payloads in DSSE envelopes
(`application/vnd.in-toto+json`, SPEC 7), canonical JSON (SPEC 3), with SPEC
4 keys and signatures. Unlike device statements they are signed by the
vendor, may carry several signatures (thresholds; at most 8 per envelope),
and are public, so they contain no customer data at all. The predicate
types are brand constants (SPEC 1): `https://kovyr.com/update/root/v1`
and `https://kovyr.com/update/release/v1`. The shapes below are a
proposal for U1, not final.

### 4.1 Root

```json
{"_type":"https://in-toto.io/Statement/v1",
 "predicateType":"https://kovyr.com/update/root/v1",
 "subject":[{"digest":{"sha256":"<key ID>"},"name":"key_<16 hex>"}, "..."],
 "predicate":{
   "version":3,
   "issued_at":"2026-11-02T18:00:00Z","expires_at":"2027-11-02T18:00:00Z",
   "keys":{"items":[{"alg":"ecdsa-p256-sha256","keyid":"<64 hex>","public_key":"<SPKI base64>"}],
           "total":5,"truncated":false},
   "roles":{"root":{"keyids":["<64 hex>","<64 hex>","<64 hex>"],"threshold":2},
            "release":{"keyids":["<64 hex>","<64 hex>"],"threshold":1}},
   "publisher":{"authenticode_subject":"<exact signer subject>"}}}
```

As in SPEC 6, the subjects are the keys this document is about, by key ID.
`publisher` pins the Authenticode signer here instead of in the binary, so
moving from a personal to a company certificate takes a root ceremony, not a
reinstall. It is the only free-text value, and it is vendor-signed public
metadata, not device data.

### 4.2 Release

```json
{"_type":"https://in-toto.io/Statement/v1",
 "predicateType":"https://kovyr.com/update/release/v1",
 "subject":[{"digest":{"sha256":"<64 hex>"},"name":"agent_windows_amd64"}],
 "predicate":{
   "release_seq":42,
   "issued_at":"2026-11-02T18:00:00Z","expires_at":"2026-12-17T18:00:00Z",
   "targets":{"items":[{"arch":"amd64","component":"agent","length":10699264,"os":"windows",
                        "sha256":"<64 hex>","version":{"major":0,"minor":3,"patch":0}}],
              "total":1,"truncated":false},
   "rollout":{"broad_bp":10000,"canary_bp":10000,"early_bp":10000}}}
```

* `release_seq` increases with every signed document, including monthly
  re-signs.
* Subject names, `component`, `os` and `arch` are enums.
* `version` uses the `agent_version` shape (SPEC 6.5).
* `*_bp` are basis points (0 to 10000) of each ring allowed to install
  (section 8).
* There are no URLs, paths, arguments, hooks or flags that make anything
  happen. The schema is closed: unknown fields are refused, as everywhere in
  the SPEC.

### 4.3 How the updater verifies (each check)

1. Load the trusted root: the compiled-in root, or the newest stored root
   that chains to it.
2. Fetch `root/<N+1>.json` (at most 64 KiB). On 404, go to step 3.
   Otherwise accept it only if it is exactly version N+1, signed by a
   threshold of distinct root keys of root N *and* of its own root keys.
   Store it and repeat, at most 16 times per check. If the release keys
   changed, reset the release high-water mark.
3. If the root has expired by the local clock, stop and report `stale`.
4. Fetch `release.json` (at most 64 KiB) and verify a threshold of distinct
   release keys of the current root. Refuse it if `release_seq` is below
   the stored high-water mark, or equal to it with different bytes (report
   `verify_failed`: equivocation). Refuse it if expired. Then store the new
   high-water mark *before* acting on the document.
5. Pick the target for this component, OS and architecture. Continue only
   if its version is strictly greater than the installed one and its digest
   has not failed here before.
6. Apply the rollout gate (section 8) and the power and load gate (section
   9).
7. Download `targets/<sha256>` with a 15-minute deadline. Stop reading at
   `length` + 1 bytes, hash while streaming to the staging folder, and
   refuse any mismatch.
8. Move the file to its version folder (section 7.3). Re-open it there
   without write sharing, hash it again, and check its Authenticode
   signature against the pinned publisher.
9. Switch (section 7.4). Steps 4 to 9 run in one pass: the updater never
   installs from a release document it fetched hours earlier, so a
   withheld (halted) document stops installs that have not started yet.

### 4.4 The heartbeat's `update` section (a SPEC 6.5 addition)

The updater never talks to halden. It writes a small status file that the
agent reads (strictly, size-capped). The agent turns it into typed values
for its heartbeat builder, so the content rule and its adversarial tests
cover it:

| Field | Type |
|---|---|
| `state` | enum: `off` (updates turned off in the settings), `current` (running the newest version offered to this device), `waiting` (a newer version exists, but it is not this device's turn yet, or it is waiting for mains power or a quiet processor), `probation` (just switched; the updater is watching the new version), `rolled_back` (the last new version failed its checks here and was undone), `stale` (no valid, unexpired release document: unreachable, withheld, or expired), `verify_failed` (something offered failed verification), `unknown` (no status from the updater, or it is older than 24 hours) |
| `release_seq` | integer 0 to 2^31-1: the newest release document verified |
| `root_version` | integer 0 to 65535 |

`waiting` deliberately doesn't say whether the computer is on battery, as
with `schedule` today. With these fields halden can:

* count rollbacks for each release (automatic halt, section 8.4);
* alert the founder to any `release_seq` or `agent_version` the founder
  never published (a sign of a stolen release key);
* alert to `verify_failed` (someone is serving bad files);
* flag computers stuck on `stale` (freeze).

## 5. Two signatures: Kovyr's update signature and Authenticode

| | Kovyr update signature (release document) | Authenticode (Windows publisher signature) |
|---|---|---|
| Who signs | The founder's release key, on a YubiKey | Kovyr's Windows code-signing identity, issued after a CA (or Microsoft for Artifact Signing) verified who Kovyr is |
| What it proves | Kovyr's release process approved exactly these bytes as version X, current until a given date, for the stated rollout | A verified publisher signed these bytes at a time vouched for by an RFC 3161 timestamp |
| Trust rooted in | Keys pinned on the device (root document); no CA | Windows' certificate store and the CA system |
| Freshness and order | Yes: release number, expiry, versions | None. An old signed binary stays valid forever thanks to timestamping, so Authenticode alone allows downgrades |
| Who else checks it | Only Kovyr's updater | Windows, Defender and other antivirus, the customer's IT provider (WDAC and AppLocker publisher rules), incident responders, SmartScreen for the MSI download |
| If its key is stolen | Bounded by the second signature, pace and alerts | Useless for updates on its own |

**Order of checks.** The release signature and the hash come first. They
are pure Go, with no Windows parser touching untrusted bytes. Authenticode
comes next (`WinVerifyTrustEx` with the generic verify action, available in
`golang.org/x/sys/windows` v0.41.0). Windows' PE parser therefore only
ever sees bytes that are already known to be Kovyr's.

**Pinning the publisher.** WinVerifyTrust only says "some trusted publisher
signed this". The updater must also check that the signer's subject matches
the root's `publisher`, or the second signature adds nothing. Reading the
signer certificate needs `CryptMsgGetParam`, which x/sys v0.41.0 does not
wrap (it does wrap `CryptQueryObject` and `CertGetNameString`). It would need
a few lines of `NewLazySystemDLL`, as `internal/sysload` does today. Pin the
subject, not the thumbprint, because certificates now renew often:
publicly trusted code-signing certificates last at most 460 days since
March 2026, and Artifact Signing uses short-lived certificates *(lifetime
unverified)*.

**No extra network.** Revocation checks would make Windows contact the CA's
servers, which breaks "the agent talks to the configured server and nothing
else". The updater asks WinVerifyTrust not to fetch revocation data
(`WTD_REVOKE_NONE` with `WTD_CACHE_ONLY_URL_RETRIEVAL`). A compromised
Authenticode identity is handled by changing the root's `publisher` pin.

**Where to sign.** Authenticode signing happens on the founder's computer
during the release ritual, not automatically on every CI push. Otherwise a
compromised GitHub account could get look-alike malware signed in Kovyr's
name. Azure Artifact Signing accepts individual developers in the US and
Canada after identity validation. The certificate then names the founder
personally until Kovyr can validate as an organization (open question 5).

## 6. What the updater fetches, and from where

Everything comes from the agent's configured `server` (the same halden
origin as the heartbeats, read from `agent-config.json`), under `/v0/update/`:

| Request | Cap | Meaning |
|---|---|---|
| `GET /v0/update/root/<N>.json` | 64 KiB | Root version N (the updater asks for N+1 until it gets 404) |
| `GET /v0/update/release.json` | 64 KiB | The current release document |
| `GET /v0/update/targets/<sha256>` | `length` from the signed document, at most 64 MiB | A binary, addressed by its hash |

Nothing else. The rules are the agent's existing client rules (`docs/api.md`):

* HTTPS only, TLS 1.2 or newer, normal certificate checks;
* no redirects and no other hosts;
* no credentials, cookies, query strings or device IDs. Requests are
  anonymous, and halden learns about update state only from signed
  heartbeats;
* a deadline on every request;
* response headers are ignored except the status code. `Content-Type` and
  `Content-Length` are never trusted.

A response is either a document that verifies, a binary that matches, or
nothing. The updater makes no POST, so it sends nothing to the server.

halden serves these as static files, uploaded by the founder's release
tool. It must serve them itself, not redirect to storage, because the
agent follows no redirects. If halden runs on Vercel, check its function
response-size limit (a few MB *(unverified)*) and serve the binaries as
static files if it bites. The dev receiver gets the same paths, served from
a folder, for tests.

## 7. Installing without os/exec

### 7.1 Options

| Option | How the new binary starts | Rollback if the new binary can't start | os/exec | Verdict |
|---|---|---|---|---|
| A. Agent updates itself: stage, change its own service path, exit with an error so the service manager restarts it | Service manager, via the existing recovery actions | **None.** The only code that could undo it is the broken binary; recovery just restarts it 1, 5 and 15 minutes later, forever. Also fills the failure counter on every update | No | Rejected |
| B. **Separate updater service and binary** (`kovyr-updater.exe`) | Service manager: the updater stops `KovyrAgent`, changes its binary path, starts it | Yes: the updater watches the new version from outside it | No | **Recommended** |
| C. Same binary, second service (`kovyr-agent.exe updater run`) | Service manager | Yes, but the updater replaces its own image while being the watchdog, and update code ships inside the agent | No | Rejected for v1 |
| D. MSI per update (`MsiInstallProduct`, or `msiexec`) | Windows Installer | Install-time file rollback only, nothing based on health. MSI custom actions are arbitrary code | `msiexec` would need it | MSI only for the first install and repair |
| E. Updater runs `kovyr-agent.exe selftest` before switching | A child process | Catches "won't start" early | **Yes** | Rejected; probation (7.5) does the same through the service manager |
| F. An off-the-shelf updater (Omaha, WinSparkle, Squirrel) | Varies | Varies | Varies | Built for desktop apps or large server stacks; new dependencies and formats |

### 7.2 Recommendation: a separate, minimal updater service

* **`kovyr-updater.exe`** is its own command (`cmd/kovyr-updater`) and its
  own service, `KovyrUpdate` ("Kovyr Updater"). It runs as LocalSystem,
  with automatic delayed start, restart on failure, and accepts only stop
  and shutdown. It has no listening port, no UI and no console commands
  that install anything.
* **Separation of duties, enforced by structure tests:** the updater
  cannot sign anything, and the agent cannot install anything.
  * Neither binary imports `os/exec`, `plugin` or `net/rpc` (the existing
    test, extended to the new command).
  * The updater imports nothing that touches the device key
    (`internal/keystore`) and none of `internal/checks`, `internal/tripwire`
    or the statement builder.
  * The agent does not import the update package.
* **The agent's network surface is unchanged.** It still accepts only a
  nonce and a status code. Its only new input is the local status file
  (section 4.4).
* **Starting the new version is only ever `StartService`** on
  `KovyrAgent`, through `golang.org/x/sys/windows/svc/mgr` (already a
  dependency). The binary path is only ever one the updater built and
  verified itself (section 7.4).
* **Cost:** a second small Go service. It must be measured in CI like the
  agent, and both together must stay under the 50 MB and 1% CPU budget
  (the updater sleeps nearly all the time; target under 15 MB). It also
  has its own update problem (section 7.8).

### 7.3 Files on disk

```
C:\Program Files\Kovyr\                      (MSI; only SYSTEM and Administrators can write)
  kovyr-updater.exe
  versions\
    0.2.0-1a2b3c4d5e6f7a8b\kovyr-agent.exe   previous, known good
    0.3.0-9f8e7d6c5b4a3a2b\kovyr-agent.exe   current
C:\ProgramData\Kovyr\                        (the agent's state directory, as today)
  agent-health.json                          written by the agent, read by the updater
  update\
    state.json                               journal, high-water marks, failed digests, rollout seed
    roots\<N>.json                           every verified root
    release.json                             the last verified release document
    staging\<sha256>.partial                 a download in progress
    status.json                              enums and integers for the heartbeat
    logs\updater.log ...                     capped and rotated like the agent's logs
```

* Folder names come from the verified version integers and the first 16
  hex digits of the digest, never from a string in a document.
* At most three agent copies exist at once: previous, current and staged
  (about 35 MB). Anything older is deleted only after a commit, and only
  inside `versions\`.
* The MSI (a Ticket 3 follow-up) moves today's single
  `C:\Program Files\Kovyr\kovyr-agent.exe` into this layout. An MSI repair
  must never move the service back to the MSI's older copy.

### 7.4 The switch

Every step is recorded in `state.json` (atomic writes, as the agent does
already). An updater that restarts at any point, including after a reboot,
can therefore finish the step or undo it:

1. `staged`: the file is verified at its final path (section 4.3, step 8).
2. `switching`: stop `KovyrAgent` through the service manager and wait up
   to 30 seconds (the agent stops within 3). If it doesn't stop, give up
   and leave everything as it was: the updater never kills a process.
3. Set the service's binary path to the new copy. The full command line is
   rebuilt from constants: the versions folder, the derived folder name,
   and `service.Args(stateDir)`. A guard refuses any path outside
   `versions\` and any file whose digest is not the staged one, which is
   hashed again just before the change.
4. Start `KovyrAgent`; the state becomes `probation`.

The agent's chain continues across the switch. The new version uses the
same key, state, queue and sequence numbers, and its first heartbeat goes
out at once (`Run` beats immediately). The alarm is off for a few seconds,
well inside halden's gap threshold.

### 7.5 Probation: is the new version healthy?

The agent writes `agent-health.json` after each heartbeat attempt. It holds
integers, enums and timestamps only: version, start time, the last accepted
time, refusals since start, and the kind of the last error (network, server,
refused). The updater reads it and the service status.

**Commit** when all of these hold:

* the service has run for 10 minutes without a restart;
* the new version has had at least one heartbeat accepted (`200` or `202`:
  the server verified the signature and the schema);
* no statement was refused.

**Roll back** when any of these happens:

* the service doesn't reach running within 2 minutes;
* it stops or restarts twice;
* the server refuses a statement as invalid (`400`, `409`, `413`, `422`).
  The new version is signing statements that are wrong, so the alarm is
  broken while it looks alive;
* the agent's average CPU over 30 minutes, or its peak working set, goes
  above twice the budget (measured from outside, as `internal/tools/winci`
  does).

**Wait** while the server is unreachable or answers `5xx`, `401`, `403` or
`429`. That is the network or halden, not the new version. Probation stays
open (with no further updates) until a heartbeat gets through. The new
version keeps running meanwhile, and a crash still triggers a rollback.

### 7.6 Automatic rollback

The rollback reverses the switch. The updater stops the agent, points the
service back at the previous copy (kept for exactly this) and starts it. It
records the failed digest so that version is never retried here, and
reports `rolled_back`. halden sees it in the next heartbeat. If even the
previous copy fails, the service manager's recovery keeps retrying, the
computer goes silent, and the usual "computer not reporting" alert follows.
Nothing on the computer is in a worse state than a crashed agent.

### 7.7 The compatibility rule

A rollback only works if the previous version can read what the new version
wrote. The agent refuses unknown fields in `chain-state.json` and
`agent-config.json`, and accepts only its own file names in the queue. That
is right for safety, but it means:

* **A release may write a new state field only after an earlier release
  learned to ignore it** (N-1 compatibility).
* Updates never rewrite `agent-config.json`.
* halden must accept statements from both versions during a rollout.

CI runs version N-1 against the state that version N leaves behind
(section 11).

### 7.8 Updating the updater

v1: **the updater is updated only by the MSI.** It is small and its job
rarely changes. A broken updater fails safe: updates stop on that computer,
protection keeps running, and the heartbeat shows `unknown`. Later (U8): the
updater switches its own service path and restarts. If the new updater fails,
updates stop on that computer, which is safe and visible, and the agent can
become its watchdog. The pace and the canary ring catch a broken updater
before customers do.

## 8. Staged rollout, halt and the kill switch

### 8.1 Rings and buckets

* **Ring** is a local setting, `update.ring` in `agent-config.json`, set at
  install by the founder or the owner: `canary` (the founder's own
  computers and CI), `early` (a few customers who agreed to it), or `broad`
  (the default). Nothing remote can move a device between rings.
* **Bucket** is a number from 0 to 9999, computed as SHA-256 of a random
  seed, which the updater creates on first start and never sends, plus the
  release number. It changes with each release, so the same customers are
  not always first.
* A device may install when its bucket is below its ring's `*_bp` in the
  release document. The founder can hold a ring back by signing with 0.

### 8.2 The agents set the pace

The updater remembers when it first saw each release. It installs only after
that release has waited a minimum time on this device, **whatever the
document says**:

| Ring | Minimum wait after first seeing the release |
|---|---|
| `canary` | none |
| `early` | 24 hours |
| `broad` | 72 hours, plus up to 96 hours more spread by bucket (so the last broad devices update about 7 days in) |

A stolen release key therefore cannot reach everyone overnight. The founder
doesn't need to widen a rollout by hand either: signing with every ring at
10000 lets the pace do it, and halden's automatic halt stops it if needed.
v1 has **no fast lane**: a read-only agent with no listening port has few
fixes that cannot wait a week, and the urgent case is usually "stop", not
"faster". A fast lane, if ever needed, would require root signatures
(open question 6).

### 8.3 Halt, and halden's automatic halt

* **Halt = stop serving.** The founder deletes `release.json` on halden,
  or puts the previous one back. Devices that saw the newer number reject
  the older one, so they see nothing new. Because installs happen only right
  after a fresh fetch (section 4.3, step 9), no install that hasn't started
  goes ahead. This needs no key and grants no power: anyone who controls the
  server could already withhold updates.
* **Automatic halt.** halden stops serving the release document by itself
  and emails the founder (not the customers) when, for the current release,
  any of these crosses a threshold:
  * rollbacks;
  * devices that went silent within 24 hours of entering probation;
  * refused statements;
  * a jump in `unknown` check results compared with the previous version.

  Proposed thresholds: 2 devices or 5%, whichever is lower. The founder looks
  at it in their next session. Nothing needs a reaction within hours.

### 8.4 The kill switch, and why it can't become remote control

The rule that keeps the kill switch harmless: **the network can only make
the updater do less.** It can withhold, delay or pause, but it can never
select, trigger or target. Everything that leads to an install carries the
release signature, and every gate (ring, bucket, pace, power, the failed
list) is computed on the device. So:

* the kill switch stops **updates**, never the agent. There is no remote
  "stop", "uninstall" or "disable protection", because that would be an
  attacker's first wish;
* there is no unsigned "go" signal of any kind;
* customers can turn automatic updates off locally (`update.enabled`). No
  remote switch exists for that either.

### 8.5 Fixing a bad release: roll forward

The documents never downgrade. To undo a bad version 0.3.0 everywhere,
release the previous code again as 0.3.1. Devices that rolled back
locally are already safe. Devices running 0.3.0 move to 0.3.1 at the normal
pace.

## 9. Privacy and footprint

* **No customer data.** Update requests are anonymous GETs to the server the
  heartbeats already reach, so halden sees only an IP address and a time, as
  it does today. The rollout seed never leaves the machine. The heartbeat
  gains three fields about Kovyr's own software (section 4.4), added through
  SPEC first and covered by the content-rule tests. Nothing about the
  customer, their files or their users is added.
* **When it runs.** The updater checks every 6 hours with up to an hour of
  jitter, and the first check comes 10 to 60 minutes after boot, never in
  the boot rush. It downloads and installs only on mains power and when the
  processor is not busy (the `internal/sysload` thresholds the agent uses).
  It never installs on battery.
* **Cost.** A check is two small documents (well under 64 KiB), with
  signatures verified in milliseconds. A download is about 6 MB if halden
  serves it compressed (the hash covers the decompressed bytes), streamed to
  disk, never held in memory. Disk: at most three agent copies (about 35 MB)
  plus capped logs.
* **Memory and CPU.** The updater sleeps between checks. CI measures it
  like the agent (`internal/tools/winci budget`), and agent plus updater
  stay inside CLAUDE.md's budget together.
* **Not in v1:** detecting metered connections (it would need the Windows
  network cost API through COM; whether that is reasonable from Go is
  unverified), and resuming broken downloads.

## 10. Operating it: the founder's runbook

**Each release (30 to 45 minutes):**

1. Merge the reviewed pull requests and tag the release.
2. Run `kovyr-release prepare` on the founder's computer. It downloads the
   CI build, rebuilds locally with the pinned Go toolchain, and compares the
   two, ignoring the Authenticode signature. It then Authenticode-signs
   (interactive login) and checks that:
   * the updater embeds exactly the root the founder holds offline;
   * no test key or test build tag is present.

   Finally it shows the change summary since the last signed release.
3. Run `kovyr-release sign`. It shows the version, digests, lengths, rollout
   and expiry, then asks for the YubiKey PIN and a touch.
4. Upload to halden. The canary computers update within about 6 hours.
   Look at halden's release page in the next session. If it is healthy,
   nothing more is needed: the pace does the rest.

**A month without a release (5 minutes):** `kovyr-release resign`
produces a new `release_seq` with the same targets and a new expiry. halden
reminds the founder 10 days before expiry. Forgetting is safe: updates
pause, nothing breaks.

**Yearly (1 to 2 hours):** the root ceremony, on a live USB with networking
off: extend the root's expiry, rotate keys if needed, test-sign with every
token, and put the off-site key back. halden reminds 60 days before
expiry.

**Incidents.** None of these needs a reaction within hours:

| What happened | What to do, at the next session |
|---|---|
| Automatic halt email | Read the release page. Fix forward (section 8.5), or leave the release halted |
| Release key lost | Sign with the spare; replace the lost key at the next root ceremony |
| Release key or founder's laptop suspected compromised | Root ceremony to remove the key; check halden for unknown-release alerts |
| A root key lost | Replace it at the next ceremony (the two remaining keys sign) |
| halden or its hosting compromised | Nothing can have been installed. Restore, rotate the TLS and storage credentials, and compare the served files with the founder's local copies |
| Authenticode identity compromised | Revoke it with Microsoft or the CA; a root ceremony pins the new subject |
| Two root keys compromised | Catastrophic: a new root through a new MSI on every computer. Tell customers |

## 11. Testing plan

* **Pure verifier with fakes.** `internal/update` holds the verification
  and decision logic as pure functions. It takes bytes, a clock, the stored
  state, the ring and the seed, and returns a decision. There is no OS and no
  network inside, so it is tested on any OS (CLAUDE.md section 5). Behind
  interfaces with fakes: `Fetcher` (HTTP), `Stager` (files),
  `ServiceControl` (stop, set path, start, query), `Health` (the health
  file), `Authenticode`, `Clock` and `sysload`.
* **Adversarial cases, one or more per row of section 2.2:**
  * thresholds: below threshold; one key counted twice; an unknown key ID;
    a key ID that does not name its key;
  * root chain: a root signed only by its new keys; only by its old keys;
    a skipped version; an expired root;
  * release numbers: a lower `release_seq`; the same `release_seq` with
    other bytes; a lower or equal target version; a fast-forward followed
    by key rotation;
  * downloads: a length one byte over; a hash mismatch; a missing or wrong
    Authenticode signer;
  * encodings: unknown fields, non-canonical bytes, high-S signatures,
    oversized documents;
  * transport: an endless or slow response; a redirect;
  * rollout: a bucket just outside the threshold; the pace floor one
    second short;
  * the switch: a path outside `versions\` and a changed file at switch
    time.
* **Fuzzing** (standard `testing.F`) of document parsing and verification,
  run for a fixed time per target in CI on Linux.
* **Mutation checks** (CLAUDE.md section 5), automated. Every guard in the
  updater is listed in `internal/update/mutations.txt` as an exact line and
  its broken form: threshold, distinct keys, old-and-new root signatures,
  each high-water mark, expiry, equivocation, length cap, hash, Authenticode
  requirement, publisher pin, path allowlist, constant arguments, failed
  digests, bucket, pace floors, each commit and rollback condition, journal
  recovery, and the power and load gate. A CI job applies each one in turn,
  and `go test ./internal/update/...` must fail every time.
* **Structure tests:** the import rules of section 7.2 for both commands,
  and a check that a release build embeds the production root and no test
  root.
* **Windows end to end** on `windows-latest`, extending `winci`:
  * build three test versions of the agent (good 0.0.1, good 0.0.2, and
    test-only broken builds behind a build tag: exits at start, signs
    invalid statements, uses too much memory);
  * sign their documents with test keys and serve them from the dev
    receiver;
  * install the agent and updater services;
  * expect 0.0.1 to 0.0.2 to commit; each broken build to roll back to
    0.0.2 and never be retried; a replayed older document to be refused; a
    tampered binary to be refused; an updater killed during the switch to
    recover consistently;
  * check that 0.0.1 runs on 0.0.2's state (section 7.7).

  CI binaries carry no real Authenticode signature. Either sign them with a
  throwaway certificate trusted only on the runner, or use a test-only
  verifier behind a build tag that release builds refuse (to decide in U5).
* **On real machines.** The founder's own computers run the observe-only
  updater (U4), then the full updater (U5), for four weeks each before any
  customer's computer does.

## 12. Ticket plan

Each ticket is one branch, reviewed before merge.

| Ticket | Branch | What ships | Depends on |
|---|---|---|---|
| U1 | `claude/update-spec` | SPEC: the update section (root and release predicates, verification rules, rollout fields), SPEC 6.5 `update`, brand constants, vectors. No agent code | This review |
| U2 | `claude/update-verify` | `internal/update`: the pure verifier and decisions, fakes, fuzz targets, the mutation list and its CI job. Not wired into any binary | U1 |
| U3 | `claude/release-tool` | `cmd/kovyr-release`: root ceremony, sign, re-sign, verify, rebuild comparison, embedded-root and test-marker checks. Software keys first; YubiKey support needs a dependency decision (open question 3) | U1, U2 |
| U4 | `claude/updater-observe` | `cmd/kovyr-updater` as a service in **observe-only mode**: check, verify, download, stage and check Authenticode, write status; the agent reports `update`. It installs nothing. The read-only first step, run on the founder's computers | U2, U3, halden serving files (Ticket 5) or the dev receiver |
| U5 | `claude/updater-switch` | Switch, probation, rollback, journal, the health file in the agent, Windows end-to-end CI | U4 |
| U6 | `claude/update-rollout` | Rings, buckets, pace floors. Plus, in halden: serving `/v0/update/`, per-release health, automatic halt, unknown-release and version-lag alerts | U5, Ticket 5 |
| U7 | (MSI ticket) | The MSI installs both services in the versions layout; repair never downgrades | U5 |
| U8 | later | Release transparency (log every release document in a witnessed log; the updater requires an inclusion proof once real witnesses exist); updater self-update; arm64; rule packs on this channel | U6, real witnesses |

## 13. Open questions for the founder

Each question comes with a recommendation.

1. **A separate updater service, or update code in the agent?**
   *Recommendation:* separate `kovyr-updater` binary and service (section
   7). It is the only option that can roll back a version that won't
   start, and it keeps install code out of the agent.
2. **Root threshold and key custody.** *Recommendation:* root 2 of 3
   YubiKeys, one at home and two in separate places off-site. Release key 1
   of 2 (desk and home safe). ES256 on the PIV applet. The yearly ceremony
   then needs one trip to fetch an off-site key.
3. **How the release tool talks to the YubiKey.** That means either a Go
   dependency in the release tool only (for example `piv-go`, which may
   need cgo and PC/SC on Linux *(unverified)*), or the founder's existing
   Yubico tools. *Recommendation:* `piv-go` in `cmd/kovyr-release` only,
   justified in its PR, with a structure test proving neither the agent nor
   the updater can import it.
4. **An online timestamp key now?** *Recommendation:* no. Rely on the
   45-day release expiry and halden's version-lag alerts. Revisit at around
   500 devices or with weekly releases.
5. **Authenticode route and publisher name.** *Recommendation:* Azure
   Artifact Signing as an individual now (US and Canada only, identity
   check), signing from the founder's computer, not CI. Move to an
   organization identity once Kovyr is incorporated; the root's
   `publisher` pin makes that a ceremony, not a reinstall.
6. **The pace (24 hours to early, then 72 hours plus 4 days to broad), and
   no fast lane.** *Recommendation:* yes for v1. A fast lane, if ever
   needed, requires root signatures.
7. **A tax-season change freeze?** *Recommendation:* yes, enforced by the
   release tool, not by agents. In the weeks before April 15 and October 15
   it refuses broad rollout of anything not marked as a fix, unless the
   founder overrides it.
8. **May the owner or their IT provider turn updates off?**
   *Recommendation:* yes, locally (`update.enabled=false`). halden shows
   these computers and their version lag in the owner's digest.
9. **Updating the updater.** *Recommendation:* only through the MSI in v1;
   self-update in U8 (section 7.8).
10. **Where the files are served.** *Recommendation:* halden, on the same
    origin under `/v0/update/`, with no redirects. Check Vercel's response
    limits before choosing where the binaries live.
11. **Release transparency.** *Recommendation:* publish every release
    document to a public, witnessed log from the first release (cheap).
    Make the updater require inclusion proofs once real witnesses exist
    (U8). This is the defense against a stolen release key used on a single
    customer.
12. **Updates for pilot customers before U5 is proven.** *Recommendation:*
    pilots get manual MSI updates until the full updater has run on the
    founder's computers for four weeks.
13. **The updater's account.** *Recommendation:* LocalSystem in v1, since
    by its job it is equivalent to SYSTEM anyway, and separation comes from
    code structure. Revisit with the privilege-hardening follow-up from
    Ticket 3.

## Sources

Checked on the web while writing (October 2026):

* Notepad++ update hijack, 2025: [The Register](https://www.theregister.com/2026/02/02/notepad_plusplus_intrusion/),
  [Advanced Installer's analysis](https://www.advancedinstaller.com/the-notepad-plus-plus-attack-explained.html).
* Code-signing certificates at most 460 days from 1 March 2026:
  [CA/Browser Forum ballot CSC-31](https://cabforum.org/2025/11/17/ballot-csc-31-maximum-validity-reduction).
* AWS KMS Ed25519 support (November 2025):
  [AWS announcement](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/).
* Azure Artifact Signing (formerly Trusted Signing), individual developers in the US and Canada:
  [quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart),
  [pricing](https://azure.microsoft.com/pricing/details/artifact-signing/).
* `go-tuf` v2 dependencies (older revision) and latest release:
  [go.mod](https://github.com/theupdateframework/go-tuf/blob/master/go.mod),
  [FreshPorts](https://www.freshports.org/security/go-tuf).

Checked in this repository: `golang.org/x/sys/windows` v0.41.0 provides
`WinVerifyTrustEx`, `CryptQueryObject`, `CertGetNameString`,
`ChangeServiceConfig` and `svc/mgr` `UpdateConfig`, but not
`CryptMsgGetParam`. The agent binary at this commit is 10,699,264 bytes
(`GOOS=windows GOARCH=amd64 go build -trimpath`), and 5,936,771 bytes
with `gzip -9`.

From the TUF specification and public incident reports, not re-checked in
this session: the TUF roles and attack names; Kaseya VSA (2021),
ScreenConnect (2024), CrowdStrike (2024).

Not verified: YubiKey prices and firmware support for Ed25519 in PIV; Artifact
Signing's price, certificate lifetime and organization requirements; Vercel's
response-size limit; `piv-go` build needs; the Windows network cost API from Go.
