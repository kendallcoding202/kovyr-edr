# CLAUDE.md: build rules for the Kovyr endpoint agent

Read this fully before writing code. The agent runs on other people's
computers. A bug here can lock a tax office out of its files during tax
season, or hand an attacker every client at once. These rules exist to
prevent that.

## 1. Who is building this

The founder builds Kovyr part-time (about 10 hours a week) next to a full-time
job, until Kovyr's revenue covers their bills. So:
- **Small steps.** One focused change per branch, reviewed before merge. Stop
  for review; never merge to `main` yourself.
- **Boring tech.** Go, standard library first. Add a dependency only when it
  replaces real risk (for example `golang.org/x/sys/windows` instead of
  hand-written syscalls). Justify each new one in the PR.
- **No on-call products.** Until a 24/7 partner or team exists, nothing may
  require a human to react within hours. Alerts go to halden, which emails
  the owner.

## 2. Hard safety rules

- **Read-only until v2.** The agent observes. It does not change settings,
  delete files, kill processes, isolate networks or run commands sent from a
  server. Any capability that acts on the machine needs an explicit founder
  decision and a security review first.
- **No remote control or remote shell. Ever, without a deliberate decision.**
  Remote-management tools (Kaseya VSA, ScreenConnect, SimpleHelp) are among
  attackers' favorite targets because one compromise reaches every customer.
  The agent never accepts commands, scripts or binaries from the network, apart
  from signed agent updates (see below).
- **No kernel code until v3.** User mode only. No drivers, no hooking other
  processes' memory.
- **Low footprint.** Target under 1% CPU on average and under 50 MB RAM. Back
  off on battery and under load. Never block the user's work.
- **Fail safe.** If a check errors, report `unknown`. Never crash, never loop
  hot, never fill the disk (cap every queue and log).
- **Updates are a code-execution channel.** Agent updates must be signed and
  verified against a pinned key before they run, rolled out in stages, and
  able to roll back.

## 3. Privacy rules

- Signed statements contain only booleans, integers, enums and timestamps.
  Never file names, paths, file contents, email, user names or free text. The
  statement builder must not be able to see such data. Enforce this in code
  and test it adversarially.
- Hostnames and staff account names may appear in alerts the owner sees, but
  never in signed statements or the public log.
- The public log holds only salted commitments (fingerprints), never posture
  values or firm identifiers.

## 4. The proof format

Statements follow the Kovyr proof spec (in-toto Statement v1 in DSSE
envelopes; device signatures ECDSA P-256 so they can move into the TPM;
service keys and log checkpoints Ed25519; RFC 6962 Merkle log with witness
cosignatures; salted commitments). Do not invent a second format. If the spec
needs a change, change the spec first.

## 5. Testing

- Every OS-specific check sits behind an interface with a fake, so logic is
  tested on any OS. Windows-only code lives in `*_windows.go` files.
- CI runs `go vet` and `go test ./...` on Linux and on `windows-latest`,
  including the real Windows checks.
- Mutation-check new guards: temporarily break the guard, and a test must fail.
- Never test against a customer's machine or data.

## 6. Commits

Small and focused. The message says why, not just what.
