# The Kovyr agent as a Windows service

The agent runs as a Windows service named `KovyrAgent` ("Kovyr Protection
Alarm"). It stays read-only: it changes no setting, runs no command and
accepts nothing from the network but a nonce and a status code
(`docs/api.md`).

## Install with the MSI

`kovyr-protection-alarm-x64.msi` (built on Linux by `installer/build-msi.sh`
with wixl from msitools; CI publishes it in the
`kovyr-protection-alarm-test-kit` artifact, from `main` only) does everything below in one
step. Testing it on your own PC: `docs/testing-on-your-pc.md`.

```bat
msiexec /i kovyr-protection-alarm-x64.msi /qn            (or double-click it)
msiexec /x kovyr-protection-alarm-x64.msi /qn            (uninstall)
```

* It puts `kovyr-agent.exe` in `C:\Program Files\Kovyr\`, then runs, as
  SYSTEM, `kovyr-agent service install --server "[SERVER]" --create-key
  --start` (with `--dev-insecure` added when `DEV_INSECURE=1`): the code
  below, with a device key made if there is none (an existing key is
  always kept, and one that cannot be opened stops the install) and the
  service started (and removed again if it does not start). If that step
  fails, the whole install rolls back. Its output is not shown, so it also
  writes each step to the agent log (`service install:` lines).
* `SERVER` defaults to `https://agent.kovyr.com/api/agent`.
  `DEV_INSECURE=1` allows plain http to localhost (CI and development).
  Set them from an elevated prompt:
  `msiexec /i kovyr-protection-alarm-x64.msi SERVER=https://... /qn`.
  Because the install step runs as SYSTEM, the MSI refuses (before it
  copies anything) a `SERVER` that holds a quote or a backslash, or does
  not start with `https://` or `http://`, and a `DEV_INSECURE` other than
  `0` or `1`; `DEV_INSECURE` only chooses between two fixed command lines.
  The agent then accepts only a plain URL (below).
* Uninstalling stops and deletes the service (Windows Installer's
  ServiceControl) and removes the binary and its folder. **The state
  directory `C:\ProgramData\Kovyr` is kept** (device key, chain state,
  settings, logs), so a reinstall is the same device with the same
  enrollment, and its chain continues. To remove it, delete the folder by
  hand after uninstalling and revoke the device on the admin page; the
  next install is then a new device.
* A newer build, or a rebuild of the same version, upgrades in place:
  the old product (and its service) is removed first, keeping the key.
* It refuses to install over a service set up by hand, and says how to
  remove that first.
* x64 only; it runs on Windows on ARM under emulation (untested there).
  It is not code-signed yet, so SmartScreen warns and Smart App Control
  blocks it.

CI (`installer-test` on `windows-latest`) checks that an install with a bad
server URL rolls back completely and that a `SERVER` with a backslash or a
`DEV_INSECURE` other than 0 or 1 is refused by a launch condition, then
installs it silently against the dev receiver and checks the binary,
service, settings and state directory ACL. It runs the test kit's scripts (including the ransomware test)
against the installed service, installs a second build over it (same
device, chain continues), uninstalls (key kept), reinstalls (same device)
and uninstalls again, and checks that it refuses to install over a
service set up by hand and leaves that service alone. The state folder
checks (below) run on a real NTFS volume in the `internal/keystore` tests
on `windows-latest`: a folder a user owns is refused, a loose access list
is repaired, and an earlier version's folder is accepted.

## Install by hand

From an elevated prompt ("Run as administrator"):

```bat
mkdir "C:\Program Files\Kovyr"
copy kovyr-agent.exe "C:\Program Files\Kovyr\"
cd "C:\Program Files\Kovyr"
kovyr-agent keygen
kovyr-agent enroll --print-pubkey        (add the output to the receiver's devices file)
kovyr-agent service install --server https://RECEIVER [--interval 15m] [--watch D:\ClientFiles]
kovyr-agent service start
kovyr-agent service status
```

`service install` refuses, with a plain reason, when:

* the prompt is not elevated (also `uninstall`, `start` and `stop`);
* there is no device key yet;
* `--server` is not a plain `https://` URL: host name or IP address,
  optional port, optional path of letters, digits and `. _ ~ -`; no
  credentials, query, fragment, `%` escapes, spaces, quotes or
  backslashes (plain `http://` only with `--dev-insecure`, to localhost);
  `--dev-insecure` takes only `0`, `1`, `true` or `false`; `--server`,
  `--dev-insecure` and `--state-dir` may each be given once, and nothing
  but flags is accepted;
* the state folder is not safe (next section);
* `kovyr-agent.exe` is not under Program Files. A service runs as SYSTEM,
  so a binary in a folder a user can write to (Downloads, Desktop, Temp)
  would let that user run code as SYSTEM by replacing it;
* the settings are invalid (for example plain `http://` without
  `--dev-insecure`, which is allowed only to localhost).

What it sets up:

| Setting | Value |
|---|---|
| Account | LocalSystem (needed to read BitLocker, Defender and the service list) |
| Start | automatic, delayed (after the boot rush) |
| Recovery | restart after 1 minute, then 5, then 15; the count resets after a day; also when the service exits with an error code |
| Command line | `"C:\Program Files\Kovyr\kovyr-agent.exe" service run --state-dir "C:\ProgramData\Kovyr"` (quoted, so spaces are safe) |
| Service SID | unrestricted (`NT SERVICE\KovyrAgent`), so ACLs can name it later |

`service install` also refuses an already installed service (before it
writes anything). `--create-key` makes the device key if there is none and
never replaces one; `--start` starts the service and removes it again if
it does not start. The MSI uses both.

`service uninstall` stops and removes the service. It keeps the state
directory (device key, chain state, queue, settings and logs), because a
new key means a new enrollment.

## The state folder

`C:\ProgramData\Kovyr` holds the device key. Its access list is the only
thing that keeps other users from the key: DPAPI in machine scope ties
the sealed key to this computer, but any process on it can unseal it.
Any user can create a folder in `C:\ProgramData`, so the agent never
trusts one it finds there. At install, at `keygen` and every time the
service starts, before it reads or writes anything in it
(`keystore.CheckDir`):

* a folder that is a junction or link, or whose owner is not SYSTEM or
  Administrators, is refused. Someone without administrator rights may
  have made it before Kovyr was installed (and planted a key they know).
  The agent does not take it over. **Delete the folder and install
  again**; the device gets a new key, so enroll it again and revoke the
  old one;
* a folder Administrators or SYSTEM own whose access list lets anyone
  else in is repaired (protected list: SYSTEM and Administrators only),
  unless what is inside shows that access may have been used (an entry
  someone else owns, a link, or a device key others could read): then it
  is refused the same way;
* the key file has its own protected access list (SYSTEM and
  Administrators), not only what the folder passes down; a key file
  someone else owns or can open is refused. A key file from an earlier
  version, which only inherited the folder's list, gets its own.

A refusal cannot go to the agent's log, which is in that folder. The
console shows it, and it goes to the Windows **Application** event log,
source `KovyrAgent` (Event Viewer says the source's description is
missing; the text follows). A failed MSI install for this reason looks
like any other rolled-back install, so look there. At service start the
service then stops with an error and Windows' recovery actions retry it.

## Stop and shutdown

The service accepts only stop and shutdown. On either it cancels the
heartbeat loop and reports stopped within 3 seconds, even if a heartbeat
is stuck in a slow WMI query; Windows allows services several seconds at
shutdown. Everything the agent writes is crash-safe (atomic file writes, a
queue reconciled with the chain at start), so stopping or killing it
mid-heartbeat loses nothing and never reuses a sequence number. If the
loop ends by itself (no key, bad settings) the service exits with an error
code and Windows' recovery actions retry it.

## Settings

`C:\ProgramData\Kovyr\agent-config.json`, written by `service install`
and read when the service starts. The folder is open only to SYSTEM and
Administrators. Missing fields take their defaults; unknown fields,
trailing data and out-of-range values are refused (the service then fails
to start and logs why). Restart the service after editing it.

| Field | Default | Range | Meaning |
|---|---|---|---|
| `server` | (required) | `https://` URL | the receiver |
| `dev_insecure` | `false` | | allow `http://` to localhost (development only) |
| `interval_s` | `900` | 60 to 3600 | heartbeat interval |
| `battery.interval_factor` | `2` | 1 to 4 | interval multiplier on battery (capped at 3600 s) |
| `battery.skip_heavy_checks` | `true` | | skip the heavy checks on battery |
| `load.busy_percent` | `80` | 50 to 100 | processor busier than this defers a heartbeat |
| `load.window_s` | `60` | 10 to 300 | how far back "busy" looks |
| `load.defer_step_s` | `60` | 10 to 600 | how long one deferral waits |
| `load.max_defer_s` | `300` | 1 to 1800 | longest total deferral (and never more than a third of the interval) |
| `log.max_file_bytes` | `1048576` | 64 KiB to 8 MiB | size of one log file |
| `log.files` | `5` | 1 to 10 | number of log files kept |
| `tripwire.enabled` | `true` | | run the ransomware tripwire |
| `tripwire.user_folders` | `true` | | watch each user's Desktop and Documents (`--no-user-folders` turns it off) |
| `tripwire.folders` | `[]` | at most 16 absolute paths | more data folders to watch (`--watch DIR`, repeatable) |
| `tripwire.window_s`, `min_activity`, … | see `docs/tripwire.md` | | the tripwire thresholds |

## Backing off

* **On battery** (`GetSystemPowerStatus`): the interval doubles and the
  heavy checks are skipped. Heavy means the slow WMI queries of settings
  that change only with a reboot or an administrator: BitLocker and memory
  integrity. They report `unknown` with outcome `skipped`. Defender, EDR,
  firewall and Security Center always run, because those are what an
  attacker turns off.
* **Under load** (`GetSystemTimes`): the loop samples the processor one
  window before each heartbeat. If it was more than 80% busy over that
  minute, the heartbeat waits a minute and checks again, for at most five
  minutes (a third of the interval), and is then made anyway. A heartbeat
  is delayed, never skipped.
* **Unknown** power or load never causes a back-off.
* Each statement says what happened (SPEC 6.5 `schedule`: `interval_s`,
  `deferred_s`, `heavy_checks_skipped`), so the receiver judges silence
  against the announced interval and a laptop on battery is not reported
  as missing heartbeats. The power source itself is not reported.

## Logs

`C:\ProgramData\Kovyr\logs\agent.log`, then `agent.1.log` (newer) to
`agent.4.log` (oldest): at most 5 files of 1 MB. If rotation fails the
current file is emptied, and failing that the line is dropped: the cap
always wins. Lines are cut at 2 KB and control characters replaced. The
log holds only what is needed to debug the agent: check names and
outcomes, sequence numbers, back-off decisions, its server URL and its own
state directory. Never file contents, user names, or paths outside the
agent's directory. Signed statements never contain any of this.

## Resource budget

CLAUDE.md: under 1% CPU on average and under 50 MB RAM. CI measures it on
`windows-latest` (`internal/tools/winci budget` and `service`; numbers in
each run's job summary):

* 20 `kovyr-agent run --once` heartbeats, each reporting its own CPU time
  and peak working set (`--usage`). Budget: peak working set under 50 MB,
  and the CPU of one heartbeat averaged over the default 15-minute
  interval under 0.5%.
* The running loop at a 1-minute interval (15 times the default rate) for
  three minutes, measured from outside. Budget: under 1% CPU and 50 MB.
* The installed service, between its first and third heartbeat. Same
  budget.

WMI queries run in the WMI provider host (`WmiPrvSE.exe`), not in the
agent. That CPU is reported next to the budget but not counted against
it, because other software on the runner uses WMI too.

First measurement (CI run 40404987818, `windows-latest`, Windows Server):

| Measurement | Result | Budget |
|---|---|---|
| `run --once`, agent CPU per heartbeat (20 runs) | mean 102 ms, max 140 ms | |
| That, averaged over the default 15-minute interval | 0.011% | < 0.5% |
| WMI provider host CPU per heartbeat (shared, report only) | about 52 ms | |
| `run --once` peak working set / peak private bytes | 19.8 MB / 16.5 MB | < 50 MB |
| Running loop at a 1-minute interval, 3 minutes | 0.095% CPU, peak working set 20.8 MB | < 1%, < 50 MB |
| Installed service at a 1-minute interval, 2 minutes | 0.078% CPU, peak working set 21.3 MB | < 1%, < 50 MB |
| Service stop / uninstall while running | 136 ms / 127 ms | |
| Crash recovery (process killed) | restarted after 1 minute, chain intact | |

A CI runner is not a customer's laptop: no third-party EDR, Server
edition, no battery. Real machines are the next measurement.

## Follow-ups

* Restrict the service's privileges (`SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`)
  to what the checks need; it needs testing on real machines first, since
  WMI and BitLocker queries might need more than expected.
* Code-sign the MSI and the binary, so SmartScreen and Smart App Control
  accept them.
* A signed "sensor stopping" heartbeat on a clean stop, so the receiver can
  tell a stop from a cut cable.
