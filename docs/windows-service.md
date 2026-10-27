# The Kovyr agent as a Windows service

The agent runs as a Windows service named `KovyrAgent` ("Kovyr Protection
Alarm"). It stays read-only: it changes no setting, runs no command and
accepts nothing from the network but a nonce and a status code
(`docs/api.md`).

## Install

From an elevated prompt ("Run as administrator"):

```bat
mkdir "C:\Program Files\Kovyr"
copy kovyr-agent.exe "C:\Program Files\Kovyr\"
cd "C:\Program Files\Kovyr"
kovyr-agent keygen
kovyr-agent enroll --print-pubkey        (add the output to the receiver's devices file)
kovyr-agent service install --server https://RECEIVER [--interval 15m]
kovyr-agent service start
kovyr-agent service status
```

`service install` refuses, with a plain reason, when:

* the prompt is not elevated (also `uninstall`, `start` and `stop`);
* there is no device key yet;
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

`service uninstall` stops and removes the service. It keeps the state
directory (device key, chain state, queue, settings and logs), because a
new key means a new enrollment.

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
* An installer (MSI) that puts the binary in Program Files and runs
  install, so nobody has to copy it by hand.
* A signed "sensor stopping" heartbeat on a clean stop, so the receiver can
  tell a stop from a cut cable.
