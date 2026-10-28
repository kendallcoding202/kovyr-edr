# The ransomware tripwire

The tripwire watches a bounded set of folders for the file activity
ransomware causes and, when it sees it, sends a heartbeat at once instead
of waiting for the next scheduled one. Halden (and the dev receiver) show
that heartbeat as a `ransomware_suspected` tamper signal.

It is an alarm, not a defense. It **only reports**: it never stops a
process, never opens, reads, hashes, creates or changes a file, and never
takes any other action (CLAUDE.md section 2, read-only until v2). Code:
`internal/tripwire`; statement section: SPEC 6.5 `tripwire`.

## What it watches

* Each user's **Desktop** and **Documents**: `Desktop` and `Documents`
  in each profile under the profiles folder (`C:\Users`, found through the
  known-folder API). Real directories only: a junction or symlink is
  skipped, and so are the Public, Default, Default User, All Users and
  DefaultAppPool profiles.
* Up to 16 more **data folders** from the settings file (`tripwire.folders`)
  or `--watch DIR`, for example a shared client-files folder.
* At most **32 folders** in all. Duplicates and folders inside another
  listed folder are dropped first (each watch covers its subfolders, so
  they would be counted twice); configured folders come before user
  folders when the cap bites.

It uses `ReadDirectoryChangesW` on each folder (with subfolders), file-name
and last-write changes only, through one I/O completion port: one thread,
no polling.

Each folder, configured ones included, is opened without following a
junction or symbolic link (`FILE_FLAG_OPEN_REPARSE_POINT`), and watched
only if the opened handle is that folder: not a junction or link itself,
and its final path (`GetFinalPathNameByHandle`) the folder's own, so a
junction anywhere on the way is caught too. Otherwise a user could swap
their Documents for a junction to `C:\` between the agent listing it and
opening it, and the SYSTEM service would watch the whole drive. Such a
folder is skipped like one that cannot be opened. Folders that only carry
a non-redirecting reparse point, such as OneDrive's cloud placeholders,
are watched as before.

## What it counts

Each change is classified in memory and only its class is kept; the file
name is looked at and dropped.

| Class | Meaning |
|---|---|
| `renamed` | every rename (the statement's `renamed` bucket counts all of them) |
| `extension_changed` | a rename to a different extension (`report.docx` to `report.docx.locked`), except renames to or from temporary files: `.tmp`, `.temp`, `.crdownload`, `.part`, `.partial`, `.download`, `.opdownload`, `.dwl`, `.dwl2`, `.bak`, `.swp`, `.~*`, `*~`, `.dropbox`, `.gdtmp`, and Office's `~$…` and `~WR…` files |
| `modified` | a file's contents were written |
| `deleted` | a file was removed |
| `suspicious_created` | a file created with a ransom-note name (`README_TO_DECRYPT.txt`, `HOW_TO_RECOVER_FILES.html`, `_readme.txt`, `!!!RESTORE_FILES!!!.txt`, …: `.txt`, `.html`, `.htm`, `.hta`, `.rtf` or `.url` with a note phrase in it) or a random-looking name (16 to 128 letters and digits, mixed classes, high character entropy) |
| `unknown_activity` | the notification buffer overflowed: changes came too fast to count |

Counts go into a per-second ring and are summed over the sliding window.
Statements carry them only as buckets (`0`, `1_9`, `10_99`, `100_999`,
`1000_plus`), so a statement never shows how much a person works.

## When it trips

Defaults are conservative: a person working, a download, or a sync engine
filling a folder stays far below them.

| Setting (`tripwire.*` in `agent-config.json`) | Default | Allowed |
|---|---|---|
| `enabled` | `true` | |
| `user_folders` (each user's Desktop and Documents) | `true` | |
| `folders` (more data folders, absolute paths) | none | at most 16 |
| `window_s` (sliding window) | 60 | 10, 30, 60, 120, 300 |
| `min_activity` (renames + writes in the window) | 100 | 20 to 100000 |
| `min_extension_changed` | 50 | 10 to `min_activity` |
| `extension_changed_percent` (share of renames that change the extension) | 60 | 10 to 100 |
| `min_suspicious_created` (ransom notes or random names) | 3 | 1 to 1000 |
| `notes_activity` (renames + writes alongside those notes) | 30 | 1 to 100000 |
| `cooldown_s` (at most one immediate heartbeat per) | 600 | 60 to 86400 |

Two rules, checked after each batch of notifications:

1. **`mass_extension_change`**: at least `min_activity` renames and writes
   in the window, at least `min_extension_changed` of them renames to a new
   extension, and those at least `extension_changed_percent` of all
   renames. Extension changes have to dominate, which is what separates
   encryption from someone tidying a folder.
2. **`ransom_notes`**: at least `min_suspicious_created` ransom-note or
   random-looking files created while at least `notes_activity` renames
   and writes happen in the window. A lone `README.txt` or a file called
   "Decryption lecture notes.docx" never trips it.

When a rule fires, the agent makes a heartbeat at once: all checks, no
deferral for load (ransomware keeps the processor busy), `triggered` true
with the reason, and the counts of the window that tripped. It announces
the time left to the scheduled heartbeat as `interval_s`, and the
scheduled heartbeat keeps its time. Within the cooldown, further trips do
not send extra heartbeats; the next scheduled heartbeat reports them.

A trip counts as reported only once the server has accepted a statement
carrying it, while that statement was still inside the server's 5-minute
clock window (a `202` for an older one does not count, because halden
checks the clock later). Until then every statement carries it again. If
the agent is offline, the trip waits and goes out with the retry. If the
statement carrying it cannot be uploaded (the network drops it, an
attacker resets the connection, the server refuses it), a retry that finds
it refused, or 2 minutes old, first makes a new heartbeat with a fresh
challenge that carries the same trip, so it still arrives fresh. These
extra heartbeats happen only at retries, which back off with jitter up to
the heartbeat interval, so a server that keeps refusing gets at most about
one more statement per retry, never a loop. The owner may get the trip in
more than one statement; halden treats them as one alert.

## Sync and backup engines

OneDrive, Dropbox, Google Drive and backup tools rename and rewrite many
files at once, which looks like ransomware to a file watcher.
`ReadDirectoryChangesW` does not say which process made a change, so the
tripwire cannot attribute changes directly. Instead, while files are
changing it samples (every 5 seconds at most) the total write operations of
running processes whose image name is a known engine, compared in memory:
`OneDrive.exe`, `FileCoAuth.exe`, `Dropbox.exe`, `GoogleDriveFS.exe`,
`googledrivesync.exe`, `Syncthing.exe`, `nextcloud.exe`, `owncloud.exe`,
and, not yet confirmed on real installs, `Box.exe`, `iCloudServices.exe`,
`iCloudCKKS.exe`, `bztransmit64.exe` (Backblaze), `CarboniteService.exe`,
`Code42Service.exe`, `Veeam.EndPoint.Service.exe`,
`TIB_Mounter_Monitor.exe` (Acronis).

A burst is suppressed only when those engines wrote at least as often as
files changed during the window. Ransomware writes from its own process,
so when it encrypts a OneDrive folder while OneDrive uploads the results,
OneDrive's write count stays below the change count and the burst still
trips (tested). This is a heuristic: see the decisions below.

## False-positive sources

What could look like ransomware, and how each is handled:

* **Office saves** (`~WRL0001.tmp` renamed into place, `~$` owner files):
  temporary-file renames are not extension changes.
* **Browser and download-manager downloads** (`.crdownload`, `.part`,
  `.partial`, `.opdownload`): temporary extensions.
* **Sync engines** downloading or restoring a whole folder (a new laptop,
  OneDrive Known Folder Move, "free up space"): mostly creations and
  writes, which do not count toward the extension rule, and suppressed by
  the engines' write counts. A restore that renames many files could still
  trip if the engine is not in the list.
* **Developer builds or package installs in Documents** (`node_modules`,
  build output): many writes and some renames, but extension changes rarely
  dominate. A tool that renames thousands of files to new extensions would
  trip it.
* **Batch conversions** (a photo tool renaming `.CR2` to `.dng`, a script
  renaming `.txt` to `.csv`): these do look like ransomware to this rule and
  can trip it. The owner sees a signal they can explain; nothing is acted
  on.
* **Archive extraction** of a large archive into a watched folder:
  creations and writes, below the extension rule.
* **Random-looking names** from cameras, cloud exports or hashes (`3f9a…`):
  they count only toward the ransom-note rule, which also needs activity
  and at least three of them.

Each of these only ever costs a false alarm: the tripwire takes no action.

## What it misses (limitations)

* **No process attribution.** It cannot say which program made the
  changes, and engine suppression is by image name, which malware could
  copy (it would then also have to out-write the files it encrypts).
* **Encryption that keeps names and extensions** (in-place, intermittent
  encryption) shows only as `modified`, which no rule trips on; the busiest
  window appears in the next heartbeat's buckets. A content-based check
  would need to read files, which the tripwire never does.
* **Copy-then-delete encryption** (write `file.docx.locked`, delete
  `file.docx`) shows as creations and deletions, which the rules do not
  count unless ransom notes appear. A pairing rule is a follow-up.
* **Only Desktop, Documents and configured folders.** Pictures, Downloads,
  other drives and network shares are not watched unless configured.
  Desktop and Documents redirected elsewhere (Group Policy folder
  redirection, or OneDrive Known Folder Move to
  `%UserProfile%\OneDrive\Documents`) are not found yet: the agent looks
  for the folders by name in each profile. Until a follow-up reads each
  user's known-folder settings, add redirected folders as data folders.
* **A notification buffer overflow** (64 KiB, about 600 changes per
  folder per read; two buffers per folder) loses the details of that
  burst. It counts as `unknown_activity`, never a crash, but those changes
  do not count toward the rules.
* **Profiles created after the agent started** are picked up at the next
  agent restart.

## Footprint and failure

* Two 64 KiB notification buffers per folder (at most 4 MiB for 32
  folders; a typical office PC watches 2 to 6). No file is opened, read or
  hashed; only change notifications arrive.
* Engine write counts are sampled only while files are changing.
* A folder that cannot be opened, or that is or passes through a
  junction or link, is skipped (logged by number and reason, never by
  path); a folder that disappears is dropped; with no folder left the state
  is `unknown`. The tripwire never stops the agent: if it cannot start, the
  heartbeats carry `state` `unknown`.
* The watcher stops cleanly with the agent (every outstanding read is
  cancelled and completed before the handles close).

## Privacy

Statements carry only the bucketed counts, the window, the number of
folders, the state and the reason: never a path, file name, extension or
process name (SPEC 6.5, CLAUDE.md section 3). The agent log names folders
by number only. The configured folder paths stay in the settings file,
which only SYSTEM and Administrators can open. The CI test checks that no
stored statement, receiver record or agent log line names a file or folder.

## Testing

* Fake streams drive the detector logic on any OS: a burst of renames
  trips; normal editing, OneDrive sync and reorganizing a folder do not;
  ransomware running while OneDrive uploads still trips; a buffer overflow
  is counted as unknown; trips are rate limited and reported once. The
  notification-buffer parser is fuzzed.
* On `windows-latest`, `TestRealWatcher*` watch a temporary folder with
  the real API, and the CI step `Ransomware tripwire` runs the real agent
  against the dev receiver: it creates 300 dummy files in a temporary
  folder, checks that light editing sends nothing, renames them to
  `.locked`, and asserts that an extra heartbeat with `triggered` true and
  `mass_extension_change` arrives and raises `ransomware_suspected`. It
  touches nothing outside that folder.

## Decisions for the founder

* **Decoy files** ("canaries"): the tripwire could plant hidden decoy files
  in the watched folders and alarm when one is touched. That catches
  ransomware sooner and with fewer false alarms, but it means the agent
  creates files on customers' machines, which breaks the read-only rule and
  can confuse users and backup tools. Not built; it needs a decision.
* **Engine suppression by image name** is a heuristic. Confirm the
  unverified names on real installs, and decide whether a code-signature
  check on the engine binaries is worth its cost.
* **Turning it off** reports `state` `unknown`, the same as a tripwire that
  could not start. Halden could treat a tripwire that goes from `ok` to
  `unknown` as a signal of its own.
