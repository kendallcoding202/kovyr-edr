# Testing the Protection Alarm on your own PC

This guide walks you through installing the Kovyr Protection Alarm on a test
Windows computer and setting off each of its alerts on purpose, so you see
exactly what a customer would see. It takes about an hour, plus one
overnight wait for the last test.

**Only use a test computer:** a Windows virtual machine (VM) on your Mac, or
a spare PC with no client files on it. Never a customer's computer.

You will need:

* the test computer (step 1);
* the **test kit** from GitHub (step 2);
* the Kovyr admin site, and the Railway dashboard for halden.

The times below assume the agent's normal settings: it checks in **every 15
minutes**, and halden checks new check-ins **every minute**.

## 1. Get a test computer

**A VM on your Mac.** The common options are Parallels Desktop, VMware Fusion
and UTM. On a Mac with Apple silicon (M1 to M4) they run Windows 11 on ARM.
The Kovyr installer is built for ordinary (x64) Windows, and Windows 11 on
ARM runs it through its built-in emulation. Our automated tests run on x64
Windows, not on ARM, so you are the first to try it there. Give the VM about
4 GB of memory and 64 GB of disk. Install the VM's "tools" so copy and paste
work between the Mac and Windows. If Windows offers to back up your Desktop
and Documents to OneDrive, say no on this VM (see Troubleshooting, "The
ransomware test sent nothing").

**Or a spare Windows 10 or 11 PC** that holds nothing you or a client need.

Sign in to Windows with an account that is an administrator (the first
account on a new PC or VM is).

## 2. Download the test kit

The kit is built by GitHub each time the code changes.

1. In the test computer's browser, sign in to GitHub and open
   **kendallcoding202/kovyr-edr → Actions**.
2. Open the newest run with a green tick for the branch you are testing
   (`claude/installer-test-kit` until it is merged, then `main`).
3. At the bottom, under **Artifacts**, download
   **kovyr-protection-alarm-test-kit**. (GitHub keeps these for a limited
   time, 90 days by default.)
4. In Downloads, right-click the zip, choose **Extract All**, and keep the
   suggested folder.

You can also download it on your Mac and drag the zip into the VM.

The kit holds:

* `kovyr-protection-alarm-x64.msi`: the installer;
* `SHA256SUMS`: its fingerprint;
* `status.ps1`, `check-in-now.ps1`, `tripwire-test.ps1`: helper scripts;
* this guide.

## 3. Open an administrator PowerShell in the kit folder

You will use this window for everything below.

1. Click Start, type **PowerShell**, right-click **Windows PowerShell**, and
   choose **Run as administrator**. Click **Yes**.
2. Go to the kit folder and allow the kit's scripts to run **in this window
   only** (this changes no setting on the computer):

```powershell
cd $HOME\Downloads\kovyr-protection-alarm-test-kit
Set-ExecutionPolicy -Scope Process Bypass -Force
```

If you open a new window later, run those two lines again.

The helper scripts:

* `.\status.ps1` shows the service, this computer's enrollment text,
  Defender's state, the clock and the agent's latest log lines. It changes
  nothing.
* `.\check-in-now.ps1` restarts the Kovyr service. The agent checks in as
  soon as it starts, so you don't have to wait up to 15 minutes.
* `.\tripwire-test.ps1` is the ransomware test (test A). It only touches a
  folder and files it creates itself.

## 4. Install

Double-click `kovyr-protection-alarm-x64.msi` in the kit folder (or run
`msiexec /i kovyr-protection-alarm-x64.msi` in the PowerShell window).

* Windows may say **"Windows protected your PC"**, because this test build
  is not code-signed yet. Click **More info**, then **Run anyway**.
* Click **Yes** when Windows asks for administrator permission.
* A small progress bar appears and closes. No "finished" window appears.

What the installer did:

* put `kovyr-agent.exe` in `C:\Program Files\Kovyr`;
* made this computer's device key in `C:\ProgramData\Kovyr` (a folder
  only administrators can open);
* set the agent to report to `https://agent.kovyr.com/api/agent`;
* installed and started the **Kovyr Protection Alarm** service.

Check it:

```powershell
.\status.ps1
```

The first line should end in **running**. Lower down, the log will say
`challenge: HTTP 403` a few times. That is normal: Kovyr refuses the
computer until you enroll it in step 6.

Optional: compare the installer's fingerprint with `SHA256SUMS`:

```powershell
Get-FileHash .\kovyr-protection-alarm-x64.msi
Get-Content .\SHA256SUMS
```

## 5. Pick a test customer whose owner is you

Alert emails go to the **owner's login email** of the customer the computer
is enrolled under. So enroll it under a test customer you own:

1. Open **kovyr.com/admin**. Under **Add a customer**, add one named, say,
   "Kovyr Test Office". (Or reuse an earlier test customer.)
2. Open it. Under **Invite customer**, enter an email address you read, and
   click **Invite**. That address becomes the owner. A Gmail "plus" address
   works well and keeps it apart from your admin login: if you are
   `name@gmail.com`, use `name+kovyrtest@gmail.com`.

## 6. Enroll the computer

1. On the test computer, run `.\status.ps1` again. Under **"This computer's
   enrollment"** it prints a short block of text that starts with `{` and
   ends with `}`, and copies it to the clipboard.
2. On the test customer's admin page, click **Protection Alarm**.
3. Under **Enroll a computer**, paste the whole block. Give the computer a
   name you will recognise, such as "Test VM". Click **Enroll**.
4. Check that the `device_id` the page shows is the one `status.ps1`
   printed (it starts with `dev_`).

## 7. Turn on halden's two switches

In the Railway dashboard, open the halden project and the **worker**
service (the one running `python -m workers watch`). Under **Variables**,
set:

* `AGENT_VERIFY_ENABLED` = `1` (halden checks each check-in and updates the
  admin page);
* `AGENT_ALERTS_ENABLED` = `1` (halden sends the owner emails).

Railway restarts the worker with the new values (click **Deploy** if it
asks). Until `AGENT_VERIFY_ENABLED` is on, check-ins are stored but the admin
page keeps saying "waiting".

## 8. Check that it checks in

Make it check in now instead of waiting:

```powershell
.\check-in-now.ps1
```

Within about **2 minutes**, the computer's row on the Protection Alarm page
shows a **Last check-in** time marked **on time**, **Protection: on** (with
Defender, BitLocker and firewall details) and **Tripwire: watching**.
Refresh the page if needed.

From now on it checks in by itself every 15 minutes. If nothing shows up,
see Troubleshooting.

## 9. Test A: ransomware tripwire

What it does: `tripwire-test.ps1` makes a new folder in your Documents
called "Kovyr tripwire test" plus the date and time. It fills it with 200
small dummy text files, renames them all to a new extension within a few
seconds (what ransomware does when it encrypts files), waits 15 seconds, and
deletes exactly those files and the folder. It touches nothing else.

Why 200: the alarm trips when, within 60 seconds, it sees at least 100
renames and file writes, at least 50 of them renames to a new extension,
and those at least 60% of all renames. 200 renames clear all three.

Run it:

```powershell
.\tripwire-test.ps1
```

What you should see:

* **Within about 2 minutes:** an email to the test customer's owner,
  subject **"URGENT: possible ransomware on Test VM"**. It tells the owner
  to disconnect the computer from the network, leave it on, and call their
  IT provider.
* On the admin page: **Tripwire: suspected: mass_extension_change**, and an
  open **Ransomware suspected** episode marked **owner emailed**. It closes
  at the next normal check-in (within 15 minutes; or run
  `.\check-in-now.ps1`).

Wait at least **30 minutes** before running it again. The agent sends at
most one immediate alarm per 10 minutes, and halden sends one email per
episode.

## 10. Test B: protection switched off

You will turn off two Microsoft Defender settings, see the alert, then turn
both back on. Do this only on the test computer.

Why two: Windows turns Real-time protection back on by itself after a
while. Tamper Protection stays off until you turn it on, so the alarm still
sees protection off. Turn Tamper Protection off first, because it guards
the other settings.

Turn them off:

1. Click Start, type **Windows Security** and open it.
2. Click **Virus & threat protection**. Under "Virus & threat protection
   settings", click **Manage settings**.
3. Switch **Tamper Protection** to **Off**. Click **Yes**.
4. Switch **Real-time protection** to **Off**. Click **Yes**.

halden emails only when protection is still off at the **next** check-in,
so a short switch-off during an update emails nobody. So it needs two
check-ins:

* **Quick way:** run `.\check-in-now.ps1`, wait 1 minute, run it again.
  The email comes within about **2 minutes** of the second run.
* **Or just wait:** the next two scheduled check-ins take **15 to 30
  minutes**, and the email follows within about a minute.

What you should see: an email with the subject **"Protection is off on Test
VM"**, listing what the computer reported (Tamper Protection off,
Real-time protection off). The admin page shows **Protection: off** with
the same reasons, and an open **Protection off** episode marked **owner
emailed**. To repeat the test, wait 30 minutes after turning protection
back on: a switch-off soon after the last one counts as the same episode,
which is emailed only once.

**Turn both back on** (same page in Windows Security):

1. Switch **Real-time protection** to **On**.
2. Switch **Tamper Protection** to **On**.
3. Run `.\status.ps1`. Under "Microsoft Defender", both should say **on**.

At the next check-in (or after `.\check-in-now.ps1`) the episode closes on
the admin page. No "all clear" email is sent.

## 11. Test C: a computer that goes silent

A computer that stops checking in is marked **silent** on the admin page
about 25 minutes later. It is never emailed straight away (a PC switched off
at night would set it off every evening). Instead it appears in the next
**morning digest**, sent at or after **7:00 am Mountain time** (usually by
7:10), once a day.

halden lists a computer in the digest only once it has been silent for
**more than 24 hours**. The worker setting `AGENT_DIGEST_SILENT_HOURS`
(default 24) can shorten that: a computer is also listed once it is that
many hours past its missed check-in. So with the normal setting, a single
night off is not enough. Pick one way:

* **Normal setting:** stop the agent **before 6:30 am** Mountain time on day
  one, and leave it stopped until the digest arrives on day two.
* **Faster:** on Railway, set `AGENT_DIGEST_SILENT_HOURS` = `1` on the
  worker. Then stop the agent any evening (before about 5 am); the next
  morning's digest lists it. **Delete the variable afterwards** so real
  customers get the normal 24 hours.

To stop the agent, either:

* shut down the VM (or the PC), or
* in the administrator PowerShell window:

```powershell
& "$env:ProgramFiles\Kovyr\kovyr-agent.exe" service stop
```

What you should see: about 25 minutes after the missed check-in, the admin
page marks the computer **silent**, with an open **Silent** episode (never
emailed on its own). The next 7 am digest, subject **"Protection Alarm: 1 thing to check at Kovyr
Test Office"** (the number counts everything it lists), names the computer
under "Computers that have gone quiet" with its last check-in time.

Leave the computer off until the digest has arrived: if it checks in first,
it is no longer silent. Afterwards, start the VM again, or run:

```powershell
& "$env:ProgramFiles\Kovyr\kovyr-agent.exe" service start
```

## 12. Uninstall

* **Settings → Apps → Installed apps**, find **Kovyr Protection Alarm**,
  click **⋯ → Uninstall**; or
* in the administrator PowerShell window, in the kit folder:
  `msiexec /x kovyr-protection-alarm-x64.msi`

This stops and removes the service and deletes `C:\Program Files\Kovyr`.

It **keeps** `C:\ProgramData\Kovyr`: the device key, settings and logs. So
if you install again later, it is the same computer to Kovyr and you don't
need to enroll it again. A newer test kit's installer also replaces the old
one in place and keeps the key.

To remove everything, uninstall first, then run this in the administrator
window, and click **Revoke** for the computer on the admin page:

```powershell
Remove-Item -Recurse -Force "$env:ProgramData\Kovyr"
```

After that, installing again makes a new device key, which you have to
enroll again.

**When you are done testing:** revoke the test computer on the admin page
(its alerts and digest lines stop), and if you set
`AGENT_DIGEST_SILENT_HOURS`, delete it.

## Troubleshooting

Start with `.\status.ps1` in an administrator PowerShell window. Log lines
start with a time in UTC.

### No check-ins on the admin page

* **Is the service running?** The first line of `status.ps1` should end in
  `running`. If it says `stopped`, run `.\check-in-now.ps1`.
* **Is `AGENT_VERIFY_ENABLED` set to `1`** on the Railway worker? Without
  it, the page keeps saying "waiting".
* **Did you just enroll?** After a refusal, the agent waits longer between
  tries, up to 15 minutes. Run `.\check-in-now.ps1` to try at once.
* Then look at the log lines in `status.ps1`, below.

### The log says `challenge: HTTP 403`

For example:
`heartbeat not made (no server challenge: challenge: HTTP 403); next try in 40s`.

Kovyr does not know this computer:

* it is not enrolled yet (step 6), or was enrolled under a different
  customer than you are looking at;
* the `device_id` on the admin page is not the one `status.ps1` prints
  (paste the whole block again);
* the computer was **revoked**: click **Re-activate** on the admin page.

### The clock is wrong

Kovyr refuses a check-in whose time is more than **5 minutes** off. VM
clocks often fall behind after the Mac sleeps. The agent cannot tell (it is
refused later, by halden's checker), so the log looks fine, but the admin
page shows no new check-in.

Compare the time `status.ps1` prints with your phone. To fix it: **Settings
→ Time & language → Date & time**, make sure **Set time automatically** is
on, and click **Sync now**. Then run `.\check-in-now.ps1`.

To confirm in Supabase, the newest row of `agent_heartbeats_raw` shows
`reject_reason` `stale_timestamp` or `future_timestamp`.

### Proxy or network errors

Log lines with `dial tcp`, `no such host`, `i/o timeout`, `proxyconnect` or
`x509: certificate` mean the agent cannot reach `agent.kovyr.com` on port
443.

* The agent connects directly. It does **not** use Windows' proxy settings,
  and it refuses networks that inspect HTTPS (common at offices and some
  hotels).
* Test on your home network. A VM's default network setting ("shared" or
  "NAT") works.
* Check that this opens in the test computer's browser and shows a
  "forbidden" error (that is the right answer for an unknown device):
  `https://agent.kovyr.com/api/agent/v0/challenge?device=dev_0000000000000000`

### The installer stops with an error

* **"A program run as part of the setup did not finish as expected"**: the
  agent's install step failed and the installer undid everything. The
  reason is in the agent's log: run
  `Get-Content "$env:ProgramData\Kovyr\logs\agent.log" -Tail 20` and look
  for lines with `service install:`. If there is no such folder, the
  install stopped before it made the key.
* **"The Kovyr Protection Alarm service is already installed, but not by
  this installer"**: it was installed by hand earlier. Remove that copy
  with the command the message shows, then run the installer again.
* **The log says "marked for deletion"**: the Services window was open
  while the old copy was removed. Close it (or restart Windows) and run the
  installer again.
* **Smart App Control blocked it** (Windows 11): this test build is not
  code-signed yet, and Smart App Control does not allow unsigned
  installers. Stop and tell Claude: the fix is signing the installer. Do not
  switch Smart App Control off on a computer you care about; Windows can't
  switch it back on without a reinstall.

### The ransomware test sent nothing

* **Was it within 30 minutes of the last test?** See test A.
* **Did the script say Documents or Desktop are not normal folders?**
  OneDrive "folder backup" or a company policy moved them. The agent does
  not watch moved folders yet, so the test cannot trip it on this
  computer. Use a test computer without OneDrive folder backup.
* **Is the tripwire watching?** The admin page's tripwire column should say
  watching. If your Windows account was created after the agent started,
  run `.\check-in-now.ps1` (the agent looks for user folders when it
  starts), then run the test again.
* **Did Windows Security say "Unauthorized changes blocked"?** Controlled
  folder access stopped PowerShell from writing in Documents, so nothing
  was renamed. Run the test on a computer without it.

### The protection-off email did not come

* It needs **two** check-ins in a row with protection off (test B).
* If another antivirus is installed, Defender is not the active one and
  the alarm judges that antivirus instead.
* If Tamper Protection can't be switched off, the computer is managed by
  an organisation: use another test computer.

### No emails at all

* Look in spam, and check the address: the email goes to the test
  customer's **owner** (step 5).
* Check `AGENT_ALERTS_ENABLED` = `1` on the Railway worker.
* The admin page shows, for each open episode, whether the owner was
  emailed or why it failed.
