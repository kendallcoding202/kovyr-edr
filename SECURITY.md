# Security policy

Kovyr EDR is an agent that runs as SYSTEM on small offices' Windows
computers. If you have found a way to misuse it, its installer, its
heartbeats or the proof format, we want to hear about it, privately,
before anyone else does.

## How to report a vulnerability

**Please do not open a public issue or pull request.**

1. Open the repository's **Security** tab and click **Report a
   vulnerability**
   (https://github.com/kendallcoding202/kovyr-edr/security/advisories/new).
   Only the maintainer sees the report. We can talk it through there, fix
   it in a private fork and credit you in the advisory if you want.
2. If you can't use GitHub, email **kendall@kovyr.com** with the subject
   "Security report". Leave out exploit details in that first email: we
   will reply with a private GitHub advisory to continue in.

Helpful to include: what an attacker can do, what they need first (for
example a standard user account on the PC, or a position on the network),
the commit or test-kit version, and steps to reproduce.

## What to expect

Kovyr is built by one person, part-time. We read reports on working days
and aim to reply within 7 days, to agree a fix and a disclosure date with
you, and to publish a GitHub security advisory once a fix ships. There is
no 24/7 security team and no bug bounty.

## Scope

In scope: the code in this repository (the agent, the installer, the
heartbeat protocol, the proof format and verifier) and the test kits
built by this repository's CI on `main`.

Please test only on computers and accounts you own. Do not test against
kovyr.com or agent.kovyr.com, a Kovyr customer's computers, or anyone
else's data.

## Not this page: a computer under attack now

This page is for reporting bugs. Kovyr is not a 24/7 response service.
If you think a computer is being attacked right now, disconnect it from
the network (unplug the cable or turn off Wi-Fi), leave it switched on,
and call your IT provider.
