Reporting Security Issues
=========================

Please report any security issues you find in fd.io to: <security@lists.fd.io>.

Anyone can post to this list. The subscribers are only
trusted individuals who will handle the resolution of
any reported security issues in confidence. In your
report, please note how you would like to be credited
for discovering the issue and the details of any embargo
you would like to impose.

The fd.io vulnerability management process is
`documented here`_.

.. _documented here:
   tsc_vulnerability_management_v3.html

The description of the potential security vulnerability must endeavor to
accurately depict the nature of the flaw. Information that should be included must
indicate the attack vector that is exposed by the flaw and the initial access
level required by the attacker. Where applicable, please advise how an operator may audit
for abuse of the flaw within their environment.

The FD.io TSC Vulnerability Management process requires that the CVSS v4.0 score be calculated
and the score and vector / tag string be submitted by the reporter.

Please use the CVSS v4.0 calculator [0], the documented scoring rubrics [1], and the CVSS
Implementation guide [2] (Threat, Environmental, and Supplemental groups) to evaluate the issue.
Please include both the numeric CVSS v4.0 score and the complete CVSS vector / tag string to this email.

Note: the Supplemental group is optional and may be elided from the calculation as it has no effect on the CVSS score.

[0] https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator
[1] https://www.first.org/cvss/v4.0/user-guide#Scoring-Rubrics
[2] https://www.first.org/cvss/v4.0/implementation-guide

Security Response Team
======================

At the `August 25, 2016 TSC meeting`_,
the FD.io TSC approved the security response team charter
and initial membership, approved Dave Wallace as chair and
Maciek Konstantynowicz membership at the `June 4, 2026 TSC meeting`_,
and approved Florin Coras membership at the `June 11, 2026 TSC meeting`_:

.. _August 25, 2016 TSC meeting:
   http://ircbot.wl.linuxfoundation.org/meetings/fdio-meeting/2016/fdio-meeting.2016-08-25-15.03.html

.. _June 4, 2026 TSC meeting:
   https://ircbot.wl.linuxfoundation.org/meetings/fdio-meeting/2026/fd_io_tsc/fdio-meeting-fd_io_tsc.2026-06-04-15.01.html

.. _June 11, 2026 TSC meeting:
   https://ircbot.wl.linuxfoundation.org/meetings/fdio-meeting/2026/fd_io_tsc/fdio-meeting-fd_io_tsc.2026-06-11-15.00.html

- Dave Wallace (elected chair)
- Jim Thompson
- Maciek Konstantynowicz
- Florin Coras

The team can be reached at the above private security
mailing list.

Emeritus SRT Members
--------------------
 - David Jorm (chair)
 - Ed Warnicke
 - Mathieu Lemay

Security Scope
==============

Understanding which issues qualify as security vulnerabilities determines
whether to follow the private embargo process or the normal bug tracker.

Dataplane bugs
--------------

A bug is a **security vulnerability** if it is exploitable through the VPP
**dataplane** — that is, by a remote or unauthenticated attacker sending
crafted packets processed by the VPP forwarding graph, without requiring
any pre-existing privileged access to the system.

Examples:

- A crafted packet that crashes VPP (denial of service).
- A crafted packet that achieves remote code execution inside the VPP process.
- Any memory-safety flaw reachable purely through normal packet-processing paths.

Such issues **must** be reported privately and handled under the embargo
process described in this document.

Trusted API
-----------

The VPP binary API is a **trusted interface**. The caller of the VPP API
is assumed to be in the same administrative trust domain as VPP itself —
typically the operator or orchestration/management plane. A process that can
reach the VPP API socket or debug CLI already has operator-level trust.

Consequently, the following are **not** treated as security vulnerabilities:

- Crashing or causing undefined behavior in VPP via the binary API.
- Exploiting VPP through the debug CLI (``vppctl``).
- Any issue that requires prior API or CLI access as a precondition.

These are still bugs and should be reported through the normal public bug
tracker. They are **not** subject to embargo.
