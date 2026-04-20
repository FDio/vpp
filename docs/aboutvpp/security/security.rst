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
   tsc_vulnerability_management_v2.rst

Security Response Team
======================

At the `August, 25th 2016 TSC meeting`_,
the TSC approved the security response team charter
and initial membership:

.. _August, 25th 2016 TSC meeting:
   http://ircbot.wl.linuxfoundation.org/meetings/fdio-meeting/2016/fdio-meeting.2016-08-25-15.03.html

- David Jorm (elected chair)
- Ed Warnicke
- Jim Thompson
- Dave Wallace
- Mathieu Lemay

The team can be reached at the above private security
mailing list.

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
