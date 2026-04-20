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

Not all bugs qualify as security vulnerabilities. Bugs exploitable through the
VPP **dataplane** (e.g. a crafted packet causing a crash or remote code
execution) are security vulnerabilities and must be reported privately.
Bugs reachable only through the VPP binary API or debug CLI are handled through
the normal bug tracker, because the API caller is considered a trusted operator.

For the full scope definition, see the `Security Scope section`_ of the
vulnerability management policy.

.. _Security Scope section:
   tsc_vulnerability_management_v2.html#security-scope
