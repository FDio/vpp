# Security Policy

## Reporting a Security Issue

Please report security issues to the fd.io security team at:
**security@lists.fd.io**

This is a private list accessible only to trusted security team members.
Do not file a public bug or GitHub issue for security vulnerabilities.

The full vulnerability management process is documented in
`docs/aboutvpp/security/tsc_vulnerability_management_v2.rst`.

## Security Scope

### What IS a security bug (report privately)

A bug is a **security vulnerability** if it is exploitable through the VPP
**dataplane** — that is, by sending crafted packets on a network interface
processed by the VPP forwarding graph — without any prior privileged access to
the system.

Examples:
- A crafted packet that crashes VPP (denial of service via the dataplane)
- A crafted packet that achieves remote code execution inside the VPP process
- Any memory-safety flaw reachable through normal packet-processing paths

These must be reported privately and handled under embargo.

### What is NOT a security bug (report via normal bug tracker)

The **VPP binary API** is a **trusted interface**. The API caller is assumed to
be in the same administrative trust domain as VPP (operator / management
plane). A process that can reach the VPP API socket already has operator-level
trust.

The following are **not** security vulnerabilities — they are still bugs we
want fixed, but they go through the normal public bug process:
- Crashing or triggering undefined behavior in VPP via the binary API
- Any bug requiring prior API or CLI (`vppctl`) access as a precondition

## Further Reading

- `docs/aboutvpp/security/security.rst` — contact info and team
- `docs/aboutvpp/security/tsc_vulnerability_management_v2.rst` — full policy
- `docs/aboutvpp/security/security_advisories.rst` — past CVEs
