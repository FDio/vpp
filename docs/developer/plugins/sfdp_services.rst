.. _sfdp_services:

SFDP Session Statistics Service
===============================

Overview
--------

'sfdp-session-stats' is a SFDP service that provides comprehensive
per-session statistics collection and export. It tracks packet/byte counts,
timing information, TTL/RTT metrics, and TCP-specific statistics for tracked
sessions.

Statistics are collected at **session granularity**.

Key Features
~~~~~~~~~~~~

- Per-session packet and byte counters (bidirectional)
- TTL statistics with min/max/mean/stddev per direction
- RTT estimation with mean/stddev per direction
- TCP-specific metrics: SYN/FIN/RST counters, retransmissions, zero-window events
- ECN/CWR congestion notification tracking
- Custom API data for external correlation (64-bit per tenant/context)
- Ring buffer export to VPP stats segment for external consumption


Known Limitations
~~~~~~~~~~~~~~~~~

- Counters - TCP 'out-of-order' event counter is currently unset/unused
- Ring Buffer - Session information is dumped in binary format to ring buffer,
but the schema used for session information is shared in JSON format in ring
buffer metadata.
- Ring Buffer - Sessions are naively dumped to ring buffer, meaning that
if the number of sessions is larger than the ring buffer size, then entries
will be overwritten during dump time.
- Custom Data - Custom data can be specified per-tenant currently,
there are no mechanisms to specify custom data with per-session or per-scope
granularity.
- Testing - No IPv6 tests are currently present

