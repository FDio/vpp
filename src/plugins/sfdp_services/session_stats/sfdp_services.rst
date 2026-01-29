SFDP Session Statistics Service
===============================

Overview
--------

``sfdp-session-stats`` is an SFDP service that provides comprehensive
per-session statistics collection and export. It tracks packet/byte counts,
timing information, TTL/RTT metrics, and TCP-specific statistics for tracked
sessions.

It aims to port to the ``flow-quality`` service from the SASC infrastructure into the
SFDP infrastructure.

Statistics are collected at **session granularity**.

Key Features
~~~~~~~~~~~~

- Per-session packet and byte counters (bidirectional)
- TTL statistics with min/max/mean/stddev per direction
- RTT estimation with mean/stddev per direction
- TCP-specific metrics: SYN/FIN/RST counters, retransmissions, zero-window events, partial overlaps, etc.
- ECN/CWR congestion notification tracking
- Setting custom u64 value per-tenant through API, which can be used to introduce external labels and/or for data correlation
- Ring buffer export to VPP stats segment for external consumption
- IPv4 and IPv6 traffic support


Collected Statistics
~~~~~~~~~~~~~~~~~~~~

All statistics are maintained per-session and collected inline per-packet
in the ``sfdp-session-stats`` node. Struct definitions are in
`session_stats.h <../session_stats/session_stats.h>`_
and per-packet processing logic is in
`node.c <../session_stats/node.c>`_.

**IP-Level (all protocols)**

.. table::
   :widths: 35 65

   ======================================= ==========================================================
   Statistic                               Description
   ======================================= ==========================================================
   Packet count (per direction)            Total packets seen in forward and reverse directions
   Byte count (per direction)              Total bytes at IP level, including headers
   First/last seen timestamps              Timestamps of the first and last packet of the session
   Session duration                        Time elapsed between first and last packet
   TTL / hop-limit (per direction)         Min, max, mean, and standard deviation (Welford's algorithm)
   ======================================= ==========================================================

**TCP-Specific**

.. table::
   :widths: 35 65

   ============================================ ==========================================================
   Statistic                                    Description
   ============================================ ==========================================================
   SYN / FIN / RST counts                       Number of each control packet type
   Handshake completion                          Whether the 3-way handshake completed
   MSS                                          Maximum Segment Size extracted from SYN options
   Sequence / ACK tracking (per direction)       Last sequence and acknowledgment numbers seen
   Retransmissions (per direction)               Segments fully within already-seen sequence space
   Partial overlaps (per direction)              Segments that partially overlap previously seen data
   Duplicate ACKs (per direction)                Repeated ACKs with outstanding unacknowledged data
   Zero-window events (per direction)            Edge-triggered transitions to receiver window of zero
   Out-of-order segments (per direction)         *Defined but not yet implemented*
   RTT estimate (per direction)                  Mean and standard deviation via probe-and-match (Welford's)
   ECN ECT / CE packets                          Packets with ECT(0)/ECT(1) or Congestion Experienced in IP header
   ECE / CWR packets                             TCP ECE and CWR flag counts
   ============================================ ==========================================================

Exposing Session Statistics
~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are two mechanisms to access session statistics:

**API Dump (``sfdp_session_stats_dump``)**

The API dump walks all tracked sessions and returns structured data via the
VPP binary API. It runs on the **main thread** and is blocking for the
duration of the dump. Suitable for debugging and low-frequency queries,
but not recommended for high-rate polling with large session counts.

The dump supports filtering by ``session_id`` and ``tenant_idx``.

**Ring Buffer Export**

Session statistics can be exported to a ring buffer in the VPP stats
segment. This is the recommended path for external consumption.

- **Entry size**: currently set to 384 bytes, to fit on 6 cache lines.
- **Schema**: JSON, generated at ring init time (schema version 6).
  Published alongside ring data at ``/sfdp/session/stats``. The schema
  describes field names, types, and byte offsets for binary decoding.
- **Data format**: Entries are serialized in binary. External consumers
  can parse the JSON schema to identify the format used and decode the entries.

Ring buffer exports can be triggered by:

- **Periodic export**: Configurable interval (default 30s). All active
  sessions with traffic are dumped every interval.
- **Session expiry**: Automatically exports a session's final stats when
  the session expires (enabled by default).
- **On-demand**: Via API (``sfdp_session_stats_export_now``) or CLI
  (``sfdp session stats export``).

Custom Data
~~~~~~~~~~~

A 64-bit user-defined value can be attached **per-tenant** and is included
in every exported ring buffer entry for sessions belonging to that tenant.

- Set via ``sfdp_session_stats_set_custom_api_data`` API (tenant_id + u64 value)
- On export: if set, the value populates the ``api_data`` field and sets flag
  ``SFDP_SESSION_STATS_CUSTOM_FLAG_API_DATA`` flag.
- The custom data field name defaults to ``"custom_api_data"`` but can be
  customized via ``sfdp_session_stats_set_custom_api_data_name``
  (max 20 chars, must be set **before** ring buffer is enabled).
- Bulk clear: use tenant_id ``0xFFFFFFFF`` to clear all tenants at once.

Session Exporter Program
~~~~~~~~~~~~~~~~~~~~~~~~

For Prometheus scraping of session metrics, use ``vpp_session_stats_export``.
It consumes ``/sfdp/session/stats`` from the VPP stats segment and serves HTTP
endpoint ``/metrics``.
The current implementation is an independent C program, but the same
ring-buffer consumption/export logic could also be implemented in other
languages (for example Go or Python).

Exporter flow summary:

- The exporter reads the JSON schema stored in ring-buffer metadata and parses
  it with ``vppinfra/cJSON``.
- Parsed schema fields are validated to determine which session fields are
  present and usable (checks if 'core' information is present, like session src-dst IPs, ports, etc).
- Only valid/available fields are decoded from ring entries and then exposed as
  Prometheus metrics with session labels.
- The exporter keeps a local cache of active sessions instead of exposing only the
  latest raw ring entries: caching preserves the last
  known values per session between exports and avoids metric flapping
- The cache also enables stale-session handling via ``session-timeout`` (silent
  sessions are skipped during emission).

.. code-block:: none

   # In VPP CLI: enable ring export
   sfdp session stats ring enable [size <n>]

   # Optional: periodic session export (otherwise trigger on demand)
   sfdp session stats periodic enable [interval <seconds>]
   sfdp session stats export

   # In shell: run the session exporter
   vpp_session_stats_export [socket-name <path>] [port <0-65535>] \
     [session-timeout <seconds>] [instance <name>]

   # Verifying statistics exposed by program
   curl http://127.0.0.1:9482/metrics

Defaults: ``port=9482`` and ``session-timeout=300`` seconds.


CLI Reference
~~~~~~~~~~~~~

.. code-block:: none

   # Display session statistics
   show sfdp session stats [session <id>] [tenant <idx>] [max <n>] [verbose]

   # Ring buffer control
   sfdp session stats ring enable [size <n>]    # default size: 4096
   sfdp session stats ring disable

   # Periodic export control
   sfdp session stats periodic enable [interval <seconds>]
   sfdp session stats periodic disable

   # Trigger immediate export
   sfdp session stats export

   # Set custom data value for a tenant
   sfdp session stats custom-data tenant <id> value <n>

   # Clear custom data for a tenant (or all tenants)
   sfdp session stats custom-data [tenant <id>] clear

   # Custom data field name (must be set before ring enable)
   sfdp session stats custom-data-name name <name>

   # Clear statistics
   clear sfdp session stats [session <id>]

For a complete working example — including tenant creation, service chain
setup, and ring buffer configuration — see
`setup.pg <../../../src/plugins/sfdp_services/session_stats/setup.pg>`_.

Known Limitations
~~~~~~~~~~~~~~~~~

- **Out-of-order detection**: The TCP out-of-order event counter is defined
  but not yet implemented in the packet processing node.
- **Ring buffer format**: Session data is dumped in native binary format.
  The JSON schema (in ring buffer metadata) must be used to decode entries.
  No text/structured export format is provided directly.
- **Ring buffer overflow**: Sessions are dumped naively. If the number of
  active sessions exceeds the ring buffer size, older entries will be
  overwritten during a single export cycle.
- **Custom data granularity**: Custom data is per-tenant only. There is no
  mechanism for per-session or per-scope custom data.
- **Testing**: No IPv6-specific tests are currently present.
