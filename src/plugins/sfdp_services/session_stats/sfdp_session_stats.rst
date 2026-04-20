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
- RTT estimation with mean/stddev per direction, honouring Karn's algorithm
  under retransmission/overlap
- One-shot TCP handshake RTT (``syn_rtt``), with a one-way fallback that works
  when only the initiator direction is visible
- TCP-specific metrics: SYN/FIN/RST counters, data-vs-control packet split,
  retransmissions, zero-window events, partial overlaps, duplicate ACKs,
  out-of-order classification
- ECN/CWR congestion notification tracking
- Setting custom u64 value per-tenant through API, which can be used to
  introduce external labels and/or for data correlation
- Ring buffer export to VPP stats segment for external consumption
- Window-scoped Welford statistics (TTL / RTT reset on each successful
  ring export) so exported values reflect the current interval rather than the
  whole session lifetime
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
   Packet count (per direction)            Total packets seen in forward and reverse directions (lifetime)
   Byte count (per direction)              Total bytes at IP level, including headers (lifetime)
   First/last seen timestamps              Timestamps of the first and last packet of the session
   Session duration                        Time elapsed between first and last packet
   TTL / hop-limit (per direction)         Min, max, mean, and standard deviation (Welford); window-scoped
   ======================================= ==========================================================

**TCP-Specific**

.. table::
   :widths: 35 65

   ============================================ ==========================================================
   Statistic                                    Description
   ============================================ ==========================================================
   SYN / FIN / RST counts                       Number of each control packet type (lifetime)
   Handshake completion                         Whether the 3-way handshake completed
   Handshake RTT (``syn_rtt``)                  One-shot seconds between the initiator's SYN and either
                                                the responder's SYN-ACK (bidirectional, preferred) or the
                                                initiator's handshake-completing ACK (one-way fallback).
                                                Lifetime scalar; latched once, not reset on export.
   MSS                                          Maximum Segment Size extracted from SYN options
   Data packets (per direction)                 Packets carrying non-empty TCP payload; denominator for
                                                loss rate and mean segment size (lifetime)
   Sequence / ACK tracking (per direction)      Last sequence and acknowledgment numbers seen
   Retransmissions (per direction)              Segments within seen sequence space, confirmed as loss by
                                                duplicate ACKs or prior ACK (lifetime)
   Partial overlaps (per direction)             Segments that partially overlap previously seen data
                                                (lifetime)
   Duplicate ACKs (per direction)               Repeated ACKs with outstanding unacknowledged data
                                                (lifetime)
   Zero-window events (per direction)           Edge-triggered transitions to receiver window of zero
                                                (lifetime)
   Out-of-order segments (per direction)        Segments filling a gap without preceding duplicate ACKs
                                                (lifetime)
   RTT estimate (per direction)                 Mean and standard deviation via probe-and-match (Welford);
                                                window-scoped. Probes armed by retransmits or partial
                                                overlaps are discarded as ambiguous.
   ECN ECT / CE packets                         Packets with ECT(0)/ECT(1) or Congestion Experienced in
                                                IP header (lifetime)
   ECE / CWR packets                            TCP ECE and CWR flag counts (lifetime)
   ============================================ ==========================================================

Window-Scoped vs Lifetime Statistics
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two categories of statistic are emitted:

- **Lifetime** (cumulative since session start): packet/byte counts, TCP
  event counters (SYN/FIN/RST, ECE/CWR, ECN ECT/CE, retransmissions, partial
  overlaps, duplicate ACKs, out-of-order, zero-window events), data-packet
  counters, last seq/ack, MSS, handshake completion, and ``syn_rtt``.
- **Window-scoped** (reset at each successful ring-buffer export): TTL
  min/max/mean/stddev and RTT mean/stddev.

With steady-cadence periodic exports (default 30s), consumers see a time
series where each window-scoped value describes activity within that
interval. This keeps statistics responsive to recent changes instead of
being smoothed by a long session history. A window value of 0 combined
with ``rtt_count`` unchanged means "no sample in this interval", not
"measured 0".

**Timing caveat:** reset happens on successful ring commit, not on a
wall-clock boundary. If the ring is full and reservation fails, the
export bails out before the reset block, so the accumulators continue
growing until the next successful commit (which then covers both
intervals).

Handshake-RTT measurement
~~~~~~~~~~~~~~~~~~~~~~~~~

Two code paths can latch ``syn_rtt``, in preference order:

1. **Bidirectional (preferred)** — stamp origination on the initiator's
   pure SYN; compute ``now - syn_timestamp[ack_dir]`` when the responder's
   SYN-ACK arrives. Measures the pure SYN→SYN-ACK network RTT.
2. **One-way fallback** — if the SYN-ACK was not observed at this vantage
   point, the same timestamp is differenced against the initiator's
   handshake-completing ACK. This measures the full 3WHS wall-time from
   the initiator's perspective (SYN + network RTT + initiator's stack
   delay to emit the ACK, usually sub-ms for kernel TCP).

The sampler only runs while ``tcp.handshake_complete == 0`` so mid-session
SYNs (half-open probes, scanners) cannot overwrite the measurement. The
``syn_rtt == 0.0`` guard ensures the bidirectional value wins the race
whenever both paths are available.

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

- **Schema identifier**:  to ensure consistency between VPP and external consumers,
  the ring buffer entry format is defined in API typedef ``sfdp_session_stats_ring_entry``.
  An ABI ID is generated from a dedicated API marker message CRC
  (``sfdp_session_stats_ring_entry_abi_id_<crc>``) and published alongside
  ring data at ``/sfdp/session/stats``, so that external consumers can
  verify if they are using the appropriate entry format.

Ring buffer exports can be triggered by:

- **Periodic export**: Configurable interval (default 30s). Active sessions
  with traffic are exported in batches of up to ``ring_size`` entries,
  sleeping ``batch_interval`` seconds between batches.
- **Session expiry**: Automatically exports a session's final stats when
  the session expires (enabled by default).
- **On-demand**: Via API (``sfdp_session_stats_export_now``) or CLI
  (``sfdp session stats export``).

Custom Data
~~~~~~~~~~~

A 64-bit user-defined value can be attached **per-tenant** and is included
in every exported ring buffer entry for sessions belonging to that tenant.

- Set via ``sfdp_session_stats_set_tenant_custom_data`` API (tenant_id + u64 value)
- On export: the value is always written to the ring field ``opaque``.
  If a tenant has no configured value, ``opaque`` is exported as ``0``.
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

- The exporter validates the abi id stored in ring-buffer metadata & associated with the
  ring buffer entry format, and exits if format mismatch is detected
- Ring entries are decoded using the static API typedef layout (wire to
  host conversion) and exposed as Prometheus metrics with session labels.
- Each exporter Prometheus samples include an explicit unix timestamp (in milliseconds),
  derived from the last ring update seen for that session.
- If the exporter session cache reaches capacity, the oldest cached entry
  (least recent update timestamp) is evicted to make room for new sessions.
  Capacity is configurable via ``max-tracked-sessions``.
- Cached entries remain in memory, but sessions that have not been updated
  for longer than ``session-timeout`` are skipped during emission.

.. code-block:: none

   # In VPP CLI: enable ring export
   sfdp session stats ring enable [size <n>]

   # Optional: periodic session export (otherwise trigger on demand)
   sfdp session stats periodic enable [interval <seconds>]
   sfdp session stats export

   # In shell: run the session exporter
   vpp_session_stats_export [socket-name <path>] [port <0-65535>] \
     [session-timeout <seconds>] \
     [max-tracked-sessions <n>] \
     [instance <name>] \
     [opaque-label <name>] \
     [debug]

   # Verifying statistics exposed by program
   curl http://127.0.0.1:9482/metrics

Defaults: ``port=9482``, ``session-timeout=300`` seconds, and
``max-tracked-sessions=10000``.


CLI Reference
~~~~~~~~~~~~~

.. code-block:: none

   # Display session statistics
   show sfdp session stats [session <id>] [tenant <idx>] [max <n>] [verbose]

   # Ring buffer control
   sfdp session stats ring enable [size <n>]    # default size: 4096
   sfdp session stats ring disable

   # Periodic export control
   sfdp session stats periodic enable [interval <seconds>] [batch-interval <seconds>]
   sfdp session stats periodic disable

   # Trigger immediate export
   sfdp session stats export

   # Set custom data value for a tenant
   sfdp session stats custom-data tenant <id> value <n>

   # Clear custom data for a tenant (or all tenants)
   sfdp session stats custom-data [tenant <id>] clear

   # Clear statistics
   clear sfdp session stats [session <id>]

For a complete working example — including tenant creation, service chain
setup, and ring buffer configuration — see
`setup.pg <../../../src/plugins/sfdp_services/session_stats/setup.pg>`_.

Known Limitations
~~~~~~~~~~~~~~~~~

- **Ring buffer overflow**: API-triggered exports (``export-now``) dump all
  sessions in a single unbatched call. If the number of active sessions
  exceeds the ring buffer size, older entries will be overwritten.
- **Testing**: No IPv6-specific tests are currently present.
