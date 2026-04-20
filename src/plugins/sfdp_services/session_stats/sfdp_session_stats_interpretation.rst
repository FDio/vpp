.. Copyright (c) 2025 Cisco Systems, Inc.

.. _sfdp_session_stats_interpretation:

Reading and Interpreting Session Statistics
===========================================

This document explains how to read the statistics exported by the
``sfdp-session-stats`` service and what they indicate about connection
quality and potential optimisations.

.. note::

   Most per-session TCP counters are derived from passive middlebox
   observations with no access to transport-layer state (SACK blocks,
   RACK reorder window, receiver-side buffers). Individual session
   counts should be treated as directional indicators, not exact
   measurements. Population-level trends across many sessions are
   more reliable.


Basic Counters
--------------

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Statistic
     - How to read it
   * - ``packets_forward`` / ``packets_reverse``
     - Total packets per direction. A large asymmetry (e.g. forward >>
       reverse) is expected for bulk downloads but unusual for
       interactive or RPC-style traffic.
   * - ``bytes_forward`` / ``bytes_reverse``
     - Total bytes at the IP level (including headers). Divide by
       ``packets`` to get average packet size; values consistently below
       ~500 B suggest small-write application behaviour or ACK flooding.
   * - ``first_seen`` / ``last_seen`` / duration
     - Session lifetime. Very short sessions with high packet counts may
       indicate connection reuse problems or aggressive retransmission.


RTT Statistics
--------------

RTT values are window-scoped: they are reset after each ring-buffer
export (default every 30 s), so each exported snapshot reflects only
activity within that interval.

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Statistic
     - How to read it
   * - ``rtt_mean_forward`` / ``rtt_mean_reverse``
     - Mean RTT per direction estimated from probe-and-match (a data
       segment's send timestamp matched against its cumulative ACK).
       Elevated values indicate path latency or endpoint processing delay.
   * - ``rtt_stddev_forward`` / ``rtt_stddev_reverse``
     - RTT jitter. High stddev relative to the mean suggests queuing
       delay variability (buffer bloat) or inconsistent routing.
   * - ``syn_rtt``
     - One-shot RTT measured between the initiator's SYN and its
       handshake-completing ACK. Unlike ``rtt_mean``, this is a lifetime
       value (not reset on export) and gives a clean baseline RTT
       unaffected by data-phase congestion. Compare ``syn_rtt`` to
       ``rtt_mean`` to detect whether RTT grew over the session lifetime.


TTL / Hop-limit Statistics
--------------------------

TTL statistics are window-scoped (reset after each export interval).

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Statistic
     - How to read it
   * - ``ttl_min`` / ``ttl_max``
     - A stable min/max (e.g. always 63) means consistent routing. A
       fluctuating min (e.g. 58–63 in the same window) indicates
       asymmetric or load-balanced routing with different path lengths.
   * - ``ttl_stddev``
     - Non-zero stddev combined with a low min hints at path changes mid-
       session. Useful for diagnosing ECMP instability.


TCP Data vs. Control Packet Ratio
----------------------------------

The ``tcp_data_packets_forward`` / ``tcp_data_packets_reverse`` counters
count only segments carrying a non-zero TCP payload.  Dividing these by
the corresponding total ``packets`` gives the *data packet ratio*.

.. code-block:: text

   data_ratio_fwd = tcp_data_packets_fwd / packets_forward

**What the ratio indicates:**

- **High ratio (> 0.7)**: Most packets carry payload.  The connection is
  bulk-transferring efficiently.  Retransmission or loss events here have
  a larger per-packet cost.
- **Low ratio (< 0.3)**: Most packets are control-only (pure ACKs, SYN,
  FIN, window updates).  Common causes and their optimisations:

  - *Many small application writes*: Nagle algorithm may be disabled
    (``TCP_NODELAY``).  Re-enabling Nagle or batching writes at the
    application level reduces segment proliferation.
  - *Chatty request-response protocol*: Consider pipelining or
    multiplexing (e.g. HTTP/2, gRPC).
  - *Very short-lived sessions*: Connection setup/teardown overhead
    dominates.  HTTP keep-alive or connection pooling would help.

- **Asymmetric ratios** (high fwd, low rev or vice versa): Expected for
  uni-directional bulk traffic (e.g. large upload: high fwd, low rev
  carrying only ACKs).  Unexpected asymmetry in interactive sessions
  may indicate half-duplex application behaviour.

Combining with retransmission counters:

.. code-block:: text

   loss_rate_fwd = tcp_retransmissions_fwd / tcp_data_packets_fwd

A loss rate above 1–2 % generally warrants investigation.  See
:ref:`tcp_event_counters` below.


.. _tcp_event_counters:

TCP Event Counters
------------------

.. note::

   These counters are based on passive sequence-number observation at a
   middlebox.  Modern TCP stacks (Linux ≥ 4.19, FreeBSD ≥ 12) use
   time-based loss detection (RACK, RFC 8985) and can retransmit after 0
   or 1 duplicate ACK rather than waiting for 3.  Our dupack snapshot
   logic may therefore under-count retransmissions and over-count
   out-of-order events.  Treat these as population-level trend indicators.

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Statistic
     - How to read it
   * - ``tcp_retransmissions_fwd/rev``
     - Segments whose sequence range fell entirely below the highest
       previously seen sequence number, classified as loss (not reorder)
       based on dupack state. Elevated counts indicate packet loss on
       the path or aggressive retransmission timeouts.
   * - ``tcp_out_of_order_fwd/rev``
     - Segments filling a sequence gap *without* observed dupacks, likely
       caused by network reordering rather than loss. Persistent OOO on
       a path with known single-path routing may indicate NIC receive-
       side scaling (RSS) mis-delivery at the capture point.
   * - ``tcp_partial_overlaps_fwd/rev``
     - Segments that partially overlap the high-water sequence mark.
       Can indicate retransmission of a larger segment than was lost, or
       middlebox TSO split artifacts.
   * - ``tcp_dupack_events_fwd/rev``
     - Repeated ACK with same cumulative ACK number while unacknowledged
       data exists. A signal that the receiver saw a gap. On RACK-enabled
       stacks, loss recovery may start before 3 dupacks are reached.
   * - ``tcp_zero_window_events_fwd/rev``
     - Transitions to a receive window of zero. Each event is edge-
       triggered (one count per transition into zero, not per packet).
       Frequent zero-window events indicate receiver-side buffer pressure:
       the application is not consuming data fast enough, or socket
       receive buffers are undersized.


ECN / Congestion Notification
------------------------------

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Statistic
     - How to read it
   * - ``tcp_ecn_ect_packets``
     - Packets with ECT(0) or ECT(1) set: both endpoints negotiated ECN
       and the sender is marking packets as ECN-capable.
   * - ``tcp_ecn_ce_packets``
     - Packets marked Congestion Experienced (CE) by a router. Indicates
       active queue management (AQM) signalling congestion on the path.
       High CE counts without retransmissions confirm ECN is working as
       intended (congestion is being signalled without packet drops).
   * - ``tcp_ece_packets``
     - TCP ECE flag: the receiver is echoing a CE mark back to the sender.
     - Together with CWR, confirms end-to-end ECN feedback loop is active.
   * - ``tcp_cwr_packets``
     - TCP CWR flag: the sender has reduced its congestion window in
       response to ECE.  Persistent CWR indicates the path is congested
       and the sender is repeatedly throttling.


Custom / Opaque Fields
-----------------------

``opaque`` and ``opaque2`` carry tenant-defined 64-bit labels set via
``sfdp_session_stats_set_tenant_custom_data``.  Their meaning is
operator-defined; typical uses include external correlation IDs, VRF
tags, or policy class markers.
