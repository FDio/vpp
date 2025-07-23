// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

/*
 * TCP Anomaly Detection Service
 *
 * This module provides comprehensive TCP anomaly detection including:
 *
 * 1. 3-Way Handshake Validation:
 *    - Validates proper SYN -> SYN-ACK -> ACK sequence
 *    - Detects unexpected SYN packets
 *    - Handles session version mismatches
 *
 * 2. Session State Tracking:
 *    - Tracks connection establishment, data transfer, and teardown phases
 *    - Validates FIN/ACK sequences during graceful closure
 *    - Handles RST packets for immediate termination
 *
 * 3. Anomaly Detection:
 *    - Retransmission detection with configurable thresholds
 *    - Packet reordering detection with configurable tolerance
 *    - Fast retransmit detection (3 duplicate ACKs)
 *    - TCP flag malformation detection
 *    - Invalid header length detection
 *
 * 4. Error Counters:
 *    - Session-specific anomaly counters for granular tracking
 *    - Per-session anomaly monitoring and debugging
 *    - Direct counter increments for minimal overhead
 *    - Real-time monitoring capabilities for network health
 *    - Total anomalies calculated on-demand when reporting
 *
 * 5. Modular Design:
 *    - Separated flag processing logic for better maintainability
 *    - Helper functions for session initialization and cleanup
 *    - Clear separation of concerns between anomaly detection and state management
 *    - Direct session-specific counter updates for maximum performance
 *
 * Configuration:
 *    - retransmit_threshold: Time threshold for retransmission detection (default: 100ms)
 *    - reorder_tolerance: Sequence number tolerance for reorder detection (default: 100000)
 *
 * Session Flags:
 *    - WAIT_FOR_RESP_SYN: Waiting for SYN-ACK response
 *    - WAIT_FOR_INIT_ACK_TO_SYN: Waiting for ACK to SYN-ACK
 *    - WAIT_FOR_RESP_ACK_TO_SYN: Waiting for ACK to SYN
 *    - SEEN_FIN_INIT: FIN seen from initiator
 *    - SEEN_FIN_RESP: FIN seen from responder
 *    - SEEN_ACK_TO_FIN_INIT: ACK to initiator FIN seen
 *    - SEEN_ACK_TO_FIN_RESP: ACK to responder FIN seen
 *    - ESTABLISHED: Connection fully established
 *    - REMOVING: Session being removed
 *    - BLOCKED: Session blocked due to protocol violation
 *    - RETRANSMIT_DETECTED: Retransmission anomaly detected
 *    - REORDER_DETECTED: Packet reordering anomaly detected
 *
 * Key Functions:
 *    - update_state_one_pkt: Main entry point for packet processing
 *    - process_tcp_flags: Handles TCP flag processing and state transitions
 *    - check_tcp_anomalies: Detects various TCP anomalies
 *    - init_tcp_session: Handles session initialization and reset
 *    - finalize_session_state: Handles final state updates and cleanup
 */

#include <vlib/vlib.h>
#include <sasc/service.h>
#include <sasc/sasc.h>
#include <sasc/sasc_funcs.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include "tcp_check.h"
#include <sasc/services/tcp-check/tcp_check.api_enum.h>
#include "counter.h"
#include <sasc/export.h>

typedef struct {
    u32 flow_id;
    u32 old_state_flags;
    u32 new_state_flags;
    u8 close_cause;
} sasc_tcp_check_trace_t;

/* Unified TCP options parse result */
typedef struct {
    u8 has_mss;
    u8 has_wscale;
    u8 has_tstamp;
    u8 has_sack;
    u8 sack_permitted; /* valid only if parsed from SYN/SYN-ACK */
    u16 mss;
    u8 wscale;
    u32 tsval;
    u32 tsecr;
    u8 num_sack_blocks;
    /* ECN flags from TCP header */
    u8 has_ece; /* ECN-Echo flag */
    u8 has_cwr; /* Congestion Window Reduced flag */
} sasc_tcp_parsed_opts_t;

/* Unified TCP options parser */
static_always_inline void
sasc_parse_tcp_options(tcp_header_t *tcp, u8 is_syn_segment, sack_block_t *sack_blocks_out,
                       u8 max_sack_blocks, sasc_tcp_parsed_opts_t *out) {
    clib_memset(out, 0, sizeof(*out));
    if (!tcp)
        return;

    /* Extract ECN flags from TCP header */
    out->has_ece = (tcp->flags & TCP_FLAG_ECE) ? 1 : 0;
    out->has_cwr = (tcp->flags & TCP_FLAG_CWR) ? 1 : 0;

    const u8 hdr_len = tcp_header_bytes(tcp);
    if (hdr_len <= sizeof(tcp_header_t))
        return;

    const u8 *options = (const u8 *)tcp + sizeof(tcp_header_t);
    u8 opts_len = hdr_len - sizeof(tcp_header_t);
    u8 off = 0;

    while (off < opts_len) {
        u8 kind = options[off];
        if (kind == 0) /* EOL */
            break;
        if (kind == 1) { /* NOP */
            off++;
            continue;
        }
        if (off + 1 >= opts_len)
            break; /* malformed */
        u8 len = options[off + 1];
        if (len < 2 || off + len > opts_len)
            break; /* malformed */

        switch (kind) {
        case 2: /* MSS */
            if (is_syn_segment && len == 4) {
                out->has_mss = 1;
                out->mss = clib_net_to_host_u16(*(u16 *)(options + off + 2));
            }
            break;
        case 3: /* Window scale */
            if (is_syn_segment && len == 3) {
                out->has_wscale = 1;
                out->wscale = options[off + 2];
                if (out->wscale > TCP_MAX_WND_SCALE)
                    out->wscale = TCP_MAX_WND_SCALE;
            }
            break;
        case 8: /* Timestamp */
            if (len == TCP_OPTION_LEN_TIMESTAMP) {
                out->has_tstamp = 1;
                out->tsval = clib_net_to_host_u32(*(u32 *)(options + off + 2));
                out->tsecr = clib_net_to_host_u32(*(u32 *)(options + off + 6));
            }
            break;
        case 4: /* SACK permitted */
            if (is_syn_segment && len == TCP_OPTION_LEN_SACK_PERMITTED) {
                out->sack_permitted = 1;
            }
            break;
        case 5: /* SACK blocks */
            if (len >= 10 && ((len - 2) % TCP_OPTION_LEN_SACK_BLOCK) == 0) {
                u8 blks = (len - 2) / TCP_OPTION_LEN_SACK_BLOCK;
                u8 can_copy = 0;
                if (sack_blocks_out && max_sack_blocks > out->num_sack_blocks) {
                    can_copy = clib_min((u8)(max_sack_blocks - out->num_sack_blocks), blks);
                    for (u8 i = 0; i < can_copy; i++) {
                        u32 start = clib_net_to_host_u32(*(u32 *)(options + off + 2 + 8 * i));
                        u32 end = clib_net_to_host_u32(*(u32 *)(options + off + 6 + 8 * i));
                        sack_blocks_out[out->num_sack_blocks + i].start = start;
                        sack_blocks_out[out->num_sack_blocks + i].end = end;
                    }
                }
                out->num_sack_blocks +=
                    can_copy ? can_copy : blks; /* track count even if not copied */
                if (out->num_sack_blocks)
                    out->has_sack = 1;
            }
            break;
        default:
            break; /* ignore */
        }
        off += len;
    }
}

static u8 *
format_sasc_tcp_check_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_tcp_check_trace_t *t = va_arg(*args, sasc_tcp_check_trace_t *);
    u32 indent = format_get_indent(s);
    indent += 2;
    s = format(s, "sasc-tcp-check: flow-id %u (session %u, %s)\n", t->flow_id, t->flow_id >> 1,
               t->flow_id & 0x1 ? "reverse" : "forward");
    s = format(s, "%Uold session flags: %U\n", format_white_space, indent,
               format_sasc_tcp_check_session_flags, t->old_state_flags);
    s = format(s, "%Unew session flags: %U\n", format_white_space, indent,
               format_sasc_tcp_check_session_flags, t->new_state_flags);
    s = format(s, "%Uclose_cause: %u\n", format_white_space, indent, t->close_cause);
    return s;
}

static inline u64
get_anom_total(const sasc_service_state_t *st, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp = (const sasc_tcp_check_session_state_t *)st;

    return tcp->invalid_tcp_header_count + tcp->malformed_flags_count + tcp->unexpected_syn_count +
           tcp->protocol_violation_count + tcp->invalid_fin_ack_count + tcp->fast_retransmit_count +
           tcp->window_probe_count + tcp->handshake_timeout_count;
}
static inline double
get_fwd_rtt_ms(const sasc_service_state_t *st, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp_session = (const sasc_tcp_check_session_state_t *)st;
    if (tcp_session->rtt_count[SASC_FLOW_FORWARD] > 0) {
        f64 avg_rtt =
            tcp_session->rtt_sum[SASC_FLOW_FORWARD] / tcp_session->rtt_count[SASC_FLOW_FORWARD];
        return avg_rtt * 1000.0;
    }
    return 0.0;
}
static inline double
get_rev_rtt_ms(const sasc_service_state_t *st, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp_session = (const sasc_tcp_check_session_state_t *)st;
    if (tcp_session->rtt_count[SASC_FLOW_REVERSE] > 0) {
        f64 avg_rtt =
            tcp_session->rtt_sum[SASC_FLOW_REVERSE] / tcp_session->rtt_count[SASC_FLOW_REVERSE];
        return avg_rtt * 1000.0;
    }
    return 0.0;
}

/* Approximate percentile from per-session log2 RTT histogram */
static_always_inline double
approx_rtt_percentile_ms(const sasc_tcp_check_session_state_t *tcp_session, u8 dir, double pct) {
    if (tcp_session->rtt_count[dir] == 0)
        return 0.0;
    u32 total = 0;
    for (u8 b = 0; b < 16; b++)
        total += tcp_session->rtt_histogram[dir][b];
    if (total == 0)
        return 0.0;
    u32 target = (u32)(((u64)total * pct + 0.5) / 100.0);
    u32 acc = 0;
    u8 chosen = 0;
    for (u8 b = 0; b < 16; b++) {
        acc += tcp_session->rtt_histogram[dir][b];
        if (acc >= target) {
            chosen = b;
            break;
        }
    }
    /* Map bin index back to approximate ms; log2 histogram → ~2^bin_index */
    double approx_ms = (double)(1u << chosen);
    return approx_ms;
}
static_always_inline f64
clamp01(f64 x) {
    return x < 0 ? 0 : (x > 1 ? 1 : x);
}
static_always_inline f64
inv1p(f64 x, f64 k) {
    return 1.0 / (1.0 + k * (x < 0 ? 0 : x));
} // smooth penalty

static_always_inline f64
sasc_tcp_quality_index_for_dir(const sasc_tcp_check_session_state_t *tcp,
                               const sasc_session_t *session, u8 dir) {
    // Volumes
    //   u64 bytes = session->bytes[dir];
    //   u32 pkts = tcp->packet_count[dir];
    u32 data_pkts = tcp->data_packet_count[dir] ? tcp->data_packet_count[dir] : 1;
    u32 ack_pkts = tcp->ack_packet_count[dir] ? tcp->ack_packet_count[dir] : 1;

    // Reliability (including ECN congestion detection)
    u32 retx = tcp->retransmit_count[dir];
    u32 spurious_full = tcp->spurious_retransmit_count;
    u32 adj_retx = (retx > spurious_full) ? (retx - spurious_full) : 0;
    u32 ecn_ce = tcp->ecn_ce_count[dir];
    f64 congestion_rate =
        (f64)(adj_retx + ecn_ce) / (f64)data_pkts; // retx + ECN CE per data packet
    f64 retx_burstness = (f64)tcp->retransmit_burst_count[dir];
    f64 fast_retx = (f64)tcp->fast_retransmit_count;
    f64 ecn_ce_rate = (f64)ecn_ce / (f64)data_pkts; // ECN CE rate
    f64 S_reliability =
        clamp01(0.50 * inv1p(congestion_rate, 8.0) + 0.25 * inv1p(retx_burstness, 0.5) +
                0.15 * inv1p(fast_retx, 1.0) + 0.10 * inv1p(ecn_ce_rate, 4.0)); // ECN penalty

    // Ordering
    f64 reorder_rate = (f64)tcp->reorder_count[dir] / (f64)data_pkts;
    f64 S_ordering = inv1p(reorder_rate, 6.0);

    // Latency (use avg/min and spread since we don't track variance)
    f64 avg_rtt = (tcp->rtt_count[dir] > 0) ? (tcp->rtt_sum[dir] / tcp->rtt_count[dir]) : 0.0;
    f64 min_rtt = tcp->rtt_min[dir] > 0 ? tcp->rtt_min[dir] : (avg_rtt > 0 ? avg_rtt : 0.001);
    f64 max_rtt = tcp->rtt_max[dir] > 0 ? tcp->rtt_max[dir] : avg_rtt;
    f64 infl = avg_rtt / (min_rtt > 0 ? min_rtt : 0.001); // inflation factor
    f64 jitterish = (avg_rtt > 0) ? (max_rtt - min_rtt) / avg_rtt : 0.0;
    f64 S_latency = clamp01(0.6 * inv1p(infl - 1.0, 2.0) + 0.4 * inv1p(jitterish, 2.0));

    // Flow control stress
    f64 zwp_rate = (f64)tcp->window_probe_count / (f64)ack_pkts;
    f64 S_flow = inv1p(zwp_rate, 8.0);

    // SACK health
    u32 sack_inv = tcp->sack_invalid_blocks[dir];
    u32 sack_blocks = tcp->sack_blocks_received[dir] ? tcp->sack_blocks_received[dir] : 1;
    f64 sack_bad_rate = (f64)sack_inv / (f64)sack_blocks;
    f64 S_sack = inv1p(sack_bad_rate, 10.0);

    // Combine (weights sum to 1)
    f64 dir_S =
        0.35 * S_reliability + 0.20 * S_ordering + 0.25 * S_latency + 0.10 * S_flow + 0.10 * S_sack;

    return dir_S; // 0..1
}

static_always_inline f64
sasc_tcp_quality_index(const sasc_tcp_check_session_state_t *tcp, const sasc_session_t *session) {
    // Base quality from directions weighted by delivered bytes
    u64 f_bytes = session->bytes[SASC_FLOW_FORWARD];
    u64 r_bytes = session->bytes[SASC_FLOW_REVERSE];
    f64 Sf = sasc_tcp_quality_index_for_dir(tcp, session, SASC_FLOW_FORWARD);
    f64 Sr = sasc_tcp_quality_index_for_dir(tcp, session, SASC_FLOW_REVERSE);
    f64 S_base = (f_bytes + r_bytes) ? ((Sf * f_bytes + Sr * r_bytes) / (f64)(f_bytes + r_bytes)) :
                                       0.5 * (Sf + Sr);

    // Handshake/closure guard rails
    f64 S_handshake = (tcp->flags & SASC_TCP_CHECK_SESSION_FLAG_ESTABLISHED) ? 1.0 : 0.0;
    f64 close_pen = 0.0;
    switch ((sasc_tcp_close_cause_t)tcp->close_cause) {
    case SASC_TCP_CLOSE_NONE:
        close_pen = 0.00;
        break;
    case SASC_TCP_CLOSE_GRACEFUL:
        close_pen = 0.00;
        break;
    case SASC_TCP_CLOSE_SIMULTANEOUS_FIN:
        close_pen = 0.05;
        break;
    case SASC_TCP_CLOSE_HALF_CLOSED_FWD:
    case SASC_TCP_CLOSE_HALF_CLOSED_REV:
        close_pen = 0.10;
        break;
    case SASC_TCP_CLOSE_ABORT_AFTER_FIN_FWD:
    case SASC_TCP_CLOSE_ABORT_AFTER_FIN_REV:
        close_pen = 0.25;
        break;
    case SASC_TCP_CLOSE_ABORT_MIDSTREAM:
        close_pen = 0.40;
        break;
    case SASC_TCP_CLOSE_HANDSHAKE_RESET:
        close_pen = 0.60;
        break;
    }

    // Handshake anomalies (soft penalties)
    f64 hs_bad = (f64)tcp->handshake_ack_mismatch_count + (f64)tcp->unexpected_syn_count;
    f64 S_hsanom = inv1p(hs_bad, 0.5);

    // Final mix
    f64 S = S_base;
    S *= (0.85 + 0.15 * S_handshake); // boost if properly established
    S *= (0.90 + 0.10 * S_hsanom);    // small hit for handshake anomalies
    S *= (1.0 - close_pen);           // closure penalty

    // clamp and scale to 0..100
    S = clamp01(S);
    return 100.0 * S;
}

static inline double
get_fwd_rtt_p50_ms(const sasc_service_state_t *st, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp_session = (const sasc_tcp_check_session_state_t *)st;
    return approx_rtt_percentile_ms(tcp_session, SASC_FLOW_FORWARD, 0.50);
}
static inline double
get_rev_rtt_p50_ms(const sasc_service_state_t *st, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp_session = (const sasc_tcp_check_session_state_t *)st;
    return approx_rtt_percentile_ms(tcp_session, SASC_FLOW_REVERSE, 0.50);
}
static inline double
get_fwd_rtt_p95_ms(const sasc_service_state_t *st, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp_session = (const sasc_tcp_check_session_state_t *)st;
    return approx_rtt_percentile_ms(tcp_session, SASC_FLOW_FORWARD, 0.95);
}
static inline double
get_rev_rtt_p95_ms(const sasc_service_state_t *st, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp_session = (const sasc_tcp_check_session_state_t *)st;
    return approx_rtt_percentile_ms(tcp_session, SASC_FLOW_REVERSE, 0.95);
}

static inline f64
get_quality_index(const sasc_service_state_t *st, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp_session = (const sasc_tcp_check_session_state_t *)st;
    sasc_session_t *session = &sasc_main.sessions[session_index];
    return sasc_tcp_quality_index(tcp_session, session);
}

// TCP check service field descriptions
static const sasc_field_desc_t tcp_check_desc[] = {
    {"flags", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, flags), -1, NULL, NULL, NULL,
     NULL, false},
    {"fwd_retransmits", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, retransmit_count), 0,
     NULL, NULL, NULL, NULL, false},
    {"rev_retransmits", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, retransmit_count), 1,
     NULL, NULL, NULL, NULL, false},
    {"fwd_reorders", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, reorder_count), 0, NULL,
     NULL, NULL, NULL, false},
    {"rev_reorders", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, reorder_count), 1, NULL,
     NULL, NULL, NULL, false},
    {"anomalies_total", SASC_T_U32, 0, -1, (sasc_get_u64_fn)get_anom_total, NULL, NULL, NULL,
     false},
    {"fwd_rtt_avg_ms", SASC_T_F64, 0, -1, NULL, (sasc_get_f64_fn)get_fwd_rtt_ms, NULL, NULL, false},
    {"rev_rtt_avg_ms", SASC_T_F64, 0, -1, NULL, (sasc_get_f64_fn)get_rev_rtt_ms, NULL, NULL, false},
    {"fwd_rtt_p50_ms", SASC_T_F64, 0, -1, NULL, (sasc_get_f64_fn)get_fwd_rtt_p50_ms, NULL, NULL,
     false},
    {"rev_rtt_p50_ms", SASC_T_F64, 0, -1, NULL, (sasc_get_f64_fn)get_rev_rtt_p50_ms, NULL, NULL,
     false},
    {"fwd_rtt_p95_ms", SASC_T_F64, 0, -1, NULL, (sasc_get_f64_fn)get_fwd_rtt_p95_ms, NULL, NULL,
     false},
    {"rev_rtt_p95_ms", SASC_T_F64, 0, -1, NULL, (sasc_get_f64_fn)get_rev_rtt_p95_ms, NULL, NULL,
     false},
    {"quality_index", SASC_T_F64, 0, -1, NULL, (sasc_get_f64_fn)get_quality_index, NULL, NULL,
     false},
    {"spurious_retx_count", SASC_T_U32,
     offsetof(sasc_tcp_check_session_state_t, spurious_retransmit_count), -1, NULL, NULL, NULL,
     NULL, false},
    {"spurious_retx_partial_bytes", SASC_T_U32,
     offsetof(sasc_tcp_check_session_state_t, spurious_retransmit_partial_bytes), -1, NULL, NULL,
     NULL, NULL, false},
    {"close_cause", SASC_T_U8, offsetof(sasc_tcp_check_session_state_t, close_cause), -1, NULL,
     NULL, NULL, NULL, false},
    {"close_time_s", SASC_T_F64, offsetof(sasc_tcp_check_session_state_t, close_time), -1, NULL,
     NULL, NULL, NULL, false},
    {"half_closed_dir", SASC_T_U8, offsetof(sasc_tcp_check_session_state_t, half_closed_dir), -1,
     NULL, NULL, NULL, NULL, false},
    {"keepalive_probes", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, keepalive_count), -1,
     NULL, NULL, NULL, NULL, false},
    {"handshake_ack_mismatch", SASC_T_U32,
     offsetof(sasc_tcp_check_session_state_t, handshake_ack_mismatch_count), -1, NULL, NULL, NULL,
     NULL, false},
    {"fwd_sack_blocks", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, sack_blocks_received),
     0, NULL, NULL, NULL, NULL, false},
    {"rev_sack_blocks", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, sack_blocks_received),
     1, NULL, NULL, NULL, NULL, false},
    {"fwd_sack_bytes", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, sack_bytes_received), 0,
     NULL, NULL, NULL, NULL, false},
    {"rev_sack_bytes", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, sack_bytes_received), 1,
     NULL, NULL, NULL, NULL, false},
    {"fwd_sack_invalid", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, sack_invalid_blocks),
     0, NULL, NULL, NULL, NULL, false},
    {"rev_sack_invalid", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, sack_invalid_blocks),
     1, NULL, NULL, NULL, NULL, false},
    {"fwd_sack_reneging", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, sack_reneging_count),
     0, NULL, NULL, NULL, NULL, false},
    {"rev_sack_reneging", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, sack_reneging_count),
     1, NULL, NULL, NULL, NULL, false},
    {"ecn_negotiated", SASC_T_U8, offsetof(sasc_tcp_check_session_state_t, ecn_negotiated), -1,
     NULL, NULL, NULL, NULL, false},
    {"fwd_ecn_ce_count", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, ecn_ce_count), 0,
     NULL, NULL, NULL, NULL, false},
    {"rev_ecn_ce_count", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, ecn_ce_count), 1,
     NULL, NULL, NULL, NULL, false},
    {"fwd_ecn_ect_count", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, ecn_ect_count), 0,
     NULL, NULL, NULL, NULL, false},
    {"rev_ecn_ect_count", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, ecn_ect_count), 1,
     NULL, NULL, NULL, NULL, false},
    {"fwd_ecn_ce_bytes", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, ecn_ce_bytes), 0,
     NULL, NULL, NULL, NULL, false},
    {"rev_ecn_ce_bytes", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, ecn_ce_bytes), 1,
     NULL, NULL, NULL, NULL, false},
    {"fwd_ecn_ect_bytes", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, ecn_ect_bytes), 0,
     NULL, NULL, NULL, NULL, false},
    {"rev_ecn_ect_bytes", SASC_T_U32, offsetof(sasc_tcp_check_session_state_t, ecn_ect_bytes), 1,
     NULL, NULL, NULL, NULL, false},
};

static const size_t tcp_check_field_count = sizeof(tcp_check_desc) / sizeof(tcp_check_desc[0]);

static cbor_item_t *
format_sasc_tcp_check_service_cbor(u32 thread_index, u32 session_index) {
    const sasc_tcp_check_session_state_t *tcp = &sasc_tcp_check_main.state[session_index];
    return sasc_encode_array_generic(tcp_check_desc, tcp_check_field_count,
                                     (const sasc_service_state_t *)tcp, session_index);
}

static u8 *
format_sasc_tcp_check_service(u8 *s, u32 thread_index, u32 session_index, bool detail) {
    sasc_tcp_check_main_t *tcm = &sasc_tcp_check_main;
    sasc_tcp_check_session_state_t *tcp_session = &tcm->state[session_index];
    sasc_session_t *session = &sasc_main.sessions[session_index];

    if (!detail) {
        return format(s,
                      "%Usasc-tcp-check: RTT:%.1fms/%.1fms Quality:%.2f | Retx:%u/%u Anomalies:%u "
                      "| SACK:%u/%u ECN:%u/%u\n",
                      format_white_space, 2, tcp_session->rtt_mean[0] * 1000,
                      tcp_session->rtt_mean[1] * 1000, sasc_tcp_quality_index(tcp_session, session),
                      tcp_session->retransmit_count[0], tcp_session->retransmit_count[1],
                      tcp_session->invalid_tcp_header_count + tcp_session->malformed_flags_count +
                          tcp_session->unexpected_syn_count +
                          tcp_session->protocol_violation_count +
                          tcp_session->invalid_fin_ack_count + tcp_session->fast_retransmit_count +
                          tcp_session->window_probe_count + tcp_session->handshake_timeout_count +
                          tcp_session->starts_without_syn_count,
                      tcp_session->sack_blocks_received[0], tcp_session->sack_blocks_received[1],
                      tcp_session->ecn_ce_count[0] + tcp_session->ecn_ce_count[1],
                      tcp_session->ecn_ect_count[0] + tcp_session->ecn_ect_count[1]);
    }

    /* Use generic text formatter */
    return sasc_format_text_generic(s, tcp_check_desc, tcp_check_field_count,
                                    (const sasc_service_state_t *)tcp_session, session_index,
                                    "sasc-tcp-check");
}

static cbor_item_t *
export_tcp_check_schema(void) {
    return sasc_export_schema_generic("tcp_check", tcp_check_desc, tcp_check_field_count, 1);
}

/**
 * @brief Parse SACK Permitted flag from a SYN/SYN-ACK segment.
 *
 * @param tcp Pointer to the TCP header
 * @param tcp_hdr_len Length of the TCP header
 * @return true if SACK Permitted (kind=4,len=2) option is present
 */
static_always_inline bool
parse_tcp_sack_permitted(tcp_header_t *tcp, u8 tcp_hdr_len) {
    if (tcp_hdr_len <= 20)
        return false;
    u8 *options = (u8 *)tcp + 20;
    u8 options_len = tcp_hdr_len - 20;
    u8 i = 0;
    while (i < options_len) {
        u8 kind = options[i];
        if (kind == 0)
            break; /* EOL */
        if (kind == 1) {
            i++;
            continue;
        } /* NOP */
        if (i + 1 >= options_len)
            break; /* malformed */
        u8 len = options[i + 1];
        if (len < 2 || i + len > options_len)
            break; /* malformed */
        if (kind == 4 && len == 2)
            return true; /* SACK permitted */
        i += len;
    }
    return false;
}

/**
 * @brief Compute overlap (in bytes) between a segment and SACK blocks.
 */
static_always_inline u32
segment_sacked_overlap(const sack_block_t *blocks, u8 count, u32 seq, u32 len) {
    if (count == 0 || len == 0)
        return 0;
    u32 end = seq + len;
    u32 overl = 0;
    for (u8 i = 0; i < count; i++) {
        u32 s = blocks[i].start, e = blocks[i].end;
        if (e <= seq || s >= end)
            continue; // no overlap
        u32 ls = (seq > s) ? seq : s;
        u32 le = (end < e) ? end : e;
        overl += (le - ls);
    }
    return overl;
}

/**
 * @brief Centralized function to update RTT statistics.
 *
 * @param tcp_session Pointer to the session state.
 * @param dir The direction for which to update stats.
 * @param rtt The calculated RTT value.
 */
static_always_inline void
do_rtt_stat_update(sasc_tcp_check_session_state_t *tcp_session, u8 dir, f64 rtt) {
    u32 thread_index = vlib_get_thread_index();
    if (rtt < 0)
        return; /* Clock issues or very long-delayed packet */

    if (tcp_session->rtt_count[dir] == 0) {
        tcp_session->rtt_min[dir] = rtt;
        tcp_session->rtt_max[dir] = rtt;
        tcp_session->rtt_mean[dir] = rtt;
        tcp_session->rtt_M2[dir] = 0.0;
    } else {
        if (rtt < tcp_session->rtt_min[dir])
            tcp_session->rtt_min[dir] = rtt;
        if (rtt > tcp_session->rtt_max[dir])
            tcp_session->rtt_max[dir] = rtt;
        /* Welford update */
        f64 delta = rtt - tcp_session->rtt_mean[dir];
        tcp_session->rtt_mean[dir] += delta / (tcp_session->rtt_count[dir] + 1);
        f64 delta2 = rtt - tcp_session->rtt_mean[dir];
        tcp_session->rtt_M2[dir] += delta * delta2;
    }

    tcp_session->rtt_sum[dir] += rtt;
    tcp_session->rtt_count[dir]++;

    /* Update histogram using log2 bins for better resolution at lower RTT values */
    u32 rtt_ms = rtt * 1000;
    u8 bin_index = vlib_log2_histogram_bin_index(&sasc_tcp_check_main.rtt_histogram, rtt_ms);
    vlib_increment_log2_histogram_bin(&sasc_tcp_check_main.rtt_histogram, thread_index, bin_index,
                                      1);
    tcp_session->rtt_histogram[dir][bin_index]++;
}

/**
 * @brief Updates Round-Trip Time (RTT) statistics for a TCP session.
 *
 * @param tcp_session Pointer to the session state.
 * @param current_time The current time.
 * @param dir The direction of the current packet.
 * @param ts_val The TSval from the current packet's TCP options.
 * @param ts_ecr The TSecr from the current packet's TCP options.
 */
static_always_inline void
update_rtt_stats(sasc_tcp_check_session_state_t *tcp_session, f64 current_time, u8 dir, u32 ts_val,
                 u32 ts_ecr) {
    u8 other_dir = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;

    if (ts_ecr != 0 && tcp_session->last_ts_val[other_dir] != 0 &&
        ts_ecr == tcp_session->last_ts_val[other_dir]) {
        f64 rtt = current_time - tcp_session->last_ts_time[other_dir];
        do_rtt_stat_update(tcp_session, other_dir, rtt);
    }

    if (ts_val != 0) {
        tcp_session->last_ts_val[dir] = ts_val;
        tcp_session->last_ts_time[dir] = current_time;
    }
}

/**
 * @brief Updates RTT statistics using sequence and acknowledgment numbers.
 *
 * @param tcp_session Pointer to the session state.
 * @param current_time The current time.
 * @param dir The direction of the current packet.
 * @param tcp Pointer to the TCP header.
 * @param data_len The data length of the packet.
 */
static_always_inline void
update_rtt_stats_no_ts(sasc_tcp_check_session_state_t *tcp_session, f64 current_time, u8 dir,
                       tcp_header_t *tcp, u32 data_len) {
    u32 seqnum = clib_net_to_host_u32(tcp->seq_number);
    u32 acknum = clib_net_to_host_u32(tcp->ack_number);
    u8 other_dir = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;

    // Check if this packet is an ACK for a data segment we sent in the other direction
    if ((tcp->flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) && tcp_session->rtt_seq[other_dir] != 0 &&
        acknum >= tcp_session->rtt_seq[other_dir]) {
        f64 rtt = current_time - tcp_session->rtt_time[other_dir];
        do_rtt_stat_update(tcp_session, other_dir, rtt);
        tcp_session->rtt_seq[other_dir] = 0; // Clear the tracked sequence
    }

    // If this packet has data and we aren't already tracking a segment for RTT in this direction
    if (data_len > 0 && tcp_session->rtt_seq[dir] == 0) {
        tcp_session->rtt_seq[dir] = seqnum + data_len;
        tcp_session->rtt_time[dir] = current_time;
    }
}

/**
 * @brief Process TCP RTT from TCP options.
 *
 * @param tcp_session Pointer to the session state.
 * @param current_time The current time.
 * @param dir The direction of the current packet.
 * @param tcp Pointer to the TCP header.
 * @param data_len The data length of the packet.
 */
static_always_inline void
process_tcp_rtt(sasc_tcp_check_session_state_t *tcp_session, f64 current_time, u8 dir,
                tcp_header_t *tcp, u32 data_len, const sasc_tcp_parsed_opts_t *opts) {
    if (opts && opts->has_tstamp) {
        update_rtt_stats(tcp_session, current_time, dir, opts->tsval, opts->tsecr);
    } else {
        update_rtt_stats_no_ts(tcp_session, current_time, dir, tcp, data_len);
    }
}

/**
 * @brief Detects SACK-related anomalies and updates statistics.
 *
 * @param tcp_session Pointer to the session state.
 * @param dir The direction of the current packet.
 * @param sack_blocks Array of SACK blocks from the packet.
 * @param num_sack_blocks Number of SACK blocks in the array.
 * @param acknum The ACK number from the packet.
 * @param current_time Current timestamp.
 * @param thread_index Thread index for counter updates.
 * @param tenant_idx Tenant index for counter updates.
 */
/* Parse ECN from IP header and update session state */
static_always_inline void
process_ecn_marks(sasc_tcp_check_session_state_t *tcp_session, u8 dir, ip_ecn_t ecn, u32 data_len,
                  u32 thread_index, u16 tenant_idx) {
    if (ecn == IP_ECN_CE) {
        /* Congestion Experienced mark */
        tcp_session->ecn_ce_count[dir]++;
        tcp_session->ecn_ce_bytes[dir] += data_len;
        vlib_increment_simple_counter(
            &sasc_tcp_check_main.counters[SASC_TCP_CHECK_COUNTER_ECN_CE_MARK], thread_index,
            tenant_idx, 1); // TODO: Move this to session close if really need as global counters
    } else if (ecn == IP_ECN_ECT_0 || ecn == IP_ECN_ECT_1) {
        /* ECN-Capable Transport mark */
        tcp_session->ecn_ect_count[dir]++;
        tcp_session->ecn_ect_bytes[dir] += data_len;
        vlib_increment_simple_counter(
            &sasc_tcp_check_main.counters[SASC_TCP_CHECK_COUNTER_ECN_ECT_MARK], thread_index,
            tenant_idx, 1);
    }
}

static_always_inline void
check_sack_anomalies(sasc_tcp_check_session_state_t *tcp_session, u8 dir, sack_block_t *sack_blocks,
                     u8 num_sack_blocks, u32 acknum, f64 current_time, u32 thread_index,
                     u16 tenant_idx) {
    sasc_tcp_check_main_t *stcm = &sasc_tcp_check_main;

    if (num_sack_blocks == 0)
        return;

    // Update SACK statistics
    tcp_session->sack_blocks_received[dir] += num_sack_blocks;
    tcp_session->last_sack_time[dir] = current_time;
    if (num_sack_blocks < 16)
        tcp_session->sack_blocks_per_packet[dir][num_sack_blocks]++;

    // Process each SACK block for anomalies
    for (u8 i = 0; i < num_sack_blocks; i++) {
        sack_block_t *block = &sack_blocks[i];

        // Validate SACK block
        if (block->start >= block->end) {
            tcp_session->sack_invalid_blocks[dir]++;
            vlib_increment_simple_counter(
                &stcm->counters[SASC_TCP_CHECK_COUNTER_SACK_INVALID_BLOCK], thread_index,
                tenant_idx, 1);
            sasc_log_warn("Invalid SACK block: start=%u, end=%u", block->start, block->end);
            continue;
        }

        // Update SACK high water mark
        if (block->end > tcp_session->last_sack_high_water[dir]) {
            tcp_session->last_sack_high_water[dir] = block->end;
        }

        // Calculate bytes acknowledged via SACK
        u32 sack_bytes = block->end - block->start;
        tcp_session->sack_bytes_received[dir] += sack_bytes;

        // Add to SACK history (circular buffer)
        if (tcp_session->sack_history_count[dir] < 8) {
            tcp_session->sack_history[dir][tcp_session->sack_history_count[dir]] = *block;
            tcp_session->sack_history_count[dir]++;
        } else {
            // Shift history and add new block
            for (u8 j = 0; j < 7; j++) {
                tcp_session->sack_history[dir][j] = tcp_session->sack_history[dir][j + 1];
            }
            tcp_session->sack_history[dir][7] = *block;
        }
    }
    // (SACK blocks beyond ACK are normal and indicate out-of-order arrival.)
}

static_always_inline void
check_tcp_anomalies(sasc_tcp_check_main_t *stcm, u32 thread_index, u16 tenant_idx,
                    sasc_tcp_check_session_state_t *tcp_session, sasc_session_t *session,
                    f64 current_time, u8 dir, tcp_header_t *tcp, u32 data_len, ip_ecn_t ecn,
                    const sasc_tcp_parsed_opts_t *opts, const sack_block_t *sack_blocks,
                    u8 num_sack_blocks) {
    u32 seqnum = clib_net_to_host_u32(tcp->seq_number);
    u32 acknum = clib_net_to_host_u32(tcp->ack_number);
    u16 window_size = clib_net_to_host_u16(tcp->window);
    u8 flags = tcp->flags & SASC_TCP_CHECK_TCP_FLAGS_MASK;
    u8 other_dir = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;

    // Calculate TCP header length
    u8 tcp_hdr_len = ((tcp->data_offset_and_reserved >> 4) & 0xF) * 4;
    if (tcp_hdr_len < 20) {
        // Invalid TCP header length
        tcp_session->invalid_tcp_header_count++;
        vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_INVALID_TCP_HEADER],
                                      thread_index, tenant_idx, 1);
        return;
    }

    /* Use parsed SACK blocks if any */
    if (opts && num_sack_blocks > 0) {
        u8 other_dir_for_perm = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;
        if (!tcp_session->sack_permitted[other_dir_for_perm]) {
            tcp_session->sack_invalid_blocks[dir]++;
            vlib_increment_simple_counter(
                &stcm->counters[SASC_TCP_CHECK_COUNTER_SACK_INVALID_BLOCK], thread_index,
                tenant_idx, 1);
            sasc_log_warn("SACK received but not permitted in direction %u", dir);
        } else {
            check_sack_anomalies(tcp_session, dir, (sack_block_t *)sack_blocks, num_sack_blocks,
                                 acknum, current_time, thread_index, tenant_idx);
        }
    }

    // Validate TCP flags for common malformations
    if ((flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) && (flags & SASC_TCP_CHECK_TCP_FLAGS_FIN)) {
        // SYN and FIN cannot be set together
        tcp_session->malformed_flags_count++;
        vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_MALFORMED_TCP_FLAGS],
                                      thread_index, tenant_idx, 1);

        sasc_log_warn("Malformed TCP flags: SYN and FIN set together");
        return;
    }

    if ((flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) && (flags & SASC_TCP_CHECK_TCP_FLAGS_RST)) {
        // SYN and RST cannot be set together
        tcp_session->malformed_flags_count++;
        vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_MALFORMED_TCP_FLAGS],
                                      thread_index, tenant_idx, 1);

        sasc_log_warn("Malformed TCP flags: SYN and RST set together");
        return;
    }

    // Skip anomaly detection for SYN/FIN/RST packets
    if (flags & (SASC_TCP_CHECK_TCP_FLAGS_SYN | SASC_TCP_CHECK_TCP_FLAGS_FIN |
                 SASC_TCP_CHECK_TCP_FLAGS_RST)) {
        return;
    }

    // Process ECN marks from IP header
    if (data_len > 0) {
        process_ecn_marks(tcp_session, dir, ecn, data_len, thread_index, tenant_idx);
    }

    // Filter TCP keepalive and zero-window probes before retransmit/reorder logic
    // TCP keepalive probe: ACK set, data_len == 0, seq = last_ack[dir]-1
    if ((flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) && data_len == 0 && tcp_session->last_ack[dir] > 0 &&
        seqnum == (tcp_session->last_ack[dir] - 1)) {
        tcp_session->keepalive_count++;
        sasc_log_debug("TCP keepalive probe detected: session %u, dir %u, count %u, seq %u",
                       session - sasc_main.sessions, dir, tcp_session->keepalive_count, seqnum);
        return; // Skip retransmit/reorder detection for keepalive probes
    }

    // Zero-window probe: data_len == 1 and last_window[other_dir] == 0
    if (data_len == 1 && tcp_session->last_window[other_dir] == 0) {
        tcp_session->window_probe_count++;
        sasc_log_debug("Zero-window probe detected: session %u, dir %u, count %u, seq %u",
                       session - sasc_main.sessions, dir, tcp_session->window_probe_count, seqnum);
        return; // Skip retransmit/reorder detection for zero-window probes
    }

    // Track zero-window episodes/duration
    if (tcp_session->last_window[other_dir] == 0) {
        if (!tcp_session->zero_window_active[other_dir]) {
            tcp_session->zero_window_active[other_dir] = 1;
            tcp_session->zero_window_start_time[other_dir] = current_time;
            tcp_session->zero_window_episodes[other_dir] += 1;
        }
    } else {
        if (tcp_session->zero_window_active[other_dir]) {
            tcp_session->zero_window_active[other_dir] = 0;
            tcp_session->zero_window_duration_total[other_dir] +=
                current_time - tcp_session->zero_window_start_time[other_dir];
        }
    }
    /* Data after FIN from this sender is a violation; request fast teardown */
    if (data_len > 0) {
        if ((dir == SASC_FLOW_FORWARD &&
             (tcp_session->flags & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT)) ||
            (dir == SASC_FLOW_REVERSE &&
             (tcp_session->flags & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP))) {
            tcp_session->protocol_violation_count++;
            tcp_session->close_cause = (dir == SASC_FLOW_FORWARD) ?
                                           SASC_TCP_CLOSE_ABORT_AFTER_FIN_FWD :
                                           SASC_TCP_CLOSE_ABORT_AFTER_FIN_REV;
            tcp_session->pending_remove_due_to_data_after_fin = 1;
            return; /* Avoid misclassifying as reorder/retransmit */
        }
    }
    // First packet in this direction: initialize session
    if (tcp_session->last_seq[dir] == 0 && tcp_session->last_ack[dir] == 0) {
        tcp_session->last_seq[dir] = seqnum;
        tcp_session->last_ack[dir] = acknum;
        tcp_session->last_pkt_time[dir] = current_time;
        tcp_session->last_flags[dir] = flags;
        tcp_session->last_data_len[dir] = data_len;
        tcp_session->last_window[dir] = window_size;
        if (data_len > 0)
            tcp_session->expected_seq[dir] = seqnum + data_len;

        // Initialize packet counters
        tcp_session->packet_count[dir]++;
        if (data_len > 0) {
            tcp_session->data_packet_count[dir]++;
        } else if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
            tcp_session->ack_packet_count[dir]++;
        }
        return;
    }

    // Update packet counters
    tcp_session->packet_count[dir]++;
    if (data_len > 0) {
        tcp_session->data_packet_count[dir]++;
    } else if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
        tcp_session->ack_packet_count[dir]++;
    }

    /* Broader retransmit detection */
    bool is_retransmit = false;
    if (data_len > 0) {
        /* Classic retransmit: same SEQ as previous data packet */
        if (tcp_session->last_data_len[dir] > 0 && seqnum == tcp_session->last_seq[dir]) {
            is_retransmit = true;
        } else if (tcp_session->expected_seq[dir] != 0 && tcp_session->last_data_len[dir] > 0 &&
                   /* payload retransmit of the immediately previous segment */
                   seqnum == tcp_session->expected_seq[dir] - tcp_session->last_data_len[dir]) {
            is_retransmit = true;
        }
    }

    if (is_retransmit) {
        /* Calculate retransmission delay relative to last packet in this direction */
        f64 retransmit_delay = current_time - tcp_session->last_pkt_time[dir];

        /* Track retransmission delay (small ring of 16) */
        if (tcp_session->retransmit_delay_count[dir] < 16) {
            tcp_session->retransmit_delays[dir][tcp_session->retransmit_delay_count[dir]] =
                retransmit_delay;
            tcp_session->retransmit_delay_count[dir]++;
        }

        /* Detect retransmission bursts (consecutive retransmits within 100ms) */
        if (current_time - tcp_session->last_retransmit_time[dir] < 0.1) {
            tcp_session->retransmit_burst_count[dir]++;
            vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_RETRANSMIT_BURST],
                                          thread_index, tenant_idx, 1);
        } else {
            tcp_session->retransmit_burst_count[dir] = 1;
            tcp_session->last_retransmit_burst_start[dir] = current_time;
        }

        vlib_increment_simple_counter(
            &sasc_tcp_check_main.counters[SASC_TCP_CHECK_COUNTER_RETRANSMIT], thread_index,
            tenant_idx, 1);
        tcp_session->retransmit_count[dir]++;
        tcp_session->last_retransmit_time[dir] = current_time;

        /* If the peer has SACKed these bytes earlier, classify as spurious or partial */
        {
            u8 od = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;
            u32 overl =
                segment_sacked_overlap(tcp_session->sack_history[od],
                                       tcp_session->sack_history_count[od], seqnum, data_len);
            if (overl == data_len) {
                tcp_session->spurious_retransmit_count++;
            } else if (overl > 0) {
                tcp_session->spurious_retransmit_partial_bytes += overl;
                sasc_log_debug(
                    "Partial spurious retransmit: session %u dir %u seq %u len %u overlap %u",
                    session - sasc_main.sessions, dir, seqnum, data_len, overl);
            }
            tcp_session->retransmit_bytes[dir] += data_len;
        }
    } else {
        /* Reordering: non-matching expected SEQ */
        if (tcp_session->expected_seq[dir] != 0 && data_len > 0 &&
            seqnum != tcp_session->expected_seq[dir]) {
            u32 expected = tcp_session->expected_seq[dir];
            u32 seq_diff = (seqnum > expected) ?
                               (seqnum - expected) :
                               (0xFFFFFFFF - expected) + seqnum + 1; /* wraparound */

            u32 tolerance = (tcp_session->reorder_tolerance > 0) ? tcp_session->reorder_tolerance :
                                                                   100000; /* default */
            u8 od = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;
            u32 peer_win = tcp_session->last_window[od];

            if (seq_diff < tolerance && (peer_win == 0 || seq_diff < peer_win)) {
                for (u8 i = 0; i < tcp_session->sack_history_count[other_dir]; i++) {
                    if (tcp_session->sack_history[other_dir][i].end > tcp_session->last_ack[dir]) {
                        break;
                    }
                }
                tcp_session->reorder_count[dir]++;
                tcp_session->reorder_bytes[dir] += data_len;
                vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_REORDER],
                                              thread_index, tenant_idx, 1);
            }
        }
    }
    // Check for fast retransmit (3 duplicate ACKs)
    if ((flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) && data_len == 0 &&
        seqnum != tcp_session->last_seq[dir]) {
        if (acknum == tcp_session->last_dup_ack_seq[dir]) {
            tcp_session->dup_ack_count[dir]++;
            if (tcp_session->dup_ack_count[dir] >= 3) {
                tcp_session->fast_retransmit_count++;
                vlib_increment_simple_counter(
                    &stcm->counters[SASC_TCP_CHECK_COUNTER_FAST_RETRANSMIT], thread_index,
                    tenant_idx, 1);
                sasc_log_warn(
                    "Fast retransmit detected: session %u, direction %u, dup_ack_count %u, ack %u",
                    session - sasc_main.sessions, dir, tcp_session->dup_ack_count[dir], acknum);
                // Reset counter after detection
                tcp_session->dup_ack_count[dir] = 0;
            }
        } else {
            tcp_session->dup_ack_count[dir] = 1;
            tcp_session->last_dup_ack_seq[dir] = acknum;
        }
    } else {
        // Reset duplicate ACK count if not a pure ACK
        tcp_session->dup_ack_count[dir] = 0;
    }

    // Process ACK to update expected_seq for other direction
    if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
        u8 other_dir = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;
        u32 acked_data =
            (acknum > tcp_session->last_ack[dir]) ? (acknum - tcp_session->last_ack[dir]) : 0;

        if (acked_data > 0) {
            tcp_session->expected_seq[other_dir] = acknum;
            sasc_log_debug(
                "ACK processing: dir=%u, acknum=%u, acked_data=%u, updated expected_seq[%u]=%u",
                dir, acknum, acked_data, other_dir, acknum);
        }

        // Pure ACK (no data) that might reflect peer's expected seq
        if (acked_data == 0 && tcp_session->last_data_len[other_dir] > 0) {
            tcp_session->expected_seq[other_dir] = acknum;
            sasc_log_debug("Pure ACK processing: dir=%u, acknum=%u, updated expected_seq[%u]=%u",
                           dir, acknum, other_dir, acknum);
        }
    }

    // Update tracking state
    tcp_session->last_seq[dir] = seqnum;
    tcp_session->last_ack[dir] = acknum;
    tcp_session->last_pkt_time[dir] = current_time;
    tcp_session->last_flags[dir] = flags;
    tcp_session->last_data_len[dir] = data_len;
    tcp_session->last_window[dir] = window_size;

    sasc_log_debug("Updated tracking state: dir=%u, seq=%u, ack=%u, data_len=%u, last_seq=%u, "
                   "last_data_len=%u",
                   dir, seqnum, acknum, data_len, tcp_session->last_seq[dir],
                   tcp_session->last_data_len[dir]);

    // Update expected_seq[dir] if this packet carries data
    if (data_len > 0) {
        tcp_session->expected_seq[dir] = seqnum + data_len;
        sasc_log_debug("Data packet: dir=%u, seq=%u, data_len=%u, updated expected_seq[%u]=%u", dir,
                       seqnum, data_len, dir, tcp_session->expected_seq[dir]);
    }
}

/**
 * Initialize or reset TCP session state
 *
 * This function handles session initialization and reset logic,
 * including version mismatch detection and default threshold setup.
 *
 * @param tcp_session TCP session state
 * @param session SASC session
 * @param flags TCP flags from current packet
 * @return 0 on success (always succeeds now)
 */
static_always_inline int
init_tcp_session(sasc_tcp_check_session_state_t *tcp_session, sasc_session_t *session, u8 flags) {
    /* Reset session state if version mismatch */
    clib_memset(tcp_session, 0, sizeof(*tcp_session));
    tcp_session->version = session->session_version;

    /* Initialize configurable thresholds with defaults */
    tcp_session->retransmit_threshold = 0.1; // 100ms default
    tcp_session->reorder_tolerance = 100000; // Default tolerance

    tcp_session->close_cause = SASC_TCP_CLOSE_NONE;
    tcp_session->half_closed_dir = 0xff;
    tcp_session->saw_simultaneous_fin = 0;
    tcp_session->close_time = 0;

    if (flags != SASC_TCP_CHECK_TCP_FLAGS_SYN) {
        /* Session starts with non-SYN packet (e.g., after restart) - increment counter and continue
         */
        sasc_log_info("Session starts with non-SYN packet (flags=0x%02x) - continuing with "
                      "established session",
                      flags);
        tcp_session->starts_without_syn_count++;
        /* Continue processing - don't block the session */
    }

    return 0;
}

/**
 * Process TCP flags and update session state flags
 *
 * This function handles the state machine transitions based on TCP flags
 * and direction. It processes SYN, ACK, FIN, and RST flags according to
 * the TCP state machine rules.
 *
 * @param tcp_session TCP session state
 * @param session SASC session
 * @param dir Packet direction (forward/reverse)
 * @param flags TCP flags
 * @param seqnum TCP sequence number
 * @param acknum TCP acknowledgment number
 * @param sf Current state flags
 * @param nsf New state flags (output)
 * @param remove_session Session removal flag (output)
 * @return 0 on success, -1 if session should be removed
 */
static_always_inline int
process_tcp_flags(sasc_tcp_check_session_state_t *tcp_session, sasc_session_t *session, u8 dir,
                  u8 flags, u32 seqnum, u32 acknum, u32 sf, u32 *nsf, u8 *remove_session,
                  tcp_header_t *tcp) {
    *nsf = sf;
    *remove_session = 0;

    /* Honor data-after-FIN violation flagged by anomaly path */
    if (PREDICT_FALSE(tcp_session->pending_remove_due_to_data_after_fin)) {
        tcp_session->pending_remove_due_to_data_after_fin = 0; /* one-shot */
        *nsf = SASC_TCP_CHECK_SESSION_FLAG_REMOVING;
        *remove_session = 1;
        return -1;
    }
    /* Default half-closed dir to none unless we observe a single-sided FIN */
    if (!(sf &
          (SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT | SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP)))
        tcp_session->half_closed_dir = 0xff;

    if (dir == SASC_FLOW_FORWARD) {
        if (sf & SASC_TCP_CHECK_SESSION_FLAG_BLOCKED)
            return 0;

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) {
            /* New session, must be a SYN otherwise bad */
            if (sf == 0) {
                *nsf = SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN |
                       SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN;
                tcp_session->syn_isn_fwd = seqnum;

                u8 tcp_hdr_len = ((tcp->data_offset_and_reserved >> 4) & 0xF) * 4;
                if (parse_tcp_sack_permitted(tcp, tcp_hdr_len))
                    tcp_session->sack_permitted[SASC_FLOW_FORWARD] = 1;

                /* Track ECN negotiation during handshake */
                if (tcp->flags & TCP_FLAG_ECE)
                    tcp_session->ecn_negotiated = 1;
            } else {
                tcp_session->unexpected_syn_count++;
                return 0;
            }
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
            /* Either ACK to SYN-ACK */
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN) {
                if (acknum != tcp_session->syn_isn_rev + 1)
                    tcp_session->handshake_ack_mismatch_count++;
                *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN;
            }
            /* Or ACK to FIN */
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP &&
                acknum >= tcp_session->fin_num[SASC_FLOW_REVERSE])
                *nsf |= SASC_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_INIT;
            else if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP) {
                /* Invalid ACK to FIN - wrong sequence number */
                tcp_session->invalid_fin_ack_count++;
            }
            /* Or regular ACK */
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_FIN) {
            /* If we were up, we are not anymore */
            *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
            /* Seen our FIN, wait for the other FIN and for an ACK */
            tcp_session->fin_num[SASC_FLOW_FORWARD] = seqnum + 1;
            *nsf |= SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT;
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP)
                tcp_session->saw_simultaneous_fin = 1;
            else
                tcp_session->half_closed_dir = SASC_FLOW_FORWARD;
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_RST) {
            /* Classify RST */
            if (sf & (SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN |
                      SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN |
                      SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN))
                tcp_session->close_cause = SASC_TCP_CLOSE_HANDSHAKE_RESET;
            else if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT)
                tcp_session->close_cause = SASC_TCP_CLOSE_ABORT_AFTER_FIN_FWD;
            else if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP)
                tcp_session->close_cause = SASC_TCP_CLOSE_ABORT_AFTER_FIN_REV;
            else
                tcp_session->close_cause = SASC_TCP_CLOSE_ABORT_MIDSTREAM;
            *remove_session = 1;
            return -1;
        }
    }

    if (dir == SASC_FLOW_REVERSE) {
        if (sf & SASC_TCP_CHECK_SESSION_FLAG_BLOCKED)
            return 0;

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) {
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN) {
                *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN;
                *nsf |= SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN;
                tcp_session->syn_isn_rev = seqnum;

                u8 tcp_hdr_len = ((tcp->data_offset_and_reserved >> 4) & 0xF) * 4;
                if (parse_tcp_sack_permitted(tcp, tcp_hdr_len))
                    tcp_session->sack_permitted[SASC_FLOW_REVERSE] = 1;

                /* Track ECN negotiation during handshake */
                if (tcp->flags & TCP_FLAG_ECE)
                    tcp_session->ecn_negotiated = 1;

                if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
                    if (acknum != tcp_session->syn_isn_fwd + 1)
                        tcp_session->handshake_ack_mismatch_count++;
                }
            }
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
            /* Either ACK to SYN */
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN)
                *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN;
            /* Or ACK to FIN */
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT &&
                acknum >= tcp_session->fin_num[SASC_FLOW_FORWARD])
                *nsf |= SASC_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_RESP;
            else if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT) {
                /* Invalid ACK to FIN - wrong sequence number */
                tcp_session->invalid_fin_ack_count++;
            }
            /* Or regular ACK */
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_FIN) {
            /* If we were up, we are not anymore */
            *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
            /* Seen our FIN, wait for the other FIN and for an ACK */
            tcp_session->fin_num[SASC_FLOW_REVERSE] = seqnum + 1;
            *nsf |= SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP;
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT)
                tcp_session->saw_simultaneous_fin = 1;
            else
                tcp_session->half_closed_dir = SASC_FLOW_REVERSE;
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_RST) {
            /* Classify RST */
            if (sf & (SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN |
                      SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN |
                      SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN))
                tcp_session->close_cause = SASC_TCP_CLOSE_HANDSHAKE_RESET;
            else if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT)
                tcp_session->close_cause = SASC_TCP_CLOSE_ABORT_AFTER_FIN_FWD;
            else if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP)
                tcp_session->close_cause = SASC_TCP_CLOSE_ABORT_AFTER_FIN_REV;
            else
                tcp_session->close_cause = SASC_TCP_CLOSE_ABORT_MIDSTREAM;
            *nsf = SASC_TCP_CHECK_SESSION_FLAG_REMOVING;
            *remove_session = 1;
            return -1;
        }
    }

    /* If all flags are cleared connection is established! */
    if (*nsf == 0) {
        *nsf = SASC_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
        /* Set the session state to TCP_ESTABLISHED when 3-way handshake is complete */
        session->state = SASC_SESSION_STATE_TCP_ESTABLISHED;
        sasc_log_debug("TCP session [%u] established after 3-way handshake validation",
                       session - sasc_main.sessions);
    }

    /* If all FINs are ACKED, game over */
    if ((*nsf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_INIT) &&
        (*nsf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_RESP)) {
        if (tcp_session->saw_simultaneous_fin)
            tcp_session->close_cause = SASC_TCP_CLOSE_SIMULTANEOUS_FIN;
        else
            tcp_session->close_cause = SASC_TCP_CLOSE_GRACEFUL;
        *nsf = SASC_TCP_CHECK_SESSION_FLAG_REMOVING;
        *remove_session = 1;
        return -1;
    }

    return 0;
}

/**
 * Handle final state transitions and session cleanup
 *
 * This function handles the final state updates and determines if a session
 * should be removed based on the processed flags and state transitions.
 *
 * @param tcp_session TCP session state
 * @param nsf New state flags
 * @param remove_session Session removal flag
 * @param result Processing result from flag processing
 */
static_always_inline void
finalize_session_state(sasc_session_t *session, sasc_tcp_check_session_state_t *tcp_session,
                       u32 nsf, u8 remove_session, int result, f64 current_time) {
    /* Update session state */
    tcp_session->flags = nsf;
    if (remove_session || result == -1) {
        sasc_log_debug("Session is being removed");

        /* Choose fast vs long transitory based on close classification.
         * - close_cause != NONE  => fast (3s)
         * - close_cause == NONE  => long (120s), e.g. half-closed/unclassified
         */
        if (tcp_session->close_cause != SASC_TCP_CLOSE_NONE) {
            session->state = SASC_SESSION_STATE_TCP_FAST_TRANSITORY;
            tcp_session->close_time = current_time;
        } else {
            session->state = SASC_SESSION_STATE_TCP_TRANSITORY;
        }
    } else {
        /* mark half-close classification so expiry can use different timers */
        if ((nsf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT) &&
            !(nsf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP)) {
            tcp_session->half_closed_dir = SASC_FLOW_FORWARD;
        } else if ((nsf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP) &&
                   !(nsf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT)) {
            tcp_session->half_closed_dir = SASC_FLOW_REVERSE;
        } else {
            tcp_session->half_closed_dir = 0xff;
        }
    }
}

static_always_inline void
update_state_one_pkt(sasc_tcp_check_main_t *stcm, u32 thread_index, u16 tenant_idx,
                     sasc_tcp_check_session_state_t *tcp_session, sasc_session_t *session,
                     f64 current_time, u8 dir, tcp_header_t *tcp, u32 *sf, u32 *nsf, u32 data_len,
                     ip_ecn_t ecn) {
    u8 flags = tcp->flags & SASC_TCP_CHECK_TCP_FLAGS_MASK;
    u32 acknum = clib_net_to_host_u32(tcp->ack_number);
    u32 seqnum = clib_net_to_host_u32(tcp->seq_number);
    u8 remove_session = 0;

    /* Handle session version mismatch */
    if (PREDICT_FALSE(tcp_session->version != session->session_version)) {
        init_tcp_session(tcp_session, session, flags);
    }

    /* Initialize state flags */
    *sf = tcp_session->flags;
    *nsf = *sf;

    /* Unified TCP options parsing */
    /* Keep this small and fixed-size to avoid stack bloat */
    sack_block_t parsed_sacks[8];
    sasc_tcp_parsed_opts_t parsed_opts;
    sasc_parse_tcp_options(tcp, (flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) != 0, parsed_sacks,
                           (u8)(sizeof(parsed_sacks) / sizeof(parsed_sacks[0])), &parsed_opts);

    /* Update RTT stats */
    process_tcp_rtt(tcp_session, current_time, dir, tcp, data_len, &parsed_opts);

    /* Check for anomalies */
    check_tcp_anomalies(stcm, thread_index, tenant_idx, tcp_session, session, current_time, dir,
                        tcp, data_len, ecn, &parsed_opts, parsed_sacks,
                        parsed_opts.num_sack_blocks);

    /* Process TCP flags and update state */
    int result = process_tcp_flags(tcp_session, session, dir, flags, seqnum, acknum, *sf, nsf,
                                   &remove_session, tcp);

    /* Handle final state transitions and session cleanup */
    finalize_session_state(session, tcp_session, *nsf, remove_session, result, current_time);
}

VLIB_NODE_FN(sasc_tcp_check_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    sasc_main_t *sasc = &sasc_main;
    sasc_tcp_check_main_t *stcm = &sasc_tcp_check_main;
    sasc_session_t *session;
    // sasc_tenant_t *tenant;
    u32 session_idx;
    sasc_tcp_check_session_state_t *tcp_session;
    u32 *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;
    u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
    u32 state_flags[VLIB_FRAME_SIZE], *sf = state_flags;
    u32 new_state_flags[VLIB_FRAME_SIZE], *nsf = new_state_flags;
    u8 close_cause[VLIB_FRAME_SIZE], *clsc = close_cause;
    f64 current_time = vlib_time_now(vm);
    u32 thread_index = vlib_get_thread_index();

    vlib_get_buffers(vm, from, bufs, n_left);
    while (n_left > 0) {
        session_idx = sasc_session_from_flow_index(b[0]->flow_id);
        session = sasc_session_at_index(sasc, session_idx);
        tcp_session = vec_elt_at_index(stcm->state, session_idx);
        u32 dir = sasc_direction_from_flow_index(b[0]->flow_id);
        u16 tenant_idx = sasc_buffer(b[0])->tenant_index;
        // tenant = sasc_tenant_at_index(sasc, tenant_idx);
        tcp_header_t *tcp = 0;
        // Check if l4_hdr_offset flag is valid is set
        tcp = (tcp_header_t *)(b[0]->data + vnet_buffer(b[0])->l4_hdr_offset);
        u8 tcp_hdr_len = tcp_header_bytes(tcp);
        u32 l3_len;
        u32 l4_rel_off = vnet_buffer(b[0])->l4_hdr_offset - vnet_buffer(b[0])->l3_hdr_offset;
        u32 ecn;
        u8 ttl;
        u32 dscp;

        sasc_parse_ip_header(b[0], &l3_len, &ecn, &ttl, &dscp);
        u32 data_len = l3_len - l4_rel_off - tcp_hdr_len;
        update_state_one_pkt(stcm, thread_index, tenant_idx, tcp_session, session, current_time,
                             dir, tcp, sf, nsf, data_len, ecn);
        clsc[0] = tcp_session->close_cause;
        sasc_next(b[0], to_next);
        n_left -= 1;
        b += 1;
        to_next += 1;
        sf += 1;
        nsf += 1;
        clsc += 1;
    }
    vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        int i;
        b = bufs;
        sf = state_flags;
        nsf = new_state_flags;
        clsc = close_cause;
        n_left = frame->n_vectors;
        for (i = 0; i < n_left; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                sasc_tcp_check_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                t->flow_id = b[0]->flow_id;
                t->old_state_flags = sf[0];
                t->new_state_flags = nsf[0];
                t->close_cause = clsc[0];
                b++;
                sf++;
                nsf++;
                clsc++;
            } else
                break;
        }
    }
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(sasc_tcp_check_node) = {
    .name = "sasc-tcp-check",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_tcp_check_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_TCP_CHECK_N_ERROR,
    .error_counters = sasc_tcp_check_error_counters,
};

SASC_SERVICE_DEFINE(tcp_check) = {
    .node_name = "sasc-tcp-check",
    .protocol_mask = SASC_PROTO_MASK_TCP,
    .format_service = format_sasc_tcp_check_service,
    .format_service_cbor = format_sasc_tcp_check_service_cbor,
    .export_schema = export_tcp_check_schema,
};
