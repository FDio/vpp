// SPDX-License-Identifier: Apache-2.0
#include "flow_quality_tcp.h"
#include <vppinfra/mem.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h> /* tcp_header_t, seq_lt, seq_geq */
#include <vnet/session_quality/session_quality.h>
#include <ctype.h>
#include <math.h>
#include "packet_stats.h"

/* Compatibility define for segment analysis */
#ifdef SESSION_QUALITY_TCP_SEGMENT_ANALYSIS_ENABLED
#define SASC_TCP_SEGMENT_ANALYSIS_ENABLED
#endif

/* ---- Public: per-packet updater (called only for TCP packets) ---- */

void
fq_tcp_on_packet(vlib_main_t *vm, vlib_buffer_t *b, u8 dir, tcp_header_t *th, u32 session_index, f64 now) {
    session_quality_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    session_quality_tcp_data_t *st = &core->tcp_data;

    u32 tcp_hlen = tcp_header_bytes(th);
    st->packets++;
    const u32 ack_dir = 1 - dir;
    const u32 seq = clib_net_to_host_u32(th->seq_number);
    const u32 ack = clib_net_to_host_u32(th->ack_number);
    const u16 win = clib_net_to_host_u16(th->window);
    const u8 flags = th->flags;

    /* Parse IP header for ECN, TTL, and DSCP using common function */
    u32 l3_len = 0;
    u32 ecn = 0;
    u8 ttl = 0;
    u32 dscp = 0;
    session_quality_parse_ip_header(b, &l3_len, &ecn, &ttl, &dscp);
    const u32 l4_off = vnet_buffer(b)->l4_hdr_offset;
    const u32 payload_len = (l3_len > (l4_off + tcp_hlen)) ? (l3_len - l4_off - tcp_hlen) : 0;
    /* Update CE density EMA for every packet */
    session_quality_ema_update(&st->ema_ce_rate, SESSION_QUALITY_EMA_ALPHA_CE, (ecn == 3) ? 1.0 : 0.0);

    /* Fast-path: Handle non-data packets (pure ACKs, control packets) */
    if (payload_len == 0) {
        /* Essential flag accounting for non-data packets */
        session_quality_tcp_process_flags(st, flags, dir, ack_dir, th, tcp_hlen);
        session_quality_tcp_process_ecn(st, flags, ecn);
        session_quality_tcp_process_zero_window(st, win, dir);
        session_quality_tcp_process_ack(st, flags, ack, ack_dir);
        return; /* Fast-path exit for non-data packets */
    }

    /* Data path: Handle packets with payload */
    st->data_packets++;

    /* Essential flag accounting for data packets */
    session_quality_tcp_process_flags(st, flags, dir, ack_dir, th, tcp_hlen);
    session_quality_tcp_process_ecn(st, flags, ecn);
    session_quality_tcp_process_zero_window(st, win, dir);
    session_quality_tcp_process_ack(st, flags, ack, ack_dir);

    /* Improved atypical segment size detection
       - Only penalize sustained small segments over a sliding window (last 16 packets)
       - Ignore first few small packets after idle (Nagle/delayed-ACK dance)
       - payload_len > mss cannot happen in-path, so drop that branch
       - Uses decayed window analysis for sustained fraction calculation */
#ifdef SASC_TCP_SEGMENT_ANALYSIS_ENABLED
    if (st->mss && payload_len > 0) {
        /* Track segment size in sliding window (16 segments instead of 64) */
        st->seg_size_history[st->seg_size_index] = (u16)payload_len;
        st->seg_size_index = (st->seg_size_index + 1) % 16;
        if (st->seg_size_count < 16)
            st->seg_size_count++;

        /* Update segment size flags for additional granularity */
        u32 size_flag = 0;
        if (payload_len < st->mss / 4) {
            size_flag = 1; // Small segment
        } else if (payload_len < st->mss / 2) {
            size_flag = 2; // Medium segment
        } else {
            size_flag = 3; // Large segment
        }

        /* Shift flags and add new flag */
        st->seg_size_flags = (st->seg_size_flags << 2) | size_flag;

        /* Check if this is a small segment that might indicate poor segmentation */
        if (payload_len < st->mss / 4) {
            /* Count small segments, but allow for Nagle/delayed-ACK behavior */
            if (st->idle_packet_count < 3) {
                /* First few small packets after idle - likely Nagle/delayed-ACK dance */
                st->idle_packet_count++;
                /* Avoid bumping EMA during initial idle dance */
                session_quality_ema_update(&st->ema_small_seg, SESSION_QUALITY_EMA_ALPHA_DEFAULT, 0.0);
            } else {
                /* Sustained small segments - count as atypical */
                st->atypical_seg_sizes++;
                session_quality_ema_update(&st->ema_small_seg, SESSION_QUALITY_EMA_ALPHA_DEFAULT, 1.0);
            }
        } else {
            /* Normal or large segment - reset idle packet counter */
            st->idle_packet_count = 0;
            session_quality_ema_update(&st->ema_small_seg, SESSION_QUALITY_EMA_ALPHA_DEFAULT, 0.0);
        }
    }
#endif

    /* Improved retransmit / reorder detection using overlap analysis and ACK tracking
       - end_seq_max[dir]: tracks highest seq+len seen to detect overlaps
       - ack_stall_count[ack_dir]: tracks consecutive non-advancing ACKs for reorder inference
       - Distinguishes between retransmissions, partial overlaps, and true reordering */
    const u32 end_seq = seq + payload_len;

    /* EMA event samples for this data packet */
    f64 ema_sample_retrans = 0.0;
    f64 ema_sample_overlap = 0.0;
    f64 ema_sample_reorder = 0.0;

    if (st->last_seq_valid[dir]) {
        if (seq_leq(end_seq, st->end_seq_max[dir])) {
            /* Segment is completely within previously seen data range = retransmission/overlap */
            st->retransmissions++;
            ema_sample_retrans = 1.0;
            ema_sample_overlap = 1.0;
        } else if (seq_lt(seq, st->end_seq_max[dir]) && seq_gt(end_seq, st->end_seq_max[dir])) {
            /* Segment partially overlaps with previous data = partial overlap */
            st->partial_overlaps++;
            ema_sample_overlap = 1.0;
        } else if (seq_lt(seq, st->end_seq_max[dir])) {
            /* Segment is completely before current range = potential reordering */
            /* Only count as reorder if ACK is not advancing (stalling ACK pattern) */
            if (st->ack_stall_count[ack_dir] >= 3) {
                st->reorder_events++;
                ema_sample_reorder = 1.0;
            }
        }
    }

    /* Update EMAs for per-packet event rates */
    session_quality_ema_update(&st->ema_retrans, SESSION_QUALITY_EMA_ALPHA_DEFAULT, ema_sample_retrans);
    session_quality_ema_update(&st->ema_overlap, SESSION_QUALITY_EMA_ALPHA_DEFAULT, ema_sample_overlap);
    session_quality_ema_update(&st->ema_reorder, SESSION_QUALITY_EMA_ALPHA_DEFAULT, ema_sample_reorder);

    /* Update sequence tracking */
    if (!st->last_seq_valid[dir] || seq_gt(end_seq, st->end_seq_max[dir])) {
        st->end_seq_max[dir] = end_seq;
    }
    st->last_seq[dir] = end_seq;
    st->last_seq_valid[dir] = 1;

    /* Save send time for RTT via ACK on reverse dir */
    st->last_data_seq[dir] = seq + payload_len - 1;
    st->rtt_probe_tick_us[dir] = session_quality_now_ticks_us();

    /* Detect idle periods for Nagle/delayed-ACK handling */
    if (st->last_data_tick_us[dir] != 0) {
        u32 now_us = session_quality_now_ticks_us();
        f64 time_since_last = session_quality_delta_s_from_ticks(now_us, st->last_data_tick_us[dir]);
        if (time_since_last > 0.1) {   /* 100ms idle threshold */
            st->idle_packet_count = 0; /* Reset counter after idle period */
        }
    }
    st->last_data_tick_us[dir] = session_quality_now_ticks_us();

#ifdef SASC_TCP_TTFB_ENABLED
    /* TTFB tracking: measure time from first data to first response data
       Note: This is a simplified approach that works for most TCP flows.
       For accurate HTTP TTFB, L7 parsing would be needed to identify request/response boundaries. */
    if (!st->ttfb_valid && payload_len > 0) {
        /* First data packet in this direction - could be client request or server response */
        if (st->data_packets == 1) {
            /* First data packet seen - this might be client request */
            /* We'll measure TTFB when we see data in the opposite direction */
        } else if (st->data_packets > 1 && !st->ttfb_valid) {
            /* We've seen data in both directions - calculate TTFB */
            /* This is a simplified approach; for HTTP flows, we'd need L7 parsing */
            if (st->rtt_probe_tick_us[ack_dir] != 0) {
                u32 now_us = session_quality_now_ticks_us();
                st->ttfb = session_quality_delta_s_from_ticks(now_us, st->rtt_probe_tick_us[ack_dir]);
                st->ttfb_valid = 1;
            }
        }
    }
#endif
}

/* ---- Scorer callback: blend TCP transport signals into core components ---- */

static void
fq_tcp_scorer(u8 protocol, u32 session_index) {
    /* Only act for TCP sessions */
    if (protocol != IP_PROTOCOL_TCP)
        return;

    session_quality_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    session_quality_tcp_data_t *st = &core->tcp_data;

    /* Compute derived TCP metrics */
    f64 rtt_sd = session_quality_tcp_rtt_stddev(st, 0);    // RTT for outgoing direction
    f64 rtt_sd_in = session_quality_tcp_rtt_stddev(st, 1); // RTT for incoming direction
    f64 loss_penalty = 0.0;
    f64 reorder_penalty = 0.0;
    f64 stall_penalty = 0.0;
    f64 handshake_penalty = 0.0;
    f64 closure_penalty = 0.0;
    f64 ecn_penalty = 0.0;

    /* Normalize by scale of observation (avoid early-flow domination) */
    f64 norm = (f64)clib_max(1u, st->data_packets);

    /* Loss / retrans: blend cumulative rate and EMA of recent retrans */
    f64 loss_penalty_count = clib_min(40.0, (st->retransmissions / norm) * 200.0); /* 0.2 per-pkt -> 40 */
    f64 loss_penalty_ema = clib_min(40.0, st->ema_retrans * 200.0);
    loss_penalty = clib_max(loss_penalty_count, loss_penalty_ema);

    /* Reordering and overlaps: prefer EMA-based instantaneous rates */
    reorder_penalty = clib_min(20.0, st->ema_reorder * 100.0);
    reorder_penalty += clib_min(10.0, st->ema_overlap * 50.0); /* partial overlaps */

    /* Stalls (zero-window) - per direction
       - Combines stall time from both directions for total penalty
       - Each direction tracks stalls independently based on window advertisements */
    stall_penalty = clib_min(25.0, (st->stall_time_accum[0] + st->stall_time_accum[1]) * 10.0); /* 2.5s stall -> 25 */

    /* Handshake / closure quality */
    if (!st->handshake_ok && st->syn_packets > 0)
        handshake_penalty += 10.0;
    if (st->syn_retx > 0)
        handshake_penalty += clib_min(15.0, st->syn_retx * 5.0);
    if (st->syn_rtt > 0 && st->syn_rtt > 1.0)
        handshake_penalty += clib_min(10.0, (st->syn_rtt - 1.0) * 5.0); /* Penalize slow handshakes */
    if (st->rst_packets > 0 && st->fin_packets == 0)
        closure_penalty += 10.0;

    /* ECN penalty based on CE mark rate: use EMA if available, else fallback to bitset popcount */
    if (st->ema_ce_rate > 0.0) {
        if (st->ema_ce_rate > 0.1) {
            ecn_penalty = clib_min(20.0, st->ema_ce_rate * 100.0);
        }
    } else if (st->ce_mark_popcnt > 0) { /* Fallback to bitset popcount */
        f64 ce_rate = (f64)st->ce_mark_popcnt / 64.0;
        if (ce_rate > 0.1) {
            ecn_penalty = clib_min(20.0, ce_rate * 100.0);
        }
    }

    /* Blend penalties into core buckets.
       Keep semantics consistent with non-TCP flows. */

    /* RTT variability penalty based on relative jitter (not absolute SD) - per direction
       - Uses rtt_sd / max(rtt_mean, eps) for fair comparison across different RTT ranges
       - Same relative jitter gets same penalty regardless of absolute RTT
       - Satellite links (500ms RTT, 50ms jitter = 10%) get same penalty as metro (10ms RTT, 1ms jitter = 10%)
       - Forward and reverse paths are analyzed separately for asymmetric path detection */
    f64 rtt_relative_variability_fwd = 0.0;
    f64 rtt_relative_variability_rev = 0.0;

    if (st->rtt_mean[0] > 0.001) { /* Forward direction RTT variability */
        rtt_relative_variability_fwd = rtt_sd / st->rtt_mean[0];
    }
    if (st->rtt_mean[1] > 0.001) { /* Reverse direction RTT variability */
        rtt_relative_variability_rev = rtt_sd_in / st->rtt_mean[1];
    }

    /* Asymmetric path penalty: detect when forward/reverse paths have significantly different characteristics */
    f64 asymmetric_penalty = 0.0;
    if (st->rtt_mean[0] > 0.001 && st->rtt_mean[1] > 0.001) {
        f64 rtt_ratio = clib_max(st->rtt_mean[0], st->rtt_mean[1]) / clib_min(st->rtt_mean[0], st->rtt_mean[1]);
        if (rtt_ratio > 2.0) {                                            /* 2:1 or worse asymmetry */
            asymmetric_penalty = clib_min(10.0, (rtt_ratio - 2.0) * 5.0); /* 2:1 -> 0, 3:1 -> 5, 4:1 -> 10 */
        }
    }
    /* Asymmetric penalty helps detect:
     * - Satellite links with different uplink/downlink characteristics
     * - Networks with asymmetric routing or congestion
     * - Paths where one direction has significantly different quality */

    /* Congestion: loss + TCP ECN + forward RTT jitter + asymmetric penalty */
    f64 cong_delta = loss_penalty + ecn_penalty +
                     clib_min(10.0, rtt_relative_variability_fwd * 100.0) + /* 0.1 -> 10, 0.2 -> 10 (capped) */
                     asymmetric_penalty;
    core->q_congestion = clib_max(0.0, core->q_congestion - cong_delta);

    /* Stability: forward RTT jitter influence (steeper than congestion term) + reverse RTT jitter */
    f64 stab_delta = clib_min(15.0, rtt_relative_variability_fwd * 150.0) + /* 0.1 -> 15, 0.2 -> 15 (capped) */
                     clib_min(10.0, rtt_relative_variability_rev * 100.0);  /* Reverse direction stability impact */
    core->q_stability = clib_max(0.0, core->q_stability - stab_delta);

    /* Continuity: reorders and zero-window stalls degrade continuity */
    f64 cont_delta = reorder_penalty + stall_penalty;
    core->q_continuity = clib_max(0.0, core->q_continuity - cont_delta);

    /* Delivery: failed handshake or RST abort = delivery issues perceived by app */
    f64 deliv_delta = handshake_penalty + closure_penalty;
    core->q_delivery = clib_max(0.0, core->q_delivery - deliv_delta);

    /* Packetization: penalize sustained poor segmentation using EMA */
#ifdef SASC_TCP_SEGMENT_ANALYSIS_ENABLED
    if (st->mss) {
        f64 small_frac = st->ema_small_seg;
        if (small_frac > 0.3) {
            f64 pz_delta = clib_min(15.0, (small_frac - 0.3) * 50.0);
            core->q_packetization = clib_max(0.0, core->q_packetization - pz_delta);
        }
    }
#else
    /* Segment analysis disabled - no packetization penalty */
#endif

    /* NOTE: We intentionally DO NOT recompute core->quality_score here.
       The caller (flow-quality core) should aggregate after all scorers run. */
}

/* ---- RTT Analysis Helpers ---- */

f64
fq_tcp_get_rtt_mean(u32 session_index, u8 direction) {
    if (direction > 1)
        return 0.0;
    session_quality_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    session_quality_tcp_data_t *st = &core->tcp_data;
    return st->rtt_mean[direction];
}

f64
fq_tcp_get_rtt_stddev(u32 session_index, u8 direction) {
    if (direction > 1)
        return 0.0;
    session_quality_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    session_quality_tcp_data_t *st = &core->tcp_data;
    return session_quality_tcp_rtt_stddev(st, direction);
}

f64
fq_tcp_get_rtt_asymmetry(u32 session_index) {
    session_quality_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    session_quality_tcp_data_t *st = &core->tcp_data;

    if (st->rtt_mean[0] <= 0.001 || st->rtt_mean[1] <= 0.001)
        return 1.0; /* No asymmetry if we don't have both measurements */

    return clib_max(st->rtt_mean[0], st->rtt_mean[1]) / clib_min(st->rtt_mean[0], st->rtt_mean[1]);
}

/* ---- Registration ---- */

void
fq_tcp_register_scorer(void) {
    sasc_quality_register_scorer("tcp-transport", (sasc_quality_scorer_fn)fq_tcp_scorer);
}

/* ---- Optional: memory usage ---- */

u64
fq_tcp_memory_usage(void) {
    /* TCP session data is stored in sasc_packet_stats_main.session_data, not in module state */
    return vec_len(sasc_packet_stats_main.session_data) * sizeof(session_quality_tcp_data_t);
}

static clib_error_t *
flow_quality_init(vlib_main_t *vm) {
    fq_tcp_register_scorer();
    return 0;
}
VLIB_INIT_FUNCTION(flow_quality_init);