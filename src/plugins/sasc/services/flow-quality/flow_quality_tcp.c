// SPDX-License-Identifier: Apache-2.0
#include "flow_quality_tcp.h"
#include <vppinfra/mem.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h> /* tcp_header_t, seq_lt, seq_geq */
#include <ctype.h>
#include <math.h>
#include "packet_stats.h"

/* ---- Small utilities ---- */

/* Time utility functions for microsecond tick handling */
static inline u32
now_ticks_us(void) {
    vlib_main_t *vm = vlib_get_main();
    /* vlib_time_now returns seconds as f64; convert to microseconds in u32 (wraps) */
    f64 seconds = vlib_time_now(vm);
    u64 us64 = (u64)(seconds * 1e6);
    return (u32)us64; /* wrap intentionally */
}

static inline f64
delta_s_from_ticks(u32 newer, u32 older) {
    /* Compute delta in seconds from wrapping u32 microsecond ticks */
    u32 delta_us = newer - older; /* unsigned wrap-safe */
    return (f64)delta_us / 1e6;
}

/* Welford update for RTT - per direction */
static inline void
rtt_update(sasc_tcp_quality_session_data_t *st, f64 sample, u8 dir) {
    st->rtt_count[dir]++;
    f64 delta = sample - st->rtt_mean[dir];
    st->rtt_mean[dir] += delta / st->rtt_count[dir];
    st->rtt_m2[dir] += delta * (sample - st->rtt_mean[dir]);
}

static inline f64
rtt_stddev(const sasc_tcp_quality_session_data_t *st, u8 dir) {
    if (st->rtt_count[dir] < 2)
        return 0.0;
    f64 var = st->rtt_m2[dir] / (st->rtt_count[dir] - 1);
    return var > 0 ? sqrt(var) : 0.0;
}

/* EMA helpers for decayed rates ("current" quality) */
#define SASC_TCP_EMA_ALPHA_DEFAULT 0.10 /* ~19-sample effective window */
#define SASC_TCP_EMA_ALPHA_CE      0.08 /* slightly slower for CE density */
static inline void
ema_update(f64 *ema_value, f64 alpha, f64 sample_value) {
    *ema_value = alpha * sample_value + (1.0 - alpha) * (*ema_value);
}

/* ---- Helper functions to eliminate code duplication ---- */

/* Process TCP flags and update counters */
static inline void
process_tcp_flags(sasc_tcp_quality_session_data_t *st, u8 flags, u8 dir, u8 ack_dir, vlib_main_t *vm, tcp_header_t *th,
                  u32 tcp_hlen) {
    if (flags & TCP_FLAG_SYN) {
        if (st->syn_packets)
            st->syn_retx++;
        st->syn_packets++;
        if ((flags & TCP_FLAG_ACK) && !st->handshake_ok) {
            /* SYN-ACK: robust SYN RTT calculation using explicit SYN timestamps */
            if (st->syn_timestamp_us[ack_dir] != 0) {
                u32 now_us = now_ticks_us();
                st->syn_rtt = delta_s_from_ticks(now_us, st->syn_timestamp_us[ack_dir]);
            }
        }
        if (!(flags & TCP_FLAG_ACK)) {
            /* Pure SYN: explicitly timestamp for robust RTT calculation */
            st->syn_timestamp_us[dir] = now_ticks_us();
        }
        /* Parse MSS from SYN options if needed */
        if (st->mss == 0) {
            const u8 *opt = (const u8 *)th + sizeof(tcp_header_t);
            const u8 *end = (const u8 *)th + tcp_hlen;
            while (opt + 1 < end) {
                u8 kind = opt[0];
                if (kind == 0)
                    break; /* EOL */
                if (kind == 1) {
                    opt += 1;
                    continue;
                } /* NOP */
                if (opt + 2 > end)
                    break;
                u8 len = opt[1];
                if (len < 2 || opt + len > end)
                    break;
                if (kind == 2 && len == 4) { /* MSS */
                    st->mss = (opt[2] << 8) | opt[3];
                    break;
                }
                opt += len;
            }
        }
    }
    if ((flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_SYN) && !st->handshake_ok) {
        /* First pure ACK following SYN-ACK finalizes 3WHS */
        st->handshake_ok = 1;
    }
    if (flags & TCP_FLAG_FIN)
        st->fin_packets++;
    if (flags & TCP_FLAG_RST)
        st->rst_packets++;
}

/* Track ECN flags and update CE mark bitset */
static inline void
process_ecn_flags(sasc_tcp_quality_session_data_t *st, u8 flags, u32 ecn) {
    /* Track ECN flags for debugging (not used for penalties) */
    if (flags & TCP_FLAG_ECE) {
        st->ece_seen++;
        if (ecn == 3)
            st->ece_with_ce++;
        else
            st->ece_without_ce++;
    }
    if (flags & TCP_FLAG_CWR)
        st->cwr_seen++;

    /* Track CE marks in 64-bit sliding window with O(1) rolling popcount */
    u64 outgoing_bit = 1ULL << st->ce_mark_index;
    u64 incoming_bit = (ecn == 3) ? (1ULL << st->ce_mark_index) : 0;

    /* Update popcount: subtract outgoing bit, add incoming bit */
    if (st->ce_mark_bitset & outgoing_bit) {
        st->ce_mark_popcnt--; /* outgoing bit was 1, so decrement count */
    }
    if (incoming_bit) {
        st->ce_mark_popcnt++; /* incoming bit is 1, so increment count */
    }

    /* Update bitset: clear outgoing bit, set incoming bit */
    st->ce_mark_bitset = (st->ce_mark_bitset & ~outgoing_bit) | incoming_bit;
    st->ce_mark_index = (st->ce_mark_index + 1) % 64;
}

/* Handle zero-window tracking and stall timing */
static inline void
process_zero_window(sasc_tcp_quality_session_data_t *st, u16 win, u8 dir, vlib_main_t *vm) {
    if (win == 0 && !st->in_zero_window[dir]) {
        st->zero_window_events++;
        st->in_zero_window[dir] = 1;
        st->stall_start_tick_us[dir] = now_ticks_us();
    } else if (win > 0 && st->in_zero_window[dir]) {
        st->in_zero_window[dir] = 0;
        if (st->stall_start_tick_us[dir] != 0) {
            u32 now_us = now_ticks_us();
            st->stall_time_accum[dir] += delta_s_from_ticks(now_us, st->stall_start_tick_us[dir]);
            st->stall_start_tick_us[dir] = 0;
        }
    }
}

/* Process ACK flags for RTT calculation and reorder detection */
static inline void
process_ack_flags(sasc_tcp_quality_session_data_t *st, u8 flags, u32 ack, u8 ack_dir) {
    if (!(flags & TCP_FLAG_ACK))
        return;

    /* Track ACK advancement for reorder detection */
    if (ack != 0) {
        if (seq_gt(ack, st->last_ack[ack_dir])) {
            /* ACK advanced - reset stall counter */
            st->ack_stall_count[ack_dir] = 0;
            st->last_ack[ack_dir] = ack;
        } else if (seq_leq(ack, st->last_ack[ack_dir])) {
            /* ACK did not advance - increment stall counter */
            st->ack_stall_count[ack_dir]++;
        }
    }

    /* RTT calculation */
    if (st->rtt_probe_tick_us[ack_dir] != 0) {
        if (seq_geq(ack, st->last_data_seq[ack_dir])) {
            u32 now_us = now_ticks_us();
            f64 sample = delta_s_from_ticks(now_us, st->rtt_probe_tick_us[ack_dir]);
            if (sample >= 0 && sample < 60.0)
                rtt_update(st, sample, ack_dir);
            st->rtt_probe_tick_us[ack_dir] = 0;
        } else {
            /* Improved dupACK detection: only count if ACK didn't advance AND we've seen data above ACK */
            if (ack == st->last_ack[ack_dir] && st->end_seq_max[ack_dir] > ack) {
                st->dupack_like++;
            }
        }
    }
}

/* ---- Public: per-packet updater (called only for TCP packets) ---- */

void
fq_tcp_on_packet(vlib_main_t *vm, vlib_buffer_t *b, u8 dir, tcp_header_t *th, u32 session_index, f64 now) {
    sasc_packet_stats_session_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    sasc_tcp_quality_session_data_t *st = &core->tcp_session_data;

    u32 tcp_hlen = tcp_header_bytes(th);
    st->packets++;
    const u32 ack_dir = 1 - dir;
    const u32 seq = clib_net_to_host_u32(th->seq_number);
    const u32 ack = clib_net_to_host_u32(th->ack_number);
    const u16 win = clib_net_to_host_u16(th->window);
    const u8 flags = th->flags;

    /* Parse IP header for ECN, TTL, and DSCP */
    u32 l3_len = 0;
    u32 ecn = 0;
    u8 ttl = 0;
    u32 dscp = 0;
    sasc_parse_ip_header(b, &l3_len, &ecn, &ttl, &dscp);
    const u32 l4_off = vnet_buffer(b)->l4_hdr_offset;
    const u32 payload_len = (l3_len > (l4_off + tcp_hlen)) ? (l3_len - l4_off - tcp_hlen) : 0;
    /* Update CE density EMA for every packet */
    ema_update(&st->ema_ce_rate, SASC_TCP_EMA_ALPHA_CE, (ecn == 3) ? 1.0 : 0.0);

    /* Fast-path: Handle non-data packets (pure ACKs, control packets) */
    if (payload_len == 0) {
        /* Essential flag accounting for non-data packets */
        process_tcp_flags(st, flags, dir, ack_dir, vm, th, tcp_hlen);
        process_ecn_flags(st, flags, ecn);
        process_zero_window(st, win, dir, vm);
        process_ack_flags(st, flags, ack, ack_dir);
        return; /* Fast-path exit for non-data packets */
    }

    /* Data path: Handle packets with payload */
    st->data_packets++;

    /* Essential flag accounting for data packets */
    process_tcp_flags(st, flags, dir, ack_dir, vm, th, tcp_hlen);
    process_ecn_flags(st, flags, ecn);
    process_zero_window(st, win, dir, vm);
    process_ack_flags(st, flags, ack, ack_dir);

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
                ema_update(&st->ema_small_seg, SASC_TCP_EMA_ALPHA_DEFAULT, 0.0);
            } else {
                /* Sustained small segments - count as atypical */
                st->atypical_seg_sizes++;
                ema_update(&st->ema_small_seg, SASC_TCP_EMA_ALPHA_DEFAULT, 1.0);
            }
        } else {
            /* Normal or large segment - reset idle packet counter */
            st->idle_packet_count = 0;
            ema_update(&st->ema_small_seg, SASC_TCP_EMA_ALPHA_DEFAULT, 0.0);
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
    ema_update(&st->ema_retrans, SASC_TCP_EMA_ALPHA_DEFAULT, ema_sample_retrans);
    ema_update(&st->ema_overlap, SASC_TCP_EMA_ALPHA_DEFAULT, ema_sample_overlap);
    ema_update(&st->ema_reorder, SASC_TCP_EMA_ALPHA_DEFAULT, ema_sample_reorder);

    /* Update sequence tracking */
    if (!st->last_seq_valid[dir] || seq_gt(end_seq, st->end_seq_max[dir])) {
        st->end_seq_max[dir] = end_seq;
    }
    st->last_seq[dir] = end_seq;
    st->last_seq_valid[dir] = 1;

    /* Save send time for RTT via ACK on reverse dir */
    st->last_data_seq[dir] = seq + payload_len - 1;
    st->rtt_probe_tick_us[dir] = now_ticks_us();

    /* Detect idle periods for Nagle/delayed-ACK handling */
    if (st->last_data_tick_us[dir] != 0) {
        u32 now_us = now_ticks_us();
        f64 time_since_last = delta_s_from_ticks(now_us, st->last_data_tick_us[dir]);
        if (time_since_last > 0.1) {   /* 100ms idle threshold */
            st->idle_packet_count = 0; /* Reset counter after idle period */
        }
    }
    st->last_data_tick_us[dir] = now_ticks_us();

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
                u32 now_us = now_ticks_us();
                st->ttfb = delta_s_from_ticks(now_us, st->rtt_probe_tick_us[ack_dir]);
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

    sasc_packet_stats_session_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    sasc_tcp_quality_session_data_t *st = &core->tcp_session_data;

    /* Compute derived TCP metrics */
    f64 rtt_sd = rtt_stddev(st, 0);    // RTT for outgoing direction
    f64 rtt_sd_in = rtt_stddev(st, 1); // RTT for incoming direction
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
    sasc_packet_stats_session_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    sasc_tcp_quality_session_data_t *st = &core->tcp_session_data;
    return st->rtt_mean[direction];
}

f64
fq_tcp_get_rtt_stddev(u32 session_index, u8 direction) {
    if (direction > 1)
        return 0.0;
    sasc_packet_stats_session_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    sasc_tcp_quality_session_data_t *st = &core->tcp_session_data;
    return rtt_stddev(st, direction);
}

f64
fq_tcp_get_rtt_asymmetry(u32 session_index) {
    sasc_packet_stats_session_data_t *core = &sasc_packet_stats_main.session_data[session_index];
    sasc_tcp_quality_session_data_t *st = &core->tcp_session_data;

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
    return vec_len(sasc_packet_stats_main.session_data) * sizeof(sasc_tcp_quality_session_data_t);
}

static clib_error_t *
flow_quality_init(vlib_main_t *vm) {
    fq_tcp_register_scorer();
    return 0;
}
VLIB_INIT_FUNCTION(flow_quality_init);