// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <math.h>
#include <vlib/vlib.h>
#include <sasc/sasc.h>
#include <sasc/service.h>
#include <sasc/sasc_funcs.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vppinfra/hash.h>
#include <stddef.h> // for offsetof
#include "packet_stats.h"
#include "counter.h"
#include <cbor.h>
#include "format.h"
#include <sasc/export.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

/* Plugin scorer registry */
static sasc_quality_scorer_fn *sasc_q_scorers;

typedef struct {
    u32 flow_id;
    u32 packet_size;
    f64 timestamp;
} sasc_packet_stats_trace_t;

static u8 *
format_sasc_packet_stats_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_packet_stats_trace_t *t = va_arg(*args, sasc_packet_stats_trace_t *);

    s = format(s, "sasc-packet-stats: flow-id %u packet-size %u timestamp %.6f", t->flow_id, t->packet_size,
               t->timestamp);
    return s;
}

/* Welford's online algorithm for variance */
static inline void
welford_update(f64 *mean, f64 *m2, u32 *count, f64 new_value) {
    /* Protect against invalid input */
    // if (!isfinite(new_value)) {
    //     return;
    // }

    (*count)++;
    f64 delta = new_value - *mean;
    *mean += delta / *count;
    f64 delta2 = new_value - *mean;
    *m2 += delta * delta2;

    /* Ensure m2 doesn't become negative due to floating point errors */
    if (*m2 < 0.0) {
        *m2 = 0.0;
    }

    // /* Ensure mean and m2 remain finite */
    // if (!isfinite(*mean) || !isfinite(*m2)) {
    //     *mean = new_value;
    //     *m2 = 0.0;
    // }
}

static inline f64
welford_stddev(f64 m2, u32 count) {
    if (count < 2 || m2 <= 0.0 /* || !isfinite(m2) */)
        return 0.0;
    f64 variance = m2 / (count - 1);
    if (variance <= 0.0 /* || !isfinite(variance) */)
        return 0.0;
    return sqrt(variance);
}

/* Quality component computation functions */
static f64
compute_q_stability(f64 iat_cv) {
    /* Map iat_cv via knee 0.5 span 1.5 */
    if (iat_cv <= 0.5)
        return 100.0;
    if (iat_cv >= 2.0)
        return 0.0;
    return 100.0 * (2.0 - iat_cv) / 1.5;
}

static f64
compute_q_congestion(u32 ecn_ce, u32 ecn_ect, f64 ttl_stddev_fwd, f64 ttl_stddev_rev) {
    f64 ce_rate = (ecn_ect > 0) ? (f64)ecn_ce / ecn_ect : 0.0;

    /* TTL penalty based on both directions - use the worse direction */
    f64 ttl_penalty_fwd = (ttl_stddev_fwd > 5.0) ? (ttl_stddev_fwd - 5.0) * 10.0 : 0.0;
    f64 ttl_penalty_rev = (ttl_stddev_rev > 5.0) ? (ttl_stddev_rev - 5.0) * 10.0 : 0.0;
    f64 ttl_penalty = clib_max(ttl_penalty_fwd, ttl_penalty_rev);

    f64 score = 100.0 - (ce_rate * 50.0) - clib_min(ttl_penalty, 50.0);
    return clib_max(0.0, score);
}

static f64
compute_q_continuity(u32 burst_count, u32 idle_periods, u32 frames_touched) {
    if (frames_touched == 0)
        return 100.0;
    f64 bursty_fraction = (f64)burst_count / frames_touched;
    f64 idle_penalty = idle_periods * 10.0;
    f64 score = 100.0 - (bursty_fraction * 40.0) - clib_min(idle_penalty, 40.0);
    return clib_max(0.0, score);
}

static f64
compute_q_delivery(u32 icmp_unreach, u32 icmp_frag_needed, u32 icmp_ttl_expired, u32 icmp_packet_too_big) {
    // Weight different ICMP error types based on their impact on delivery
    f64 penalty = (icmp_unreach * 25.0) +       // Destination unreachable - high impact
                  (icmp_frag_needed * 20.0) +   // Fragmentation needed - medium impact
                  (icmp_ttl_expired * 15.0) +   // TTL expired - medium impact
                  (icmp_packet_too_big * 20.0); // Packet too big - medium impact
    return clib_max(0.0, 100.0 - penalty);
}

static f64
compute_q_packetization(const sasc_session_t *session, sasc_packet_stats_session_data_t *session_data) {
    u32 packets_total = session->pkts[SASC_FLOW_FORWARD] + session->pkts[SASC_FLOW_REVERSE];
    u64 bytes_total = session->bytes[SASC_FLOW_FORWARD] + session->bytes[SASC_FLOW_REVERSE];

    if (packets_total == 0)
        return 100.0;

    f64 avg_packet_size = (f64)bytes_total / packets_total;
    f64 tiny_fraction = (f64)session_data->tiny_packets / packets_total;
    f64 dscp_penalty = session_data->dscp_changes * 5.0;

    /* Penalize tiny packets and DSCP changes */
    f64 tiny_penalty = tiny_fraction * 30.0;
    f64 size_penalty = 0.0;

    /* Additional penalty for very small or very large average packet sizes */
    if (avg_packet_size < 64.0) {
        size_penalty = (64.0 - avg_packet_size) * 1.0;
    } else if (avg_packet_size > 1500.0) {
        size_penalty = (avg_packet_size - 1500.0) * 0.05;
    }

    f64 score = 100.0 - tiny_penalty - dscp_penalty - clib_min(size_penalty, 20.0);
    return clib_max(0.0, score);
}

VLIB_NODE_FN(sasc_packet_stats_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    u32 session_indices[VLIB_FRAME_SIZE], *sip = session_indices;
    sasc_main_t *sasc = &sasc_main;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;

    u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
    u32 *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;
    f64 current_time = vlib_time_now(vm);

    vlib_get_buffers(vm, from, bufs, n_left);

    /* Per-packet processing (hot path) */
    while (n_left) {
        u32 session_idx = sasc_session_from_flow_index(b[0]->flow_id);
        sasc_session_t *session = sasc_session_at_index(sasc, session_idx);
        sip[0] = session_idx;

        /* Get or create session data */
        sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_idx];

        /* Handle session version mismatch */
        if (PREDICT_FALSE(session_data->version != session->session_version)) {
            clib_memset(session_data, 0, sizeof(*session_data));
            session_data->version = session->session_version;
            session_data->last_packet_time = current_time; /* bootstrap */
        }

        /* Parse IP header for ECN, TTL, and DSCP */
        u32 l3_len;
        u32 ecn;
        u8 ttl;
        u32 dscp;
        sasc_parse_ip_header(b[0], &l3_len, &ecn, &ttl, &dscp);

        /* Track tiny packets for quality assessment */
        if (b[0]->current_length < SASC_TINY_PKT_THRESH) {
            session_data->tiny_packets++;
        }

        /* Update ECN counters */
        session_data->ecn_ect += (ecn == IP_ECN_ECT_0) ? 1 : 0;
        session_data->ecn_ce += (ecn == IP_ECN_CE) ? 1 : 0;

        /* Update TTL statistics using Welford's algorithm - per direction */
        u8 dir = sasc_direction_from_flow_index(b[0]->flow_id);
        if (session_data->ttl_count[dir] == 0) {
            session_data->ttl_min[dir] = ttl;
            session_data->ttl_max[dir] = ttl;
        } else {
            session_data->ttl_min[dir] = clib_min(session_data->ttl_min[dir], ttl);
            session_data->ttl_max[dir] = clib_max(session_data->ttl_max[dir], ttl);
        }
        welford_update(&session_data->ttl_mean[dir], &session_data->ttl_m2[dir], &session_data->ttl_count[dir], ttl);

        /* Update DSCP drift */
        if (session_data->frames_touched > 0 && session_data->last_dscp != dscp) {
            session_data->dscp_changes++;
        }
        session_data->last_dscp = dscp;

        /* Update frame statistics */
        session_data->frames_touched++;

        /* Compute IAT sample */
        f64 iat = current_time - session_data->last_packet_time;
        session_data->last_packet_time = current_time;

        /* Update Welford state for IAT */
        welford_update(&session_data->iat_mean, &session_data->iat_m2, &session_data->iat_count, iat);

        /* Classify burst and idle periods */
        if (iat < 0.001) { /* < 1ms */
            session_data->burst_count++;
        } else if (iat > 1.0) { /* > 1s */
            session_data->idle_periods++;
        }

        // TCP
        if (session->protocol == IP_PROTOCOL_TCP) {
            u8 dir = sasc_direction_from_flow_index(b[0]->flow_id);
            tcp_header_t *tcp = (tcp_header_t *)(b[0]->data + vnet_buffer(b[0])->l4_hdr_offset);
            fq_tcp_on_packet(vm, b[0], dir, tcp, session_idx, current_time);
        }
        sasc_next(b[0], to_next);

        b++;
        to_next++;
        n_left--;
        sip++;
    }

    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        n_left = frame->n_vectors;
        b = bufs;
        for (int i = 0; i < n_left; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                sasc_packet_stats_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                t->flow_id = b[0]->flow_id;
                t->packet_size = b[0]->current_length;
                t->timestamp = current_time;
                b++;
            } else
                break;
        }
    }
    vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(sasc_packet_stats_node) = {
    .name = "sasc-packet-stats",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_packet_stats_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
};

/* Plugin scorer registry functions */
u32
sasc_quality_register_scorer(const char *name, sasc_quality_scorer_fn scorer) {
    if (!sasc_q_scorers) {
        sasc_q_scorers = 0;
    }
    vec_add1(sasc_q_scorers, scorer);
    return vec_len(sasc_q_scorers) - 1;
}

u8
sasc_quality_compute(const sasc_session_t *session, sasc_packet_stats_session_data_t *session_data) {
    /* Compute derived statistics when needed */
    session_data->ttl_stddev[0] = welford_stddev(session_data->ttl_m2[0], session_data->ttl_count[0]);
    session_data->ttl_stddev[1] = welford_stddev(session_data->ttl_m2[1], session_data->ttl_count[1]);
    session_data->iat_stddev = welford_stddev(session_data->iat_m2, session_data->iat_count);
    session_data->iat_cv = (session_data->iat_mean > 0) ? session_data->iat_stddev / session_data->iat_mean : 0.0;

    /* Compute quality components directly from session data */
    session_data->q_stability = compute_q_stability(session_data->iat_cv);
    session_data->q_congestion =
        compute_q_congestion(session_data->ecn_ce, session_data->ecn_ect, session_data->ttl_stddev[0],
                             session_data->ttl_stddev[1]); // Changed to use session_data->ttl_stddev[0]
    session_data->q_continuity =
        compute_q_continuity(session_data->burst_count, session_data->idle_periods, session_data->frames_touched);
    session_data->q_delivery = compute_q_delivery(session->icmp_unreach, session->icmp_frag_needed,
                                                  session->icmp_ttl_expired, session->icmp_packet_too_big);
    session_data->q_packetization = compute_q_packetization(session, session_data);

    /* Apply registered scorer callbacks */
    if (sasc_q_scorers) {
        sasc_quality_scorer_fn *scorer;
        vec_foreach (scorer, sasc_q_scorers) {
            (*scorer)(session, session_data);
        }
    }

    /* Compute weighted quality score (0-100) */
    session_data->quality_score = (session_data->q_stability * 0.40) + (session_data->q_congestion * 0.25) +
                                  (session_data->q_continuity * 0.20) + (session_data->q_delivery * 0.10) +
                                  (session_data->q_packetization * 0.05);

    return 0;
}

u64 sasc_packet_stats_memory_usage(void);
u8 *format_sasc_packet_stats_service(u8 *s, u32 thread_index, u32 session_index, bool detail);
cbor_item_t *format_sasc_packet_stats_service_cbor(u32 thread_index, u32 session_index);
cbor_item_t *export_packet_stats_schema(void);

SASC_SERVICE_DEFINE(packet_stats) = {
    .node_name = "sasc-packet-stats",
    .format_service = format_sasc_packet_stats_service,
    .format_service_cbor = format_sasc_packet_stats_service_cbor,
    .export_schema = export_packet_stats_schema,
    .memory_usage = sasc_packet_stats_memory_usage,
};