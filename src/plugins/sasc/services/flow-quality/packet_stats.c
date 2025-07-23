// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include "packet_stats.h"
#include <sasc/export.h>

sasc_packet_stats_main_t sasc_packet_stats_main;

static clib_error_t *
sasc_packet_stats_init(vlib_main_t *vm) {
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    vec_validate(psm->session_data, sasc_main.no_sessions);
    return 0;
};

/* TCP session data field descriptors - DEFINED here */
const sasc_field_desc_t flow_quality_tcp_desc[] = {
    {"packets", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, packets), NULL, NULL, 0, SASC_T_U32, 0},
    {"data_packets", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, data_packets), NULL, NULL, 0, SASC_T_U32, 0},
    {"syn_packets", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, syn_packets), NULL, NULL, 0, SASC_T_U32, 0},
    {"syn_retx", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, syn_retx), NULL, NULL, 0, SASC_T_U32, 0},
    {"fin_packets", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, fin_packets), NULL, NULL, 0, SASC_T_U32, 0},
    {"rst_packets", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, rst_packets), NULL, NULL, 0, SASC_T_U32, 0},

    /* ECN tracking - per-packet CE mark history for decayed window analysis */
    {"ce_mark_bitset", SASC_T_U64, offsetof(sasc_tcp_quality_session_data_t, ce_mark_bitset), NULL, NULL, 0, SASC_T_U64,
     0},
    {"ce_mark_index", SASC_T_U8, offsetof(sasc_tcp_quality_session_data_t, ce_mark_index), NULL, NULL, 0, SASC_T_U8, 0},
    {"ce_mark_popcnt", SASC_T_U8, offsetof(sasc_tcp_quality_session_data_t, ce_mark_popcnt), NULL, NULL, 0, SASC_T_U8,
     0},
    {"ece_seen", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, ece_seen), NULL, NULL, 0, SASC_T_U32, 0},
    {"cwr_seen", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, cwr_seen), NULL, NULL, 0, SASC_T_U32, 0},
    {"ece_with_ce", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, ece_with_ce), NULL, NULL, 0, SASC_T_U32, 0},
    {"ece_without_ce", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, ece_without_ce), NULL, NULL, 0, SASC_T_U32,
     0},

    /* Loss / reorder */
    {"retransmissions", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, retransmissions), NULL, NULL, 0,
     SASC_T_U32, 0},
    {"reorder_events", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, reorder_events), NULL, NULL, 0, SASC_T_U32,
     0},
    {"dupack_like", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, dupack_like), NULL, NULL, 0, SASC_T_U32, 0},
    {"partial_overlaps", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, partial_overlaps), NULL, NULL, 0,
     SASC_T_U32, 0},

    /* Window / stalls */
    {"zero_window_events", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, zero_window_events), NULL, NULL, 0,
     SASC_T_U32, 0},
    {"stall_time_accum", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, stall_time_accum), NULL, NULL, 0,
     SASC_T_F64, 2},
    {"in_zero_window", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, in_zero_window), NULL, NULL, 0,
     SASC_T_BOOL, 2},

    /* RTT (passive, coarse) */
    {"rtt_mean", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, rtt_mean), NULL, NULL, 0, SASC_T_F64, 2},
    {"rtt_m2", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, rtt_m2), NULL, NULL, 0, SASC_T_F64, 2},
    {"rtt_count", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, rtt_count), NULL, NULL, 0, SASC_T_U32, 2},

    /* Handshake / closure */
    {"handshake_ok", SASC_T_BOOL, offsetof(sasc_tcp_quality_session_data_t, handshake_ok), NULL, NULL, 0, SASC_T_BOOL,
     0},
    {"syn_rtt", SASC_T_F64, offsetof(sasc_tcp_quality_session_data_t, syn_rtt), NULL, NULL, 0, SASC_T_F64, 0},
    {"syn_timestamp_us", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, syn_timestamp_us), NULL, NULL, 0,
     SASC_T_U32, 2},
    {"orderly_close", SASC_T_BOOL, offsetof(sasc_tcp_quality_session_data_t, orderly_close), NULL, NULL, 0, SASC_T_BOOL,
     0},

    /* MSS / segmentation */
    {"mss", SASC_T_U16, offsetof(sasc_tcp_quality_session_data_t, mss), NULL, NULL, 0, SASC_T_U16, 0},
    {"atypical_seg_sizes", SASC_T_U32, offsetof(sasc_tcp_quality_session_data_t, atypical_seg_sizes), NULL, NULL, 0,
     SASC_T_U32, 0},

    /* Track sequence numbers for improved retrans/reorder detection */
    {"last_seq_valid", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, last_seq_valid), NULL, NULL, 0,
     SASC_T_U32, 2},
    {"last_seq", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, last_seq), NULL, NULL, 0, SASC_T_U32, 2},
    {"end_seq_max", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, end_seq_max), NULL, NULL, 0, SASC_T_U32, 2},
    {"last_ack", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, last_ack), NULL, NULL, 0, SASC_T_U32, 2},
    {"ack_stall_count", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, ack_stall_count), NULL, NULL, 0,
     SASC_T_U32, 2},

    /* Track ack timing for RTT: last data seq sent (per dir) and time */
    {"last_data_seq", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, last_data_seq), NULL, NULL, 0,
     SASC_T_U32, 2},
    {"rtt_probe_tick_us", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, rtt_probe_tick_us), NULL, NULL, 0,
     SASC_T_U32, 2},
    {"stall_start_tick_us", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, stall_start_tick_us), NULL, NULL, 0,
     SASC_T_U32, 2},
    {"last_data_tick_us", SASC_T_ARRAY, offsetof(sasc_tcp_quality_session_data_t, last_data_tick_us), NULL, NULL, 0,
     SASC_T_U32, 2},

    /* Decayed (EMA) rates for "current" quality assessment */
    {"ema_retrans", SASC_T_F64, offsetof(sasc_tcp_quality_session_data_t, ema_retrans), NULL, NULL, 0, SASC_T_F64, 0},
    {"ema_reorder", SASC_T_F64, offsetof(sasc_tcp_quality_session_data_t, ema_reorder), NULL, NULL, 0, SASC_T_F64, 0},
    {"ema_overlap", SASC_T_F64, offsetof(sasc_tcp_quality_session_data_t, ema_overlap), NULL, NULL, 0, SASC_T_F64, 0},
    {"ema_small_seg", SASC_T_F64, offsetof(sasc_tcp_quality_session_data_t, ema_small_seg), NULL, NULL, 0, SASC_T_F64,
     0},
    {"ema_ce_rate", SASC_T_F64, offsetof(sasc_tcp_quality_session_data_t, ema_ce_rate), NULL, NULL, 0, SASC_T_F64, 0},
};

static bool is_tcp(const void *data, u32 session_index) {
    sasc_session_t *session = sasc_session_at_index(&sasc_main, session_index);
    return session->protocol == IP_PROTOCOL_TCP;
}

static const sasc_field_desc_t packet_stats_desc[] = {
    {"version", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, version), NULL, NULL, 0, SASC_T_U32, 0},
    {"last_packet_time", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, last_packet_time), NULL, NULL, 0,
     SASC_T_F64, 0},
    {"iat_mean", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, iat_mean), NULL, NULL, 0, SASC_T_F64, 0},
    {"iat_stddev", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, iat_stddev), NULL, NULL, 0, SASC_T_F64, 0},
    {"iat_cv", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, iat_cv), NULL, NULL, 0, SASC_T_F64, 0},
    {"burst_count", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, burst_count), NULL, NULL, 0, SASC_T_U32, 0},
    {"idle_periods", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, idle_periods), NULL, NULL, 0, SASC_T_U32,
     0},
    {"tiny_packets", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, tiny_packets), NULL, NULL, 0, SASC_T_U32,
     0},
    {"frames_touched", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, frames_touched), NULL, NULL, 0,
     SASC_T_U32, 0},
    {"ecn_ect", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, ecn_ect), NULL, NULL, 0, SASC_T_U32, 0},
    {"ecn_ce", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, ecn_ce), NULL, NULL, 0, SASC_T_U32, 0},
    {"ttl_min", SASC_T_ARRAY, offsetof(sasc_packet_stats_session_data_t, ttl_min), NULL, NULL, 0, SASC_T_U8, 2},
    {"ttl_max", SASC_T_ARRAY, offsetof(sasc_packet_stats_session_data_t, ttl_max), NULL, NULL, 0, SASC_T_U8, 2},
    {"ttl_mean", SASC_T_ARRAY, offsetof(sasc_packet_stats_session_data_t, ttl_mean), NULL, NULL, 0, SASC_T_F64, 2},
    {"ttl_stddev", SASC_T_ARRAY, offsetof(sasc_packet_stats_session_data_t, ttl_stddev), NULL, NULL, 0, SASC_T_F64, 2},
    {"last_dscp", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, last_dscp), NULL, NULL, 0, SASC_T_U32, 0},
    {"dscp_changes", SASC_T_U32, offsetof(sasc_packet_stats_session_data_t, dscp_changes), NULL, NULL, 0, SASC_T_U32,
     0},
    {"quality_score", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, quality_score), NULL, NULL, 0, SASC_T_F64,
     0},
    {"q_stability", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, q_stability), NULL, NULL, 0, SASC_T_F64, 0},
    {"q_congestion", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, q_congestion), NULL, NULL, 0, SASC_T_F64,
     0},
    {"q_continuity", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, q_continuity), NULL, NULL, 0, SASC_T_F64,
     0},
    {"q_delivery", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, q_delivery), NULL, NULL, 0, SASC_T_F64, 0},
    {"q_packetization", SASC_T_F64, offsetof(sasc_packet_stats_session_data_t, q_packetization), NULL, NULL, 0,
     SASC_T_F64, 0},
    {"tcp_session_data", SASC_T_NESTED, offsetof(sasc_packet_stats_session_data_t, tcp_session_data), NULL,
     flow_quality_tcp_desc, sizeof(flow_quality_tcp_desc) / sizeof(flow_quality_tcp_desc[0]), SASC_T_U32, 0, is_tcp},
};
static const size_t packet_stats_field_count = sizeof(packet_stats_desc) / sizeof(packet_stats_desc[0]);

cbor_item_t *
format_sasc_packet_stats_service_cbor(u32 thread_index, u32 session_index) {
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];
    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session = sasc_session_at_index(sasc, session_index);

    /* Ensure quality scores are computed */
    sasc_quality_compute(session, session_data);

    // Use the new schema-based format which now includes histogram support
    return sasc_encode_array_generic(packet_stats_desc, packet_stats_field_count,
                                     (const sasc_service_state_t *)session_data, session_index);
}

u8 *
format_sasc_packet_stats_service(u8 *s, u32 thread_index, u32 session_index, bool detail) {
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];
    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session = sasc_session_at_index(sasc, session_index);

    /* Ensure quality scores are computed */
    sasc_quality_compute(session, session_data);

    if (!detail) {
        return format(s,
                      "%Usasc-packet-stats: Quality:%.2f | IAT:%.1fms±%.1fms | TTL: Fwd:%u-%u Rev:%u-%u | "
                      "ECN:%u/%u | ICMP:%u | Tiny:%u\n",
                      format_white_space, 2, session_data->quality_score, session_data->iat_mean * 1000,
                      session_data->iat_stddev * 1000,
                      session_data->ttl_min[0], session_data->ttl_max[0],  /* Forward direction */
                      session_data->ttl_min[1], session_data->ttl_max[1],  /* Reverse direction */
                      session_data->ecn_ect, session_data->ecn_ce,
                      session->icmp_unreach + session->icmp_frag_needed + session->icmp_ttl_expired +
                          session->icmp_packet_too_big,
                      session_data->tiny_packets);
    }

    /* Use generic text formatter */
    return sasc_format_text_generic(s, packet_stats_desc, packet_stats_field_count,
                                    (const sasc_service_state_t *)session_data, session_index, "sasc-packet-stats");
}
cbor_item_t *
export_packet_stats_schema(void) {
    return sasc_export_schema_generic("packet_stats", packet_stats_desc, packet_stats_field_count, 1);
}

/* ---- TTL Analysis Helpers ---- */

u8
sasc_packet_stats_get_ttl_min(u32 session_index, u8 direction) {
    if (direction > 1)
        return 0;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];
    return session_data->ttl_min[direction];
}

u8
sasc_packet_stats_get_ttl_max(u32 session_index, u8 direction) {
    if (direction > 1)
        return 0;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];
    return session_data->ttl_max[direction];
}

f64
sasc_packet_stats_get_ttl_mean(u32 session_index, u8 direction) {
    if (direction > 1)
        return 0.0;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];
    return session_data->ttl_mean[direction];
}

f64
sasc_packet_stats_get_ttl_stddev(u32 session_index, u8 direction) {
    if (direction > 1)
        return 0.0;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];
    return session_data->ttl_stddev[direction];
}

f64
sasc_packet_stats_get_ttl_asymmetry(u32 session_index) {
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];

    if (session_data->ttl_count[0] == 0 || session_data->ttl_count[1] == 0)
        return 1.0; /* No asymmetry if we don't have both directions */

    f64 fwd_mean = session_data->ttl_mean[0];
    f64 rev_mean = session_data->ttl_mean[1];

    if (fwd_mean <= 0.001 || rev_mean <= 0.001)
        return 1.0; /* No asymmetry if means are too small */

    return clib_max(fwd_mean, rev_mean) / clib_min(fwd_mean, rev_mean);
}

u64
sasc_packet_stats_memory_usage(void) {
    return sizeof(sasc_packet_stats_session_data_t);
}

// TODO: Only initialise these data structures when service is enabled
// Consider moving to a sub-block?
VLIB_INIT_FUNCTION(sasc_packet_stats_init) = {.runs_after = VLIB_INITS("sasc_init")};