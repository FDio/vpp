// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#ifndef __INCLUDED_PACKET_STATS_H__
#define __INCLUDED_PACKET_STATS_H__

#include <vlib/vlib.h>
#include <sasc/sasc.h>

/* Feature toggles */
#ifndef SASC_TINY_PKT_THRESH
#define SASC_TINY_PKT_THRESH 128
#endif

/* Session data structure */
typedef struct {
    session_version_t version;

    /* Timing metrics */
    f64 last_packet_time;

    /* Welford state for IAT */
    f64 iat_mean;
    f64 iat_m2;
    u32 iat_count;
    f64 iat_stddev;
    f64 iat_cv;

    /* Quality inputs */
    u32 burst_count;
    u32 idle_periods;
    u32 tiny_packets;
    u32 frames_touched;

    /* ECN metrics */
    u32 ecn_ect;
    u32 ecn_ce;

    /* TTL statistics */
    u8 ttl_min;
    u8 ttl_max;
    f64 ttl_mean;
    f64 ttl_m2;
    u32 ttl_count;
    f64 ttl_stddev;

    /* DSCP metrics */
    u32 last_dscp;
    u32 dscp_changes;

    /* ICMP metrics */
    u32 icmp_unreach;
    u32 icmp_frag_needed;
    u32 icmp_ttl_expired;
    u32 icmp_packet_too_big;

    /* Quality outputs */
    f64 quality_score;
    f64 q_stability;
    f64 q_congestion;
    f64 q_continuity;
    f64 q_delivery;
    f64 q_packetization;

} sasc_packet_stats_session_data_t;

/* Plugin scorer function type */
typedef void (*sasc_quality_scorer_fn)(const sasc_session_t *session,
                                       sasc_packet_stats_session_data_t *session_data);

/* Main structure */
typedef struct {
    sasc_packet_stats_session_data_t *session_data;
    u32 log_class;

    /* Counters */
    vlib_simple_counter_main_t *counters;

    /* Session coalescing histogram (always included) */
    u32 session_coalescing_histogram[64];

} sasc_packet_stats_main_t;

/* Plugin scorer API declarations */
extern sasc_packet_stats_main_t sasc_packet_stats_main;

/* Register a quality scorer plugin */
u32 sasc_quality_register_scorer(const char *name, sasc_quality_scorer_fn scorer);

/* Compute quality index for a session */
u8 sasc_quality_compute(const sasc_session_t *session,
                        sasc_packet_stats_session_data_t *session_data);

/* Note ICMP events for a session */
void sasc_quality_note_icmp_unreach(u32 session_index);
void sasc_quality_note_icmp_frag_needed(u32 session_index);

/* ICMP error callback function */
void sasc_packet_stats_icmp_error_callback(const sasc_icmp_error_info_t *error_info);

#endif // __INCLUDED_PACKET_STATS_H__