// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#pragma once

#include <vlib/vlib.h>
#include <sasc/sasc.h>
#include "flow_quality_tcp.h"

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

    /* TTL statistics - per direction for asymmetric routing analysis */
    u8 ttl_min[2];      /* TTL min per direction (0=forward, 1=reverse) */
    u8 ttl_max[2];      /* TTL max per direction */
    f64 ttl_mean[2];    /* TTL mean per direction */
    f64 ttl_m2[2];      /* TTL variance accumulator per direction */
    u32 ttl_count[2];   /* TTL sample count per direction */
    f64 ttl_stddev[2];  /* TTL stddev per direction */

    /* Per-direction TTL enables:
     * - Asymmetric routing detection (different hop counts per direction)
     * - Direction-specific network topology analysis
     * - Better quality scoring for asymmetric networks
     * - Consistent with per-direction RTT approach */

    /* DSCP metrics */
    u32 last_dscp;
    u32 dscp_changes;

    /* Quality outputs */
    f64 quality_score;
    f64 q_stability;
    f64 q_congestion;
    f64 q_continuity;
    f64 q_delivery;
    f64 q_packetization;

    /* TCP metrics */
    sasc_tcp_quality_session_data_t tcp_session_data;
} sasc_packet_stats_session_data_t;

/* Plugin scorer function type */
typedef void (*sasc_quality_scorer_fn)(const sasc_session_t *session, sasc_packet_stats_session_data_t *session_data);

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
u8 sasc_quality_compute(const sasc_session_t *session, sasc_packet_stats_session_data_t *session_data);

/* Note ICMP events for a session */
void sasc_quality_note_icmp_unreach(u32 session_index);
void sasc_quality_note_icmp_frag_needed(u32 session_index);

/* ICMP error callback function */
void sasc_packet_stats_icmp_error_callback(const sasc_icmp_error_info_t *error_info);

/* TTL analysis helpers for external use */
u8 sasc_packet_stats_get_ttl_min(u32 session_index, u8 direction);
u8 sasc_packet_stats_get_ttl_max(u32 session_index, u8 direction);
f64 sasc_packet_stats_get_ttl_mean(u32 session_index, u8 direction);
f64 sasc_packet_stats_get_ttl_stddev(u32 session_index, u8 direction);
f64 sasc_packet_stats_get_ttl_asymmetry(u32 session_index);
