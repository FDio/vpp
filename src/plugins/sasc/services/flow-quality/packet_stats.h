// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#pragma once

#include <vlib/vlib.h>
#include <vnet/session_quality/session_quality.h>
#include <sasc/sasc.h>
#include "flow_quality_tcp.h"

/* Plugin scorer function type */
typedef void (*sasc_quality_scorer_fn)(const sasc_session_t *session, session_quality_data_t *session_data);

/* Main structure */
typedef struct {
    session_quality_data_t *session_data;
    u32 log_class;
    u16 msg_id_base;

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
u8 sasc_quality_compute(const sasc_session_t *session, session_quality_data_t *session_data);

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
