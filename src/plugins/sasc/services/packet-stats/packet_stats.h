// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#ifndef __INCLUDED_PACKET_STATS_H__
#define __INCLUDED_PACKET_STATS_H__

#include <vlib/vlib.h>
#include <sasc/sasc.h>

typedef struct {
    session_version_t version;

    // Per-session histograms
    u64 size_buckets[8];
    u64 gap_buckets[16];
    u64 vector_size_buckets[8];

    /* Flow statistics */
    u64 total_packets;
    u64 total_bytes;
    u64 flow_duration_ns;
    f64 last_packet_time;

    /* Inter-packet timing */
    u64 min_inter_packet_time;
    u64 max_inter_packet_time;
    u64 avg_inter_packet_time;
    u64 inter_packet_samples;

    /* Protocol statistics */
    u64 tcp_packets;
    u64 udp_packets;
    u64 icmp_packets;
    u64 other_packets;

    /* Additional packet measurements */
    u64 packets_per_second;        /* Current packets per second rate */
    u64 bytes_per_second;          /* Current bytes per second rate */
    u32 peak_packets_per_second;   /* Peak packets per second observed */
    u32 peak_bytes_per_second;     /* Peak bytes per second observed */
    u64 burst_count;               /* Number of packet bursts detected */
    u64 idle_periods;              /* Number of idle periods detected */
    u64 last_rate_update_time;     /* Last time rates were updated */
    u64 packets_since_rate_update; /* Packets since last rate update */
    u64 bytes_since_rate_update;   /* Bytes since last rate update */
} sasc_packet_stats_session_data_t;

typedef struct {
    sasc_packet_stats_session_data_t *session_data;
    u32 log_class;

    /* Counters */
    vlib_simple_counter_main_t *counters;
    vlib_log2_histogram_main_t packet_size_histogram;
    vlib_log2_histogram_main_t vector_size_histogram; /* Global vector size histogram */
    vlib_log2_histogram_main_t
        session_coalescing_histogram; /* Global session coalescing histogram */
} sasc_packet_stats_main_t;

extern sasc_packet_stats_main_t sasc_packet_stats_main;

#endif // __INCLUDED_PACKET_STATS_H__