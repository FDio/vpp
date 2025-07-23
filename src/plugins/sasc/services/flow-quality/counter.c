// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.
// All rights reserved.

#include <vlib/vlib.h>
#include "packet_stats.h"
#include "counter.h"

static void
sasc_packet_stats_counter_tenant_add_del(u32 tenant_idx, bool is_add) {
    sasc_packet_stats_main_t *packet_stats = &sasc_packet_stats_main;
    for (int i = 0; i < SASC_PACKET_STATS_N_COUNTER; i++) {
        vlib_validate_simple_counter(&packet_stats->counters[i], tenant_idx);
        vlib_zero_simple_counter(&packet_stats->counters[i], tenant_idx);
    }
}

clib_error_t *
sasc_packet_stats_counter_init(vlib_main_t *vm) {
    sasc_packet_stats_main_t *packet_stats = &sasc_packet_stats_main;

    // Simple counters
    vec_validate(packet_stats->counters, SASC_PACKET_STATS_N_COUNTER - 1);
#define X(n, sn, p)                                                                                                    \
    packet_stats->counters[n].name = #sn;                                                                              \
    packet_stats->counters[n].stat_segment_name = "/" p "/" #sn;
    foreach_sasc_packet_stats_counter_name
#undef X

        sasc_tenant_add_del_cb_register(sasc_packet_stats_counter_tenant_add_del);

    // // Packet size histogram - 8 bins
    // packet_stats->packet_size_histogram.name = "sasc_packet_stats_packet_size_histogram";
    // packet_stats->packet_size_histogram.stat_segment_name =
    //     "/sasc/packet_stats/packet_size_histogram_bytes";
    // packet_stats->packet_size_histogram.min_exp = 6;
    // vlib_validate_log2_histogram(&packet_stats->packet_size_histogram, 7);

    // // Vector size histogram - 8 bins
    // packet_stats->vector_size_histogram.name = "sasc_packet_stats_vector_size_histogram";
    // packet_stats->vector_size_histogram.stat_segment_name =
    //     "/sasc/packet_stats/vector_size_histogram_pkts";
    // vlib_validate_log2_histogram(&packet_stats->vector_size_histogram, 7);

    // // Inter-packet gap histogram - 16 bins
    // packet_stats->session_coalescing_histogram.name = "sasc_packet_stats_gap_histogram";
    // packet_stats->session_coalescing_histogram.stat_segment_name =
    //     "/sasc/packet_stats/gap_histogram_us";
    // vlib_validate_log2_histogram(&packet_stats->session_coalescing_histogram, 15);

    return 0;
}

VLIB_INIT_FUNCTION(sasc_packet_stats_counter_init);