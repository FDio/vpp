// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.
// All rights reserved.

#include <vlib/vlib.h>
#include "tcp_check.h"
#include "counter.h"

static void
sasc_tcp_check_counter_tenant_add_del(u32 tenant_idx, bool is_add) {
    sasc_tcp_check_main_t *tcp_check = &sasc_tcp_check_main;
    for (int i = 0; i < SASC_TCP_CHECK_N_COUNTER; i++) {
        vlib_validate_simple_counter(&tcp_check->counters[i], tenant_idx);
        vlib_zero_simple_counter(&tcp_check->counters[i], tenant_idx);
    }
}

clib_error_t *
sasc_tcp_check_counter_init(vlib_main_t *vm) {
    sasc_tcp_check_main_t *tcp_check = &sasc_tcp_check_main;

    // Simple counters
    vec_validate(tcp_check->counters, SASC_TCP_CHECK_N_COUNTER - 1);
#define X(n, sn, p)                                                                                \
    tcp_check->counters[n].name = #sn;                                                             \
    tcp_check->counters[n].stat_segment_name = "/" p "/" #sn;
    foreach_sasc_tcp_check_counter_name
#undef X

        sasc_tenant_add_del_cb_register(sasc_tcp_check_counter_tenant_add_del);

    // RTT histogram
    tcp_check->rtt_histogram.name = "sasc_tcp_check_rtt_histogram";
    tcp_check->rtt_histogram.stat_segment_name = "/sasc/tcp_check/rtt_histogram_ms";
    // 15 bucket boundaries + 1 overflow bucket = 16 total buckets (indices 0-15)
    vlib_validate_log2_histogram(&tcp_check->rtt_histogram, 15);

    return 0;
}

VLIB_INIT_FUNCTION(sasc_tcp_check_counter_init);