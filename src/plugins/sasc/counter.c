// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.
// All rights reserved.

#include <vlib/vlib.h>
#include "sasc.h"
#include "counter.h"

void
sasc_counter_tenant_add_del(u32 tenant_idx, bool is_add) {
    sasc_main_t *sasc = &sasc_main;
    for (int i = 0; i < SASC_N_COUNTER; i++) {
        vlib_validate_simple_counter(&sasc->counters[i], tenant_idx);
        vlib_zero_simple_counter(&sasc->counters[i], tenant_idx);
    }
}

clib_error_t *
sasc_counter_init(vlib_main_t *vm) {
    sasc_main_t *sasc = &sasc_main;

    // Simple counters
    vec_validate(sasc->counters, SASC_N_COUNTER - 1);
#define X(n, sn, p)                                                                                                    \
    sasc->counters[n].name = #sn;                                                                                      \
    sasc->counters[n].stat_segment_name = "/" #p "/" #sn;
    foreach_sasc_counter_name
#undef X

        sasc->active_sessions = vlib_stats_add_gauge("/sasc/active_sessions");
    sasc_tenant_add_del_cb_register(sasc_counter_tenant_add_del);
    return 0;
}

VLIB_INIT_FUNCTION(sasc_counter_init);