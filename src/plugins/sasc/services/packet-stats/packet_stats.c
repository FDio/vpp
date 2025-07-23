// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <sasc/services/packet-stats/packet_stats.h>

sasc_packet_stats_main_t sasc_packet_stats_main;

static clib_error_t *
sasc_packet_stats_init(vlib_main_t *vm) {
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    vec_validate(psm->session_data, sasc_main.no_sessions);

    return 0;
};

// TODO: Only initialise these data structures when service is enabled
// Consider moving to a sub-block?
VLIB_INIT_FUNCTION(sasc_packet_stats_init) = {.runs_after = VLIB_INITS("sasc_init")};