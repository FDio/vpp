// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <sasc/services/tcp-check/tcp_check.h>

sasc_tcp_check_main_t sasc_tcp_check_main;

static clib_error_t *
sasc_tcp_check_init(vlib_main_t *vm) {
    sasc_tcp_check_main_t *stcm = &sasc_tcp_check_main;
    vec_validate(stcm->state, sasc_main.no_sessions);

    return 0;
};

// TODO: Only initialise these data structures when service is enabled
// Consider moving to a sub-block?
VLIB_INIT_FUNCTION(sasc_tcp_check_init) = {.runs_after = VLIB_INITS("sasc_init")};
