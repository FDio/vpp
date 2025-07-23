// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include "pcap.h"

sasc_pcap_main_t sasc_pcap_main;

static clib_error_t *
sasc_pcap_init(vlib_main_t *vm) {
    sasc_pcap_main_t *pm = &sasc_pcap_main;
    vec_validate(pm->session_data, sasc_main.no_sessions);
    return 0;
}
VLIB_INIT_FUNCTION(sasc_pcap_init);
