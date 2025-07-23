// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.
// All rights reserved.

#ifndef SASC_TCP_CHECK_COUNTER_H
#define SASC_TCP_CHECK_COUNTER_H

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vlib/stats/stats.h>

/* Define the X macro for counter types */
#define SASC_TCP_CHECK_COUNTER_TYPES                                                               \
    X(SASC_TCP_CHECK_COUNTER_RETRANSMIT, retransmit, sasc / tcp_check)                             \
    X(SASC_TCP_CHECK_COUNTER_REORDER, reorder, sasc / tcp_check)                                   \
    X(SASC_TCP_CHECK_COUNTER_FAST_RETRANSMIT, fast_retransmit, sasc / tcp_check)                   \
    X(SASC_TCP_CHECK_COUNTER_INVALID_TCP_HEADER, invalid_tcp_header, sasc / tcp_check)             \
    X(SASC_TCP_CHECK_COUNTER_MALFORMED_TCP_FLAGS, malformed_tcp_flags, sasc / tcp_check)           \
    X(SASC_TCP_CHECK_COUNTER_RETRANSMIT_BURST, retransmit_burst, sasc / tcp_check)

/* Generate the enum using the X macro */
typedef enum {
/* Simple counters. */
#define X(n, sn, p) n,
    SASC_TCP_CHECK_COUNTER_TYPES
#undef X
        SASC_TCP_CHECK_N_COUNTER,
} sasc_tcp_check_counter_type_t;

/* Generate the foreach macro using the same X macro */
#define foreach_sasc_tcp_check_counter_name SASC_TCP_CHECK_COUNTER_TYPES

#endif /* SASC_TCP_CHECK_COUNTER_H */