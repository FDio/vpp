// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.
// All rights reserved.

#ifndef SASC_COUNTER_H
#define SASC_COUNTER_H

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vlib/stats/stats.h>

/* Define the X macro for counter types */
#define SASC_COUNTER_TYPES                                                                                             \
    X(SASC_COUNTER_CREATED, created, sasc)                                                                             \
    X(SASC_COUNTER_REMOVED, removed, sasc)

/* Generate the enum using the X macro */
typedef enum {
/* Simple counters. */
#define X(n, sn, p) n,
    SASC_COUNTER_TYPES
#undef X
        SASC_N_COUNTER,
} sasc_counter_type_t;

/* Generate the foreach macro using the same X macro */
#define foreach_sasc_counter_name SASC_COUNTER_TYPES

#endif /* SASC_COUNTER_H */