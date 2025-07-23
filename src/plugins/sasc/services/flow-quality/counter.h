// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.
// All rights reserved.

#ifndef SASC_PACKET_STATS_COUNTER_H
#define SASC_PACKET_STATS_COUNTER_H

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vlib/stats/stats.h>

/* Define the X macro for counter types */
#define SASC_PACKET_STATS_COUNTER_TYPES                                                                                \
    X(SASC_PACKET_STATS_COUNTER_PACKETS, packets, "sasc/packet_stats")                                                 \
    X(SASC_PACKET_STATS_COUNTER_BYTES, bytes, "sasc/packet_stats")                                                     \
    X(SASC_PACKET_STATS_COUNTER_TCP_PACKETS, tcp_packets, "sasc/packet_stats")                                         \
    X(SASC_PACKET_STATS_COUNTER_UDP_PACKETS, udp_packets, "sasc/packet_stats")                                         \
    X(SASC_PACKET_STATS_COUNTER_ICMP_PACKETS, icmp_packets, "sasc/packet_stats")                                       \
    X(SASC_PACKET_STATS_COUNTER_OTHER_PACKETS, other_packets, "sasc/packet_stats")

/* Generate the enum using the X macro */
typedef enum {
/* Simple counters. */
#define X(n, sn, p) n,
    SASC_PACKET_STATS_COUNTER_TYPES
#undef X
        SASC_PACKET_STATS_N_COUNTER,
} sasc_packet_stats_counter_type_t;

/* Generate the foreach macro using the same X macro */
#define foreach_sasc_packet_stats_counter_name SASC_PACKET_STATS_COUNTER_TYPES

#endif /* SASC_PACKET_STATS_COUNTER_H */