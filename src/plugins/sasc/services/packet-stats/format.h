// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.
// All rights reserved.

#ifndef __SASC_PACKET_STATS_FORMAT_H__
#define __SASC_PACKET_STATS_FORMAT_H__

#include "packet_stats.h"

u8 *format_rate_stats(u8 *s, sasc_packet_stats_session_data_t *data);
u8 *format_timing_stats(u8 *s, sasc_packet_stats_session_data_t *data);
u8 *format_vector_size_histogram(u8 *s, u64 *buckets);
u8 *format_gap_histogram(u8 *s, u64 *buckets);
u8 *format_packet_size_histogram(u8 *s, u64 *buckets);

#endif /* __SASC_PACKET_STATS_FORMAT_H__ */