// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.
// All rights reserved.

#include <vppinfra/format.h>
#include "packet_stats.h"

#if 0
u8 *
format_rate_stats(u8 *s, sasc_packet_stats_session_data_t *data) {
    s = format(s, "Rate Statistics:\n");
    s = format(s, "  Current: %lu packets/sec, %lu bytes/sec\n", data->packets_per_second,
               data->bytes_per_second);
    s = format(s, "  Peak: %u packets/sec, %u bytes/sec\n", data->peak_packets_per_second,
               data->peak_bytes_per_second);
    s = format(s, "  Bursts: %lu detected\n", data->burst_count);
    s = format(s, "  Idle Periods: %lu detected\n", data->idle_periods);
    return s;
}

u8 *
format_timing_stats(u8 *s, sasc_packet_stats_session_data_t *data) {
    s = format(s, "Inter-Packet Timing:\n");
    s = format(s, "  Min: %lu ns\n", data->min_inter_packet_time);
    s = format(s, "  Max: %lu ns\n", data->max_inter_packet_time);
    s = format(s, "  Avg: %lu ns\n", data->avg_inter_packet_time);
    s = format(s, "  Samples: %lu\n", data->inter_packet_samples);
    return s;
}

u8 *
format_vector_size_histogram(u8 *s, u64 *buckets) {
    // Bucket names (vectors of max 256 entries)
    const char *bucket_names[] = {"1", "2", "4", "8", "16", "32", "64", "128", "256"};

    s = format(s, "Vector Size Histogram (Log2 Bins):\n");
    for (int i = 0; i < 9; i++) {
        if (buckets[i] > 0) {
            s = format(s, "  %s: %lu vectors\n", bucket_names[i], buckets[i]);
        }
    }
    return s;
}

u8 *
format_gap_histogram(u8 *s, u64 *buckets) {
    const char *bucket_names[] = {"1μs",   "2μs",   "4μs", "8μs", "16μs", "32μs", "64μs", "128μs",
                                  "256μs", "512μs", "1ms", "2ms", "4ms",  "8ms",  "16ms", "32ms+"};

    s = format(s, "Inter-Packet Gap Histogram (Log2 Bins):\n");
    for (int i = 0; i < 16; i++) {
        if (buckets[i] > 0) {
            s = format(s, "  %s: %lu gaps\n", bucket_names[i], buckets[i]);
        }
    }
    return s;
}

u8 *
format_packet_size_histogram(u8 *s, u64 *buckets) {
    const char *bucket_names[] = {"1B",    "2B",    "4B",     "8B",     "16B",   "32B",
                                  "64B",   "128B",  "256B",   "512B",   "1024B", "2048B",
                                  "4096B", "8192B", "16384B", "32768B+"};

    s = format(s, "Packet Size Histogram (Log2 Bins):\n");
    for (int i = 0; i < 16; i++) {
        if (buckets[i] > 0) {
            s = format(s, "  %s: %lu packets\n", bucket_names[i], buckets[i]);
        }
    }
    return s;
}
#endif