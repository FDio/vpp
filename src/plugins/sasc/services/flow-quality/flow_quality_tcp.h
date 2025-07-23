// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <vlib/vlib.h>
#include <vnet/tcp/tcp.h>
#include <sasc/sasc.h>
#include <sasc/service.h>
#include <sasc/sasc_funcs.h>
#include <sasc/export.h>
// Remove circular dependency - don't include packet_stats.h here

/* Feature flag for TTFB tracking - disable to save memory and processing overhead
 *
 * To enable TTFB tracking, define this before including this file:
 *   #define SASC_TCP_TTFB_ENABLED 1
 *   #include "flow_quality_tcp.h"
 *
 * Or compile with: -DSASC_TCP_TTFB_ENABLED=1
 *
 * Default: disabled (0) to save memory and processing overhead
 */
#ifndef SASC_TCP_TTFB_ENABLED
#define SASC_TCP_TTFB_ENABLED 0
#endif

/* Feature flag for segment size analysis - disable to save memory
 *
 * To enable segment size analysis, define this before including this file:
 *   #define SASC_TCP_SEGMENT_ANALYSIS_ENABLED 1
 *   #include "flow_quality_tcp.h"
 *
 * Or compile with: -DSASC_TCP_SEGMENT_ANALYSIS_ENABLED=1
 *
 * Default: enabled (1) - provides packetization quality metrics
 */
#ifndef SASC_TCP_SEGMENT_ANALYSIS_ENABLED
#define SASC_TCP_SEGMENT_ANALYSIS_ENABLED 1
#endif

/*
 * Per-session TCP overlay state for flow-quality.
 * Allocated in a parallel vector/array keyed by session_index.
 * Non-TCP sessions never touch this.
 *
 * Feature flags:
 * - SASC_TCP_TTFB_ENABLED: Enable TTFB (Time To First Byte) tracking
 *   - Adds 16 bytes per session (f64 + u8)
 *   - Adds processing overhead for TTFB calculation
 *   - Disable if TTFB metrics are not needed
 * - SASC_TCP_SEGMENT_ANALYSIS_ENABLED: Enable segment size analysis
 *   - Adds 34 bytes per session (was 268 bytes with 64-element array)
 *   - Provides packetization quality metrics
 *   - Disable to save memory when segment analysis not needed
 */
typedef struct {
    /* Basic counters */
    u32 packets;      /* TCP packets seen */
    u32 data_packets; /* PSH or data-length > 0 */
    u32 syn_packets;  /* SYNs seen */
    u32 syn_retx;     /* SYN retransmissions */
    u32 fin_packets;  /* FINs */
    u32 rst_packets;  /* RSTs */
    /* ECN tracking - per-packet CE mark history for decayed window analysis */
    u64 ce_mark_bitset; /* 64-bit sliding window of CE marks (1=CE, 0=no CE) */
    u8 ce_mark_index;   /* current index in circular buffer (0-63) */
    u8 ce_mark_popcnt;  /* rolling popcount for O(1) CE rate calculation */
    u32 ece_seen;       /* TCP ECE flag seen (for debugging, not penalty) */
    u32 cwr_seen;       /* TCP CWR flag seen (for debugging, not penalty) */
    u32 ece_with_ce;    /* ECE seen on packets with IP CE marks (for debugging, not penalty) */
    u32 ece_without_ce; /* ECE seen on packets without IP CE marks (for debugging, not penalty) */

    /* Loss / reorder */
    u32 retransmissions;  /* detected data retransmits */
    u32 reorder_events;   /* out-of-order arrivals */
    u32 dupack_like;      /* true dupACK patterns (ACK not advancing + data above ACK) */
    u32 partial_overlaps; /* segments that partially overlap with previous data */

    /* Window / stalls */
    u32 zero_window_events;  /* receiver window = 0 transitions */
    f64 stall_time_accum[2]; /* seconds of zero-window/persist observed per direction */
    u8 in_zero_window[2];    /* flag per direction */

    /* RTT (passive, coarse) - per direction for asymmetric path analysis */
    f64 rtt_mean[2];      /* RTT mean per direction (0=forward, 1=reverse) */
    f64 rtt_m2[2];        /* RTT variance accumulator per direction */
    u32 rtt_count[2];     /* RTT sample count per direction */

    /* Per-direction RTT enables:
     * - Asymmetric path detection (e.g., satellite uplink vs downlink)
     * - Direction-specific congestion analysis
     * - Separate forward/reverse stability assessment
     * - Better quality scoring for asymmetric networks */

    /* Handshake / closure */
    u8 handshake_ok;         /* SYN,SYN-ACK,ACK completed */
    f64 syn_rtt;             /* time from SYN to SYN-ACK */
    u32 syn_timestamp_us[2]; /* explicit timestamp (us ticks, wraps) when SYN seen per direction */
#ifdef SASC_TCP_TTFB_ENABLED
    f64 ttfb;      /* time from first data to first response data (HTTP TTFB) */
    u8 ttfb_valid; /* TTFB measurement is valid */
#endif
    u8 orderly_close; /* FIN/ACK handshake observed (no mid-flow RST) */

    /* MSS / segmentation */
    u16 mss;                /* from SYN options if available */
    u32 atypical_seg_sizes; /* segments deviating a lot from MSS */
#ifdef SASC_TCP_SEGMENT_ANALYSIS_ENABLED
    u16 seg_size_history[16]; /* sliding window of last 16 segment sizes (was 64) */
    u32 seg_size_flags;       /* 32 bits for additional granularity (small/medium/large) */
    u8 seg_size_index;        /* current index in circular buffer (0-15) */
    u8 seg_size_count;        /* number of segments in history */
    u8 idle_packet_count;     /* count of small packets after idle (Nagle/delayed-ACK) */
#endif

    /* Track sequence numbers for improved retrans/reorder detection */
    u32 last_seq_valid[2];
    u32 last_seq[2];        /* last sequence number seen */
    u32 end_seq_max[2];     /* highest seq+len seen (for overlap detection) */
    u32 last_ack[2];        /* last ACK number seen (for reorder inference) */
    u32 ack_stall_count[2]; /* consecutive packets with non-advancing ACK */

    /* Track ack timing for RTT: last data seq sent (per dir) and time */
    u32 last_data_seq[2];
    u32 rtt_probe_tick_us[2];   /* when data was sent (us ticks) for RTT measurement (0 = unset) */
    u32 stall_start_tick_us[2]; /* when zero-window stall started per direction (us ticks, 0 = unset) */
    u32 last_data_tick_us[2];   /* when last data packet was seen per direction (us ticks, 0 = unset) */

    /* Decayed (EMA) rates for "current" quality assessment */
    f64 ema_retrans;   /* EMA of per-packet retransmission indicator */
    f64 ema_reorder;   /* EMA of per-packet reorder indicator */
    f64 ema_overlap;   /* EMA of per-packet partial/complete overlap indicator */
    f64 ema_small_seg; /* EMA of per-packet small segment indicator */
    f64 ema_ce_rate;   /* EMA of per-packet CE mark indicator */
} sasc_tcp_quality_session_data_t;

/* Public API for the flow-quality node (called on each TCP packet) */
void fq_tcp_on_packet(vlib_main_t *vm, vlib_buffer_t *b, u8 dir, tcp_header_t *th, u32 session_index, f64 now);

/* Register the TCP scorer; call this once from flow-quality init */
void fq_tcp_register_scorer(void);

/* Access overlay state (optional helpers if you need them elsewhere) */
// sasc_tcp_quality_session_data_t* fq_tcp_state_at(u32 session_index);

/* Optional: memory usage reporting */
u64 fq_tcp_memory_usage(void);

/* RTT analysis helpers for external use */
f64 fq_tcp_get_rtt_mean(u32 session_index, u8 direction);
f64 fq_tcp_get_rtt_stddev(u32 session_index, u8 direction);
f64 fq_tcp_get_rtt_asymmetry(u32 session_index);
