// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

/**
 * @file session_quality.h
 * @brief Common session quality analysis infrastructure for VPP
 *
 * This header provides protocol-agnostic and TCP-specific structures and
 * functions for analyzing session/flow quality. It is designed to be used
 * by multiple plugins (e.g., SASC, SFDP) without code duplication.
 *
 * Features:
 * - Per-session quality metrics tracking
 * - TCP-specific analysis (retransmissions, RTT, congestion)
 * - Welford's algorithm for online statistics
 * - Quality scoring framework
 */

#ifndef __SESSION_QUALITY_H__
#define __SESSION_QUALITY_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <math.h>

/**
 * Feature toggles for optional functionality
 */

/* Tiny packet threshold for quality assessment */
#ifndef SESSION_QUALITY_TINY_PKT_THRESH
#define SESSION_QUALITY_TINY_PKT_THRESH 128
#endif

/* Enable TTFB tracking (adds memory/processing overhead) */
#ifndef SESSION_QUALITY_TCP_TTFB_ENABLED
#define SESSION_QUALITY_TCP_TTFB_ENABLED 0
#endif

/* Enable segment size analysis for packetization quality */
#ifndef SESSION_QUALITY_TCP_SEGMENT_ANALYSIS_ENABLED
#define SESSION_QUALITY_TCP_SEGMENT_ANALYSIS_ENABLED 1
#endif

/* EMA alpha values for decayed rate calculations */
#define SESSION_QUALITY_EMA_ALPHA_DEFAULT                                     \
  0.10					  /* ~19-sample effective window */
#define SESSION_QUALITY_EMA_ALPHA_CE 0.08 /* slightly slower for CE density   \
					   */

/**
 * @brief TCP session quality tracking data
 *
 * Per-session TCP overlay state for quality analysis.
 * Tracks loss, reordering, RTT, congestion, and connection lifecycle.
 */
typedef struct
{
  /* Basic counters */
  u32 packets;	    /* TCP packets seen */
  u32 data_packets; /* PSH or data-length > 0 */
  u32 syn_packets;  /* SYNs seen */
  u32 syn_retx;	    /* SYN retransmissions */
  u32 fin_packets;  /* FINs */
  u32 rst_packets;  /* RSTs */

  /* ECN tracking - per-packet CE mark history for decayed window analysis */
  u64 ce_mark_bitset; /* 64-bit sliding window of CE marks (1=CE, 0=no CE) */
  u8 ce_mark_index;   /* current index in circular buffer (0-63) */
  u8 ce_mark_popcnt;  /* rolling popcount for O(1) CE rate calculation */
  u32 ece_seen;	      /* TCP ECE flag seen */
  u32 cwr_seen;	      /* TCP CWR flag seen */
  u32 ece_with_ce;    /* ECE seen on packets with IP CE marks */
  u32 ece_without_ce; /* ECE seen on packets without IP CE marks */

  /* Loss / reorder */
  u32 retransmissions;	/* detected data retransmits */
  u32 reorder_events;	/* out-of-order arrivals */
  u32 dupack_like;	/* true dupACK patterns */
  u32 partial_overlaps; /* segments that partially overlap with previous data
			 */

  /* Window / stalls */
  u32 zero_window_events;  /* receiver window = 0 transitions */
  f64 stall_time_accum[2]; /* seconds of zero-window/persist observed per
			      direction */
  u8 in_zero_window[2];	   /* flag per direction */

  /* RTT (passive, coarse) - per direction for asymmetric path analysis */
  f64 rtt_mean[2];  /* RTT mean per direction (0=forward, 1=reverse) */
  f64 rtt_m2[2];    /* RTT variance accumulator per direction */
  u32 rtt_count[2]; /* RTT sample count per direction */

  /* Handshake / closure */
  u8 handshake_ok;	   /* SYN,SYN-ACK,ACK completed */
  f64 syn_rtt;		   /* time from SYN to SYN-ACK */
  u32 syn_timestamp_us[2]; /* explicit timestamp (us ticks) when SYN seen per
			      direction */
#if SESSION_QUALITY_TCP_TTFB_ENABLED
  f64 ttfb;	 /* time from first data to first response data */
  u8 ttfb_valid; /* TTFB measurement is valid */
#endif
  u8 orderly_close; /* FIN/ACK handshake observed (no mid-flow RST) */

  /* MSS / segmentation */
  u16 mss;		  /* from SYN options if available */
  u32 atypical_seg_sizes; /* segments deviating a lot from MSS */
#if SESSION_QUALITY_TCP_SEGMENT_ANALYSIS_ENABLED
  u16 seg_size_history[16]; /* sliding window of last 16 segment sizes */
  u32
    seg_size_flags;  /* 32 bits for additional granularity (small/medium/large)
		      */
  u8 seg_size_index; /* current index in circular buffer (0-15) */
  u8 seg_size_count; /* number of segments in history */
  u8
    idle_packet_count; /* count of small packets after idle (Nagle/delayed-ACK)
			*/
#endif

  /* Track sequence numbers for improved retrans/reorder detection */
  u32 last_seq_valid[2];
  u32 last_seq[2];	  /* last sequence number seen */
  u32 end_seq_max[2];	  /* highest seq+len seen (for overlap detection) */
  u32 last_ack[2];	  /* last ACK number seen (for reorder inference) */
  u32 ack_stall_count[2]; /* consecutive packets with non-advancing ACK */

  /* Track ack timing for RTT: last data seq sent (per dir) and time */
  u32 last_data_seq[2];
  u32 rtt_probe_tick_us[2]; /* when data was sent (us ticks) for RTT
			       measurement */
  u32
    stall_start_tick_us[2]; /* when zero-window stall started per direction */
  u32 last_data_tick_us[2]; /* when last data packet was seen per direction */

  /* Decayed (EMA) rates for "current" quality assessment */
  f64 ema_retrans;   /* EMA of per-packet retransmission indicator */
  f64 ema_reorder;   /* EMA of per-packet reorder indicator */
  f64 ema_overlap;   /* EMA of per-packet partial/complete overlap indicator */
  f64 ema_small_seg; /* EMA of per-packet small segment indicator */
  f64 ema_ce_rate;   /* EMA of per-packet CE mark indicator */
} session_quality_tcp_data_t;

/**
 * @brief Generic session quality tracking data
 *
 * Protocol-agnostic quality metrics for any session type.
 */
typedef struct
{
  /* Session version for cache invalidation */
  u32 version;

  /* Timing metrics */
  f64 last_packet_time;

  /* Welford state for Inter-Arrival Time */
  f64 iat_mean;
  f64 iat_m2;
  u32 iat_count;
  f64 iat_stddev;
  f64 iat_cv; /* Coefficient of variation */

  /* Quality inputs */
  u32 burst_count;
  u32 idle_periods;
  u32 tiny_packets;
  u32 frames_touched;

  /* ECN metrics */
  u32 ecn_ect;
  u32 ecn_ce;

  /* TTL statistics - per direction for asymmetric routing analysis */
  u8 ttl_min[2];     /* TTL min per direction (0=forward, 1=reverse) */
  u8 ttl_max[2];     /* TTL max per direction */
  f64 ttl_mean[2];   /* TTL mean per direction */
  f64 ttl_m2[2];     /* TTL variance accumulator per direction */
  u32 ttl_count[2];  /* TTL sample count per direction */
  f64 ttl_stddev[2]; /* TTL stddev per direction */

  /* DSCP metrics */
  u32 last_dscp;
  u32 dscp_changes;

  /* Quality outputs (0-100 scale) */
  f64 quality_score;
  f64 q_stability;     /* Timing stability */
  f64 q_congestion;    /* Network congestion indicators */
  f64 q_continuity;    /* Flow continuity */
  f64 q_delivery;      /* Delivery success */
  f64 q_packetization; /* Packet size efficiency */

  /* TCP-specific metrics (only valid for TCP sessions) */
  session_quality_tcp_data_t tcp_data;
} session_quality_data_t;

/**
 * @brief Welford's online algorithm for mean and variance
 *
 * Updates running statistics with a new sample value.
 *
 * @param mean Pointer to running mean
 * @param m2 Pointer to M2 accumulator (for variance)
 * @param count Pointer to sample count
 * @param new_value New sample to incorporate
 */
static inline void
session_quality_welford_update (f64 *mean, f64 *m2, u32 *count, f64 new_value)
{
  (*count)++;
  f64 delta = new_value - *mean;
  *mean += delta / *count;
  f64 delta2 = new_value - *mean;
  *m2 += delta * delta2;

  /* Ensure m2 doesn't become negative due to floating point errors */
  if (*m2 < 0.0)
    *m2 = 0.0;
}

/**
 * @brief Compute standard deviation from Welford state
 *
 * @param m2 M2 accumulator value
 * @param count Sample count
 * @return Standard deviation, or 0.0 if insufficient samples
 */
static inline f64
session_quality_welford_stddev (f64 m2, u32 count)
{
  if (count < 2 || m2 <= 0.0)
    return 0.0;
  f64 variance = m2 / (count - 1);
  if (variance <= 0.0)
    return 0.0;
  return sqrt (variance);
}

/**
 * @brief EMA (Exponential Moving Average) update
 *
 * @param ema_value Pointer to EMA state
 * @param alpha Smoothing factor (0-1)
 * @param sample_value New sample value
 */
static inline void
session_quality_ema_update (f64 *ema_value, f64 alpha, f64 sample_value)
{
  *ema_value = alpha * sample_value + (1.0 - alpha) * (*ema_value);
}

/**
 * @brief Get current time in microsecond ticks (wrapping u32)
 *
 * @return Current time in microseconds
 */
static inline u32
session_quality_now_ticks_us (void)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 seconds = vlib_time_now (vm);
  u64 us64 = (u64) (seconds * 1e6);
  return (u32) us64; /* wrap intentionally */
}

/**
 * @brief Compute delta in seconds from wrapping microsecond ticks
 *
 * @param newer Newer timestamp (us ticks)
 * @param older Older timestamp (us ticks)
 * @return Delta in seconds
 */
static inline f64
session_quality_delta_s_from_ticks (u32 newer, u32 older)
{
  u32 delta_us = newer - older; /* unsigned wrap-safe */
  return (f64) delta_us / 1e6;
}

/**
 * @brief Parse IP header for quality-relevant fields
 *
 * Extracts ECN, TTL, DSCP, and L3 length from IP header.
 *
 * @param b Buffer containing packet
 * @param[out] l3_len IP packet length
 * @param[out] ecn ECN field value
 * @param[out] ttl TTL/hop limit value
 * @param[out] dscp DSCP field value
 */
static inline void
session_quality_parse_ip_header (vlib_buffer_t *b, u32 *l3_len, u32 *ecn,
				 u8 *ttl, u32 *dscp)
{
  ip4_header_t *ip4 =
    (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
  if (ip4->ip_version_and_header_length >> 4 == 4)
    {
      /* IPv4 */
      *l3_len = clib_net_to_host_u16 (ip4->length);
      *ecn = ip4_header_get_ecn (ip4);
      *ttl = ip4->ttl;
      *dscp = ip4_header_get_dscp (ip4);
    }
  else
    {
      /* IPv6 */
      // TODO - Verify accuracy of IPv6 functions
      ip6_header_t *ip6 =
	(ip6_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      *l3_len =
	clib_net_to_host_u16 (ip6->payload_length) + sizeof (ip6_header_t);
      *ecn = ip6_ecn_network_order (ip6);
      *ttl = ip6->hop_limit;
      *dscp = ip6_dscp_network_order (ip6);
    }
}

/**
 * @brief Update RTT statistics using Welford's algorithm
 *
 * @param tcp TCP session data
 * @param sample RTT sample in seconds
 * @param dir Direction (0=forward, 1=reverse)
 */
static inline void
session_quality_tcp_rtt_update (session_quality_tcp_data_t *tcp, f64 sample,
				u8 dir)
{
  tcp->rtt_count[dir]++;
  f64 delta = sample - tcp->rtt_mean[dir];
  tcp->rtt_mean[dir] += delta / tcp->rtt_count[dir];
  tcp->rtt_m2[dir] += delta * (sample - tcp->rtt_mean[dir]);
}

/**
 * @brief Compute RTT standard deviation for a direction
 *
 * @param tcp TCP session data
 * @param dir Direction (0=forward, 1=reverse)
 * @return RTT standard deviation in seconds
 */
static inline f64
session_quality_tcp_rtt_stddev (const session_quality_tcp_data_t *tcp, u8 dir)
{
  if (tcp->rtt_count[dir] < 2)
    return 0.0;
  f64 var = tcp->rtt_m2[dir] / (tcp->rtt_count[dir] - 1);
  return var > 0 ? sqrt (var) : 0.0;
}

/* ---- Quality Component Computation Functions ---- */

/**
 * @brief Compute stability score from IAT coefficient of variation
 *
 * @param iat_cv Coefficient of variation (stddev/mean)
 * @return Score 0-100
 */
static inline f64
session_quality_compute_stability (f64 iat_cv)
{
  /* Map iat_cv via knee 0.5 span 1.5 */
  if (iat_cv <= 0.5)
    return 100.0;
  if (iat_cv >= 2.0)
    return 0.0;
  return 100.0 * (2.0 - iat_cv) / 1.5;
}

/**
 * @brief Compute congestion score from ECN and TTL metrics
 *
 * @param ecn_ce CE mark count
 * @param ecn_ect ECT-capable packet count
 * @param ttl_stddev_fwd Forward direction TTL stddev
 * @param ttl_stddev_rev Reverse direction TTL stddev
 * @return Score 0-100
 */
static inline f64
session_quality_compute_congestion (u32 ecn_ce, u32 ecn_ect,
				    f64 ttl_stddev_fwd, f64 ttl_stddev_rev)
{
  f64 ce_rate = (ecn_ect > 0) ? (f64) ecn_ce / ecn_ect : 0.0;

  /* TTL penalty based on both directions - use the worse direction */
  f64 ttl_penalty_fwd =
    (ttl_stddev_fwd > 5.0) ? (ttl_stddev_fwd - 5.0) * 10.0 : 0.0;
  f64 ttl_penalty_rev =
    (ttl_stddev_rev > 5.0) ? (ttl_stddev_rev - 5.0) * 10.0 : 0.0;
  f64 ttl_penalty = clib_max (ttl_penalty_fwd, ttl_penalty_rev);

  f64 score = 100.0 - (ce_rate * 50.0) - clib_min (ttl_penalty, 50.0);
  return clib_max (0.0, score);
}

/**
 * @brief Compute continuity score from burst/idle patterns
 *
 * @param burst_count Number of burst periods detected
 * @param idle_periods Number of idle periods detected
 * @param frames_touched Total frames processed
 * @return Score 0-100
 */
static inline f64
session_quality_compute_continuity (u32 burst_count, u32 idle_periods,
				    u32 frames_touched)
{
  if (frames_touched == 0)
    return 100.0;
  f64 bursty_fraction = (f64) burst_count / frames_touched;
  f64 idle_penalty = idle_periods * 10.0;
  f64 score = 100.0 - (bursty_fraction * 40.0) - clib_min (idle_penalty, 40.0);
  return clib_max (0.0, score);
}

/**
 * @brief Compute delivery score from ICMP error counts
 *
 * @param icmp_unreach Destination unreachable count
 * @param icmp_frag_needed Fragmentation needed count
 * @param icmp_ttl_expired TTL expired count
 * @param icmp_packet_too_big Packet too big count
 * @return Score 0-100
 */
static inline f64
session_quality_compute_delivery (u32 icmp_unreach, u32 icmp_frag_needed,
				  u32 icmp_ttl_expired,
				  u32 icmp_packet_too_big)
{
  f64 penalty = (icmp_unreach * 25.0) +	      /* Destination unreachable */
		(icmp_frag_needed * 20.0) +   /* Fragmentation needed */
		(icmp_ttl_expired * 15.0) +   /* TTL expired */
		(icmp_packet_too_big * 20.0); /* Packet too big */
  return clib_max (0.0, 100.0 - penalty);
}

/**
 * @brief Compute packetization score from packet sizes
 *
 * @param packets_total Total packet count
 * @param bytes_total Total byte count
 * @param tiny_packets Count of tiny packets
 * @param dscp_changes Count of DSCP changes
 * @return Score 0-100
 */
static inline f64
session_quality_compute_packetization (u32 packets_total, u64 bytes_total,
				       u32 tiny_packets, u32 dscp_changes)
{
  if (packets_total == 0)
    return 100.0;

  f64 avg_packet_size = (f64) bytes_total / packets_total;
  f64 tiny_fraction = (f64) tiny_packets / packets_total;
  f64 dscp_penalty = dscp_changes * 5.0;

  f64 tiny_penalty = tiny_fraction * 30.0;
  f64 size_penalty = 0.0;

  if (avg_packet_size < 64.0)
    size_penalty = (64.0 - avg_packet_size) * 1.0;
  else if (avg_packet_size > 1500.0)
    size_penalty = (avg_packet_size - 1500.0) * 0.05;

  f64 score =
    100.0 - tiny_penalty - dscp_penalty - clib_min (size_penalty, 20.0);
  return clib_max (0.0, score);
}

/* ---- TCP-Specific Processing Functions ---- */

/**
 * @brief Process TCP flags and update counters
 *
 * @param tcp TCP session data
 * @param flags TCP flags from header
 * @param dir Packet direction
 * @param ack_dir Acknowledgment direction (1-dir)
 * @param th TCP header pointer
 * @param tcp_hlen TCP header length
 */
void session_quality_tcp_process_flags (session_quality_tcp_data_t *tcp,
					u8 flags, u8 dir, u8 ack_dir,
					tcp_header_t *th, u32 tcp_hlen);

/**
 * @brief Process ECN flags and update CE mark bitset
 *
 * @param tcp TCP session data
 * @param flags TCP flags
 * @param ecn ECN field from IP header
 */
void session_quality_tcp_process_ecn (session_quality_tcp_data_t *tcp,
				      u8 flags, u32 ecn);

/**
 * @brief Handle zero-window tracking and stall timing
 *
 * @param tcp TCP session data
 * @param win Window size from TCP header
 * @param dir Packet direction
 */
void session_quality_tcp_process_zero_window (session_quality_tcp_data_t *tcp,
					      u16 win, u8 dir);

/**
 * @brief Process ACK for RTT calculation and reorder detection
 *
 * @param tcp TCP session data
 * @param flags TCP flags
 * @param ack ACK number
 * @param ack_dir Acknowledgment direction
 */
void session_quality_tcp_process_ack (session_quality_tcp_data_t *tcp,
				      u8 flags, u32 ack, u8 ack_dir);

/**
 * @brief Full TCP packet processing for quality analysis
 *
 * Main entry point for processing a TCP packet and updating quality metrics.
 *
 * @param b Buffer containing packet
 * @param dir Packet direction (0=forward, 1=reverse)
 * @param th TCP header pointer
 * @param data Session quality data structure
 * @param now Current time in seconds
 */
void session_quality_tcp_on_packet (vlib_buffer_t *b, u8 dir, tcp_header_t *th,
				    session_quality_data_t *data, f64 now);

/**
 * @brief Apply TCP-specific penalties to quality scores
 *
 * Blends TCP transport signals into the core quality components.
 *
 * @param data Session quality data (with TCP data populated)
 * @param is_tcp Whether this is a TCP session
 */
void session_quality_tcp_apply_penalties (session_quality_data_t *data,
					  u8 is_tcp);

/**
 * @brief Compute all quality scores for a session
 *
 * @param data Session quality data structure
 * @param is_tcp Whether this is a TCP session
 * @param icmp_unreach ICMP unreachable count
 * @param icmp_frag_needed ICMP frag needed count
 * @param icmp_ttl_expired ICMP TTL expired count
 * @param icmp_packet_too_big ICMP packet too big count
 * @param packets_fwd Forward direction packet count
 * @param packets_rev Reverse direction packet count
 * @param bytes_fwd Forward direction byte count
 * @param bytes_rev Reverse direction byte count
 */
void session_quality_compute_scores (session_quality_data_t *data, u8 is_tcp,
				     u32 icmp_unreach, u32 icmp_frag_needed,
				     u32 icmp_ttl_expired,
				     u32 icmp_packet_too_big, u32 packets_fwd,
				     u32 packets_rev, u64 bytes_fwd,
				     u64 bytes_rev);

/* ---- RTT Analysis Helpers ---- */

/**
 * @brief Get RTT mean for a direction
 */
static inline f64
session_quality_get_rtt_mean (const session_quality_data_t *data, u8 direction)
{
  if (direction > 1)
    return 0.0;
  return data->tcp_data.rtt_mean[direction];
}

/**
 * @brief Get RTT standard deviation for a direction
 */
static inline f64
session_quality_get_rtt_stddev (const session_quality_data_t *data,
				u8 direction)
{
  if (direction > 1)
    return 0.0;
  return session_quality_tcp_rtt_stddev (&data->tcp_data, direction);
}

/**
 * @brief Get RTT asymmetry ratio (max/min of forward/reverse RTT means)
 */
static inline f64
session_quality_get_rtt_asymmetry (const session_quality_data_t *data)
{
  const session_quality_tcp_data_t *tcp = &data->tcp_data;

  if (tcp->rtt_mean[0] <= 0.001 || tcp->rtt_mean[1] <= 0.001)
    return 1.0; /* No asymmetry if we don't have both measurements */

  return clib_max (tcp->rtt_mean[0], tcp->rtt_mean[1]) /
	 clib_min (tcp->rtt_mean[0], tcp->rtt_mean[1]);
}

/* ---- TTL Analysis Helpers ---- */

/**
 * @brief Get TTL asymmetry (difference between forward and reverse mean TTL)
 */
static inline f64
session_quality_get_ttl_asymmetry (const session_quality_data_t *data)
{
  if (data->ttl_count[0] == 0 || data->ttl_count[1] == 0)
    return 0.0;
  return fabs (data->ttl_mean[0] - data->ttl_mean[1]);
}

#endif /* __SESSION_QUALITY_H__ */
