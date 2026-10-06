/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_session_stats_h__
#define __included_sfdp_session_stats_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>

/*
 * TCP-specific session statistics - tracks TCP protocol metrics
 * Inspired by SASC flow_quality service
 */
typedef struct
{
  /* Basic TCP counters */
  u32 syn_packets; /**< SYN packets seen */
  u32 fin_packets; /**< FIN packets seen */
  u32 rst_packets; /**< RST packets seen */

  /* ECN/CWR tracking (Explicit Congestion Notification) */
  u32 ecn_ect_packets; /**< Packets with ECN ECT(0) or ECT(1) marks */
  u32 ecn_ce_packets;  /**< Packets with ECN CE (Congestion Experienced) marks */
  u32 ece_packets;     /**< Packets with TCP ECE flag set */
  u32 cwr_packets;     /**< Packets with TCP CWR flag set */

  /* TCP events per direction */
  u32 retransmissions[SFDP_FLOW_F_B_N];	   /**< Detected data retransmits */
  u32 zero_window_events[SFDP_FLOW_F_B_N]; /**< Receiver window = 0 transitions */
  u32 dupack_like[SFDP_FLOW_F_B_N];	   /**< Duplicate ACK patterns */
  u32 partial_overlaps[SFDP_FLOW_F_B_N];   /**< Partially overlapping segments */
  u32 out_of_order[SFDP_FLOW_F_B_N];	   /**< Out-of-order segments detected */

  /* TCP sequence window tracking */
  u32 last_seq[SFDP_FLOW_F_B_N]; /**< Last sequence number seen */
  u32 last_ack[SFDP_FLOW_F_B_N]; /**< Last ACK number seen */

  /* MSS from SYN options */
  u16 mss;		 /**< MSS from SYN options if available */
  u8 handshake_complete; /**< 3-way handshake completed flag */
  u8 reserved_tcp;
} sfdp_session_stats_tcp_t;

typedef struct
{
  f64 mean;  /**< Running mean */
  f64 m2;    /**< Variance accumulator */
  u32 count; /**< Sample count */
  u32 reserved;
} sfdp_session_stats_rtt_t;

typedef struct
{
  u8 min_ttl; /**< Minimum TTL seen */
  u8 max_ttl; /**< Maximum TTL seen */
  u8 reserved[2];
  f64 mean;  /**< Running mean */
  f64 m2;    /**< Variance accumulator */
  u32 count; /**< Sample count */
} sfdp_session_stats_ttl_t;

/*
 * Session statistics structure - tracks packets and bytes per direction
 * Extended with TTL, RTT, and TCP-specific metrics
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 packets[SFDP_FLOW_F_B_N]; /**< Packet count per direction */
  u64 bytes[SFDP_FLOW_F_B_N];	/**< Byte count per direction */
  session_version_t version;	/**< Session version for validation */
  f64 first_seen;		/**< Timestamp of first packet */
  f64 last_seen;		/**< Timestamp of last packet */

  /* Extended statistics - TTL per direction */
  sfdp_session_stats_ttl_t ttl[SFDP_FLOW_F_B_N];

  /* Extended statistics - RTT per direction */
  sfdp_session_stats_rtt_t rtt[SFDP_FLOW_F_B_N];

  /* TCP-specific statistics (only valid for TCP sessions) */
  sfdp_session_stats_tcp_t tcp;

  /* RTT measurement helpers */
  u32 rtt_probe_tick_us[SFDP_FLOW_F_B_N];   /**< When data was sent for RTT measurement */
  u32 last_data_seq[SFDP_FLOW_F_B_N];	    /**< Last data sequence for RTT */
  u32 end_seq_max[SFDP_FLOW_F_B_N];	    /**< Highest seq+len for overlap detection */
  u8 last_seq_valid[SFDP_FLOW_F_B_N];	    /**< Sequence tracking valid flag */
  u8 in_zero_window[SFDP_FLOW_F_B_N];	    /**< Currently in zero window state */
  u8 has_pending_gap[SFDP_FLOW_F_B_N];	    /**< Forward gap detected, awaiting fill */
  u32 gap_start_seq[SFDP_FLOW_F_B_N];	    /**< Seq where the gap begins (old end_seq_max) */
  u32 gap_dupack_snapshot[SFDP_FLOW_F_B_N]; /**< dupack_like[ack_dir] at gap detection */
} sfdp_session_stats_entry_t;

/* Default value for opaque data when no tenant-specific value is set */
#define SFDP_SESSION_STATS_OPAQUE_DATA_DEFAULT ((u64) 0)

/* Value to indicate all tenants (max u32) */
#define SFDP_SESSION_STATS_ALL_TENANTS ((u32) ~0U)

#define foreach_sfdp_session_stats_export_reason                                                   \
  _ (PERIODIC, 0, "periodic")                                                                      \
  _ (EXPIRY, 1, "expiry")                                                                          \
  _ (API_REQUEST, 2, "api-request")

typedef enum
{
#define _(name, val, str) SFDP_SESSION_STATS_EXPORT_##name = val,
  foreach_sfdp_session_stats_export_reason
#undef _
} sfdp_session_stats_export_reason_t;

/* Per-thread data for session stats */
typedef struct
{
  f64 last_export_time; /**< Last time stats were exported to ring */
  u64 total_exports;	/**< Per-thread export counter */
} sfdp_session_stats_per_thread_t;

/*
 * Per-tenant custom data entry
 */
typedef struct
{
  u64 value;	/**< Custom data value */
  u8 has_value; /**< Whether value has been explicitly set */
  u8 reserved[7];
} sfdp_session_stats_custom_data_entry_t;

/*
 * Main session stats structure
 */
typedef struct
{
  sfdp_session_stats_entry_t *stats;	       /**< vec indexed by session-index */
  sfdp_session_stats_per_thread_t *per_thread; /**< Per-thread data */

  u32 ring_buffer_index;      /**< Stats segment ring buffer index */
  u32 ring_buffer_size;	      /**< Ring buffer size */
  f64 export_interval;	      /**< Export interval in seconds */
  f64 export_batch_interval;  /**< Export batch interval in seconds */
  u8 ring_buffer_enabled;     /**< Ring buffer enabled flag */
  u8 periodic_export_enabled; /**< Enable periodic export */
  u8 export_on_expiry;	      /**< Export stats when session expires */

  /* Per-tenant custom data, vec indexed directly by tenant_id */
  sfdp_session_stats_custom_data_entry_t *custom_data_entries;
  vlib_log_class_t log_class; /**< Log class */

  u16 msg_id_base; /**< API message ID base */
} sfdp_session_stats_main_t;

extern sfdp_session_stats_main_t sfdp_session_stats_main;

/* Sum total exports across all threads */
static inline u64
sfdp_session_stats_total_exports (sfdp_session_stats_main_t *ssm)
{
  sfdp_session_stats_per_thread_t *pt;
  u64 total = 0;
  vec_foreach (pt, ssm->per_thread)
    total += pt->total_exports;
  return total;
}

/* Default ring buffer size */
#define SFDP_SESSION_STATS_DEFAULT_RING_SIZE 4096

/* Default export interval(s) for ring buffer (in seconds) */
#define SFDP_SESSION_STATS_DEFAULT_EXPORT_INTERVAL	 30.0
#define SFDP_SESSION_STATS_DEFAULT_BATCH_EXPORT_INTERVAL 1.0

/* Minimum ratio the export interval must have compared to the batch cycle */
#define SFDP_SESSION_STATS_BATCH_CYCLE_MAX_RATIO 2.0

/* Ring buffer functions */
int sfdp_session_stats_ring_init (vlib_main_t *vm, u32 ring_size);
int sfdp_session_stats_export_session (vlib_main_t *vm, u32 session_index,
				       sfdp_session_stats_export_reason_t reason);
void sfdp_session_stats_export_all_sessions (vlib_main_t *vm,
					     sfdp_session_stats_export_reason_t reason);
u32 sfdp_session_stats_export_batch (vlib_main_t *vm, sfdp_session_stats_export_reason_t reason,
				     u32 start_index, u32 max_entries, f64 active_since);

int sfdp_session_stats_clear_sessions (u64 session_id);

/* Custom data configuration functions */
int sfdp_session_stats_set_tenant_custom_data (u32 tenant_id, u64 value);
int sfdp_session_stats_clear_tenant_custom_data (u32 tenant_id);
u64 sfdp_session_stats_get_tenant_custom_data (u32 tenant_id, u8 *has_value);

/* Export and periodic node control functions */
int sfdp_session_stats_periodic_export_enable (vlib_main_t *vm, f64 interval, f64 batch_interval);
void sfdp_session_stats_periodic_export_disable (vlib_main_t *vm);
void sfdp_session_stats_export_now (vlib_main_t *vm);

/* Time utility: get current time in microseconds (wrapping u32) */
static inline u32
sfdp_session_stats_now_ticks_us (vlib_main_t *vm)
{
  f64 seconds = vlib_time_now (vm);
  u64 us64 = (u64) (seconds * 1e6);
  return (u32) us64; /* wrap intentionally */
}

/* Time utility: compute delta in seconds from wrapping u32 microsecond ticks */
static inline f64
sfdp_session_stats_delta_s_from_ticks (u32 newer, u32 older)
{
  u32 delta_us = newer - older; /* unsigned wrap-safe */
  return (f64) delta_us / 1e6;
}

/* Welford update for running mean and M2 (variance accumulator) */
static inline void
sfdp_session_stats_welford_update (f64 *mean, f64 *m2, u32 *count, f64 sample)
{
  (*count)++;
  f64 delta = sample - *mean;
  *mean += delta / (f64) (*count);
  *m2 += delta * (sample - *mean);
}

/* Compute stddev from Welford M2 and count */
static inline f64
sfdp_session_stats_compute_stddev (f64 m2, u32 count)
{
  if (count < 2)
    return 0.0;
  f64 var = m2 / (f64) (count - 1);
  return var > 0 ? __builtin_sqrt (var) : 0.0;
}

/* Update TTL statistics for a direction */
static inline void
sfdp_session_stats_update_ttl (sfdp_session_stats_ttl_t *ttl, u8 ttl_value)
{
  if (ttl->count == 0 || ttl_value < ttl->min_ttl)
    ttl->min_ttl = ttl_value;
  if (ttl->count == 0 || ttl_value > ttl->max_ttl)
    ttl->max_ttl = ttl_value;

  sfdp_session_stats_welford_update (&ttl->mean, &ttl->m2, &ttl->count, (f64) ttl_value);
}

/* Update RTT statistics for a direction */
static inline void
sfdp_session_stats_update_rtt (sfdp_session_stats_rtt_t *rtt, f64 rtt_sample)
{
  /* Only accept reasonable RTT samples (0-60 seconds) */
  if (rtt_sample >= 0 && rtt_sample < 60.0)
    {
      sfdp_session_stats_welford_update (&rtt->mean, &rtt->m2, &rtt->count, rtt_sample);
    }
}

#endif /* __included_sfdp_session_stats_h__ */
