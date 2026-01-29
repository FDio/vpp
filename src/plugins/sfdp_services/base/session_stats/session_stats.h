/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_session_stats_h__
#define __included_sfdp_session_stats_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>

/*
 * Session statistics structure - tracks packets and bytes per direction
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 packets[SFDP_FLOW_F_B_N]; /**< Packet count per direction */
  u64 bytes[SFDP_FLOW_F_B_N];	/**< Byte count per direction */
  session_version_t version;	/**< Session version for validation */
  f64 first_seen;		/**< Timestamp of first packet */
  f64 last_seen;		/**< Timestamp of last packet */
} sfdp_session_stats_entry_t;

/*
 * Ring buffer entry for session stats export
 * This is the format written to the stat segment ring buffer
 */
typedef struct
{
  u64 session_id;		    /**< SFDP session ID */
  u32 session_index;		    /**< Session pool index */
  u32 tenant_id;		    /**< Tenant ID */
  u8 proto;			    /**< IP protocol */
  u8 session_type;		    /**< Session type (IP4/IP6/USER) */
  u8 export_reason;		    /**< Reason for export (expiry/periodic) */
  u8 pad;			    /**< Padding for alignment */
  u64 packets_forward;		    /**< Forward direction packets */
  u64 packets_reverse;		    /**< Reverse direction packets */
  u64 bytes_forward;		    /**< Forward direction bytes */
  u64 bytes_reverse;		    /**< Reverse direction bytes */
  f64 first_seen;		    /**< First packet timestamp */
  f64 last_seen;		    /**< Last packet timestamp */
  f64 export_time;		    /**< Time of export */
  u8 src_ip[16];		    /**< Source IP (IPv4 in first 4 bytes) */
  u8 dst_ip[16];		    /**< Destination IP */
  u16 src_port;			    /**< Source port */
  u16 dst_port;			    /**< Destination port */
  u8 is_ip4;			    /**< 1 if IPv4, 0 if IPv6 */
  u8 reserved[15];		    /**< Padding to 128 bytes */
} __clib_packed sfdp_session_stats_ring_entry_t;

STATIC_ASSERT_SIZEOF (sfdp_session_stats_ring_entry_t, 128);

#define foreach_sfdp_session_stats_export_reason                              \
  _ (PERIODIC, 0, "periodic")                                                 \
  _ (EXPIRY, 1, "expiry")                                                     \
  _ (API_REQUEST, 2, "api-request")

typedef enum
{
#define _(name, val, str) SFDP_SESSION_STATS_EXPORT_##name = val,
  foreach_sfdp_session_stats_export_reason
#undef _
} sfdp_session_stats_export_reason_t;

/*
 * Per-thread data for session stats
 */
typedef struct
{
  f64 last_export_time; /**< Last time stats were exported to ring */
} sfdp_session_stats_per_thread_t;

/*
 * Main session stats structure
 */
typedef struct
{
  sfdp_session_stats_entry_t *stats; /**< vec indexed by session-index */
  sfdp_session_stats_per_thread_t *per_thread; /**< Per-thread data */

  u32 ring_buffer_index;	/**< Stats segment ring buffer index */
  u32 ring_buffer_size;		/**< Ring buffer size */
  f64 export_interval;		/**< Export interval in seconds */
  u8 ring_buffer_enabled;	/**< Ring buffer enabled flag */
  u8 periodic_export_enabled;	/**< Enable periodic export */
  u8 export_on_expiry;		/**< Export stats when session expires */
  u8 pad;			/**< Padding */
  u64 total_exports;		/**< Total exports counter */
  u16 msg_id_base;		/**< API message ID base */
} sfdp_session_stats_main_t;

extern sfdp_session_stats_main_t sfdp_session_stats_main;

/* Default ring buffer size */
#define SFDP_SESSION_STATS_DEFAULT_RING_SIZE 4096

/* Format functions */
format_function_t format_sfdp_session_stats;
format_function_t format_sfdp_session_stats_export_reason;

/* Ring buffer functions */
int sfdp_session_stats_ring_init (vlib_main_t *vm, u32 ring_size);
void sfdp_session_stats_export_session (vlib_main_t *vm, u32 session_index,
					sfdp_session_stats_export_reason_t reason);
void sfdp_session_stats_export_all_sessions (vlib_main_t *vm,
					     sfdp_session_stats_export_reason_t reason);

#endif /* __included_sfdp_session_stats_h__ */
