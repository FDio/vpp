/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#ifndef included_vpp_session_stats_export_internal_h
#define included_vpp_session_stats_export_internal_h

#include <vpp-api/client/stat_client.h>
#include <vlib/stats/shared.h>
#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vppinfra/cJSON.h>
#include <vppinfra/time.h>
#include <plugins/sfdp_services/session_stats/session_stats.h>

/* Default port - follow existing exporter behavior */
#define SERVER_PORT 9482

/* Ring buffer name for SFDP session stats */
#define SFDP_SESSION_STATS_RING "/sfdp/session/stats"

/* Expected session stats ring entry size (must match sfdp_session_stats_ring_entry_t) */
#define SESSION_STATS_ENTRY_SIZE 320

/* Maximum sessions to track for Prometheus (to limit memory) */
#define MAX_TRACKED_SESSIONS 10000

/* Default name for custom API data if not found in schema */
#define CUSTOM_API_DATA_DEFAULT_NAME "custom_api_data"

#define foreach_session_stats_export_field(_)                                                      \
  _ (SESSION_ID, "session_id", FIELD_TYPE_U64, session_id)                                         \
  _ (SESSION_INDEX, "session_index", FIELD_TYPE_U32, session_index)                                \
  _ (TENANT_ID, "tenant_id", FIELD_TYPE_U32, tenant_id)                                            \
  _ (PROTO, "proto", FIELD_TYPE_U8, proto)                                                         \
  _ (SESSION_TYPE, "session_type", FIELD_TYPE_U8, session_type)                                    \
  _ (IS_IP4, "is_ip4", FIELD_TYPE_U8, is_ip4)                                                      \
  _ (PACKETS_FORWARD, "packets_forward", FIELD_TYPE_U64, packets_forward)                          \
  _ (PACKETS_REVERSE, "packets_reverse", FIELD_TYPE_U64, packets_reverse)                          \
  _ (BYTES_FORWARD, "bytes_forward", FIELD_TYPE_U64, bytes_forward)                                \
  _ (BYTES_REVERSE, "bytes_reverse", FIELD_TYPE_U64, bytes_reverse)                                \
  _ (DURATION, "duration", FIELD_TYPE_F64, duration)                                               \
  _ (SRC_IP, "src_ip", FIELD_TYPE_IP, src_ip)                                                      \
  _ (DST_IP, "dst_ip", FIELD_TYPE_IP, dst_ip)                                                      \
  _ (SRC_PORT, "src_port", FIELD_TYPE_U16, src_port)                                               \
  _ (DST_PORT, "dst_port", FIELD_TYPE_U16, dst_port)                                               \
  _ (TTL_MIN_FORWARD, "ttl_min_forward", FIELD_TYPE_U8, ttl_min_forward)                           \
  _ (TTL_MAX_FORWARD, "ttl_max_forward", FIELD_TYPE_U8, ttl_max_forward)                           \
  _ (TTL_MIN_REVERSE, "ttl_min_reverse", FIELD_TYPE_U8, ttl_min_reverse)                           \
  _ (TTL_MAX_REVERSE, "ttl_max_reverse", FIELD_TYPE_U8, ttl_max_reverse)                           \
  _ (TTL_MEAN_FORWARD, "ttl_mean_forward", FIELD_TYPE_F64, ttl_mean_forward)                       \
  _ (TTL_MEAN_REVERSE, "ttl_mean_reverse", FIELD_TYPE_F64, ttl_mean_reverse)                       \
  _ (TTL_STDDEV_FORWARD, "ttl_stddev_forward", FIELD_TYPE_F64, ttl_stddev_forward)                 \
  _ (TTL_STDDEV_REVERSE, "ttl_stddev_reverse", FIELD_TYPE_F64, ttl_stddev_reverse)                 \
  _ (RTT_MEAN_FORWARD, "rtt_mean_forward", FIELD_TYPE_F64, rtt_mean_forward)                       \
  _ (RTT_MEAN_REVERSE, "rtt_mean_reverse", FIELD_TYPE_F64, rtt_mean_reverse)                       \
  _ (RTT_STDDEV_FORWARD, "rtt_stddev_forward", FIELD_TYPE_F64, rtt_stddev_forward)                 \
  _ (RTT_STDDEV_REVERSE, "rtt_stddev_reverse", FIELD_TYPE_F64, rtt_stddev_reverse)                 \
  _ (TCP_MSS, "tcp_mss", FIELD_TYPE_U16, tcp_mss)                                                  \
  _ (TCP_HANDSHAKE_COMPLETE, "tcp_handshake_complete", FIELD_TYPE_U8, tcp_handshake_complete)      \
  _ (TCP_SYN_PACKETS, "tcp_syn_packets", FIELD_TYPE_U32, tcp_syn_packets)                          \
  _ (TCP_FIN_PACKETS, "tcp_fin_packets", FIELD_TYPE_U32, tcp_fin_packets)                          \
  _ (TCP_RST_PACKETS, "tcp_rst_packets", FIELD_TYPE_U32, tcp_rst_packets)                          \
  _ (TCP_ECN_ECT_PACKETS, "tcp_ecn_ect_packets", FIELD_TYPE_U32, tcp_ecn_ect_packets)              \
  _ (TCP_ECN_CE_PACKETS, "tcp_ecn_ce_packets", FIELD_TYPE_U32, tcp_ecn_ce_packets)                 \
  _ (TCP_ECE_PACKETS, "tcp_ece_packets", FIELD_TYPE_U32, tcp_ece_packets)                          \
  _ (TCP_CWR_PACKETS, "tcp_cwr_packets", FIELD_TYPE_U32, tcp_cwr_packets)                          \
  _ (TCP_RETRANSMISSIONS_FWD, "tcp_retransmissions_fwd", FIELD_TYPE_U32, tcp_retransmissions_fwd)  \
  _ (TCP_RETRANSMISSIONS_REV, "tcp_retransmissions_rev", FIELD_TYPE_U32, tcp_retransmissions_rev)  \
  _ (TCP_ZERO_WINDOW_EVENTS_FWD, "tcp_zero_window_events_fwd", FIELD_TYPE_U32,                     \
     tcp_zero_window_events_fwd)                                                                   \
  _ (TCP_ZERO_WINDOW_EVENTS_REV, "tcp_zero_window_events_rev", FIELD_TYPE_U32,                     \
     tcp_zero_window_events_rev)                                                                   \
  _ (TCP_DUPACK_EVENTS_FWD, "tcp_dupack_events_fwd", FIELD_TYPE_U32, tcp_dupack_events_fwd)        \
  _ (TCP_DUPACK_EVENTS_REV, "tcp_dupack_events_rev", FIELD_TYPE_U32, tcp_dupack_events_rev)        \
  _ (TCP_PARTIAL_OVERLAP_EVENTS_FWD, "tcp_partial_overlap_events_fwd", FIELD_TYPE_U32,             \
     tcp_partial_overlap_events_fwd)                                                               \
  _ (TCP_PARTIAL_OVERLAP_EVENTS_REV, "tcp_partial_overlap_events_rev", FIELD_TYPE_U32,             \
     tcp_partial_overlap_events_rev)                                                               \
  _ (TCP_OUT_OF_ORDER_EVENTS_FWD, "tcp_out_of_order_events_fwd", FIELD_TYPE_U32,                   \
     tcp_out_of_order_events_fwd)                                                                  \
  _ (TCP_OUT_OF_ORDER_EVENTS_REV, "tcp_out_of_order_events_rev", FIELD_TYPE_U32,                   \
     tcp_out_of_order_events_rev)                                                                  \
  _ (TCP_LAST_SEQ_FORWARD, "tcp_last_seq_forward", FIELD_TYPE_U32, tcp_last_seq_forward)           \
  _ (TCP_LAST_ACK_FORWARD, "tcp_last_ack_forward", FIELD_TYPE_U32, tcp_last_ack_forward)           \
  _ (TCP_LAST_SEQ_REVERSE, "tcp_last_seq_reverse", FIELD_TYPE_U32, tcp_last_seq_reverse)           \
  _ (TCP_LAST_ACK_REVERSE, "tcp_last_ack_reverse", FIELD_TYPE_U32, tcp_last_ack_reverse)           \
  _ (CUSTOM_DATA_FLAGS, "custom_data_flags", FIELD_TYPE_U8, custom_data_flags)                     \
  _ (CUSTOM_API_DATA, "custom_api_data", FIELD_TYPE_U64, custom_data.api_data)

typedef enum
{
#define _(id, name, type, member) FIELD_##id,
  foreach_session_stats_export_field (_)
#undef _
    FIELD_MAX
} schema_field_id_t;

typedef enum
{
  FIELD_TYPE_U8,
  FIELD_TYPE_U16,
  FIELD_TYPE_U32,
  FIELD_TYPE_U64,
  FIELD_TYPE_F64,
  FIELD_TYPE_IP,
  FIELD_TYPE_BYTES,
} schema_field_type_t;

typedef struct
{
  const char *name;
  schema_field_id_t id;
  schema_field_type_t type;
} schema_field_def_t;

typedef struct
{
  u8 valid;
  u32 offset;
  u32 size;
} schema_field_t;

typedef struct
{
  schema_field_t fields[FIELD_MAX];
  u32 entry_size;
  u32 schema_version;
  u32 schema_size;
  u32 schema_offset;
  u8 parsed;
  u8 valid;
  u8 has_core_labels;
  u8 has_custom_label;
  u8 has_custom_flags;
  char custom_api_data_name[SFDP_SESSION_STATS_CUSTOM_API_DATA_NAME_MAX_LEN + 1];
} ring_schema_t;

typedef struct
{
  u64 session_id;
  sfdp_session_stats_ring_entry_t stats;
  f64 last_update;
} tracked_session_t;

typedef struct
{
  u32 local_tail;
  u64 last_sequence;
  u8 initialized;
} thread_consumer_state_t;

/*
 * Global exporter state.
 * `session_silence_timeout`: stale threshold in seconds; stale sessions remain
 * in cache but are skipped during metrics emission.
 */
typedef struct
{
  tracked_session_t *sessions;
  uword *session_index_by_id;
  thread_consumer_state_t *thread_states;
  u8 *instance;
  ring_schema_t schema;
  f64 session_silence_timeout;
} session_exporter_main_t;

typedef enum
{
  CONSUME_OK = 0,
  CONSUME_ERR_NO_RING = -1,
  CONSUME_ERR_CONFIG = -2,
  CONSUME_ERR_SCHEMA = -3,
} consume_result_t;

extern session_exporter_main_t exporter_main;
extern const schema_field_def_t schema_field_defs[];

void schema_reset (ring_schema_t *schema);
int ensure_schema_loaded (session_exporter_main_t *em, stat_client_main_t *shm,
			  vlib_stats_entry_t *ep, const vlib_stats_ring_config_t *config,
			  const vlib_stats_ring_metadata_t *metadata, int *schema_changed);
void decode_entry (const session_exporter_main_t *em, const u8 *entry,
		   sfdp_session_stats_ring_entry_t *out);

consume_result_t consume_ring_buffer_entries (stat_client_main_t *shm);
void dump_session_metrics (FILE *stream, stat_client_main_t *shm);

#endif /* included_vpp_session_stats_export_internal_h */
