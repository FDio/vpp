/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HSI_HSI_TYPES_H_
#define SRC_PLUGINS_HSI_HSI_TYPES_H_

#include <vnet/ip/ip46_address.h>
#include <vnet/session/session.h>

#define HSI_TCP_DRAIN_CACHE_DEFAULT_PACKETS	  3
#define HSI_TCP_DRAIN_NO_PROGRESS_DEFAULT_TIMEOUT 10.0
#define HSI_UDP_DRAIN_CACHE_DEFAULT_PACKETS	  3
#define HSI_UDP_DRAIN_NO_PROGRESS_DEFAULT_TIMEOUT 10.0
#define HSI_UDP_IDLE_DEFAULT_TIMEOUT		  300.0
#define HSI_TCP_FIN_WAIT_DEFAULT_TIMEOUT	  2.0

typedef struct hsi_tcp_track_snapshot_
{
  session_handle_t session_handle;
  u32 conn_index;
  u32 fib_index;
  ip46_address_t lcl_ip;
  ip46_address_t rmt_ip;
  u16 lcl_port;
  u16 rmt_port;
  u32 snd_nxt;
  u32 rcv_nxt;
  u32 ts_now;
  u32 tsval_recent;
  clib_thread_index_t thread_index;
  u8 rcv_wscale;
  u8 snd_wscale;
} hsi_tcp_track_snapshot_t;

typedef struct hsi_tcp_track_commit_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  hsi_tcp_track_snapshot_t peer;
} hsi_tcp_track_commit_req_t;

typedef struct hsi_tcp_drain_ hsi_tcp_drain_t;
typedef struct hsi_tcp_drain_start_req_ hsi_tcp_drain_start_req_t;
typedef struct hsi_tcp_fin_ack_req_ hsi_tcp_fin_ack_req_t;
typedef struct hsi_tcp_peer_fin_req_ hsi_tcp_peer_fin_req_t;
typedef struct hsi_session_fifos_cleanup_req_ hsi_session_fifos_cleanup_req_t;
typedef struct hsi_udp_track_commit_req_ hsi_udp_track_commit_req_t;
typedef struct hsi_udp_peer_update_req_ hsi_udp_peer_update_req_t;
typedef struct hsi_udp_drain_ hsi_udp_drain_t;
typedef struct hsi_udp_drain_start_req_ hsi_udp_drain_start_req_t;
typedef struct hsi_udp_drain_cache_req_ hsi_udp_drain_cache_req_t;

#define foreach_hsi_wrk_stat                                                                       \
  _ (tcp_track_accepted, u64, "tcp-track-accepted")                                                \
  _ (tcp_track_failed, u64, "tcp-track-failed")                                                    \
  _ (tcp_track_peer_rpc_failed, u64, "tcp-peer-rpc-failed")                                        \
  _ (tcp_drain_started, u64, "tcp-drain-started")                                                  \
  _ (tcp_drain_completed, u64, "tcp-drain-completed")                                              \
  _ (tcp_drain_stalled, u64, "tcp-drain-stalled")                                                  \
  _ (tcp_drain_cached, u64, "tcp-drain-cached")                                                    \
  _ (tcp_drain_cache_overflow, u64, "tcp-drain-cache-overflow")                                    \
  _ (tcp_drain_cache_dropped, u64, "tcp-drain-cache-dropped")                                      \
  _ (tcp_drain_cache_flushed, u64, "tcp-drain-cache-flushed")                                      \
  _ (tcp_cleanup_scheduled, u64, "tcp-cleanup-scheduled")                                          \
  _ (tcp_cleanup_completed, u64, "tcp-cleanup-completed")                                          \
  _ (tcp_fin_cleanup, u64, "tcp-fin-cleanup")                                                      \
  _ (tcp_fin_wait_started, u64, "tcp-fin-wait-started")                                            \
  _ (tcp_fin_wait_cleanup, u64, "tcp-fin-wait-cleanup")                                            \
  _ (tcp_rst_cleanup, u64, "tcp-rst-cleanup")                                                      \
  _ (udp_track_accepted, u64, "udp-track-accepted")                                                \
  _ (udp_track_failed, u64, "udp-track-failed")                                                    \
  _ (udp_track_peer_rpc_failed, u64, "udp-peer-rpc-failed")                                        \
  _ (udp_track_migrated, u64, "udp-track-migrated")                                                \
  _ (udp_track_migration_failed, u64, "udp-track-migration-failed")                                \
  _ (udp_drain_started, u64, "udp-drain-started")                                                  \
  _ (udp_drain_completed, u64, "udp-drain-completed")                                              \
  _ (udp_drain_stalled, u64, "udp-drain-stalled")                                                  \
  _ (udp_drain_cached, u64, "udp-drain-cached")                                                    \
  _ (udp_drain_cache_overflow, u64, "udp-drain-cache-overflow")                                    \
  _ (udp_drain_cache_dropped, u64, "udp-drain-cache-dropped")                                      \
  _ (udp_drain_cache_flushed, u64, "udp-drain-cache-flushed")                                      \
  _ (udp_idle_timeout, u64, "udp-idle-timeout")                                                    \
  _ (udp_idle_cleanup_scheduled, u64, "udp-idle-cleanup-scheduled")                                \
  _ (udp_cleanup_completed, u64, "udp-cleanup-completed")

typedef struct hsi_worker_stats_
{
#define _(name, type, str) type name;
  foreach_hsi_wrk_stat
#undef _
} hsi_worker_stats_t;

typedef struct hsi_worker_
{
  hsi_tcp_track_commit_req_t *tcp_track_commit_reqs;
  hsi_tcp_drain_start_req_t *tcp_drain_start_reqs;
  hsi_tcp_fin_ack_req_t *tcp_fin_ack_reqs;
  hsi_tcp_peer_fin_req_t *tcp_peer_fin_reqs;
  hsi_session_fifos_cleanup_req_t *session_fifos_cleanup_reqs;
  hsi_tcp_drain_t *tcp_drains;
  uword *tcp_drain_by_session_conn;
  session_handle_t *tcp_drain_update_handles;
  uword *tcp_fin_wait_by_session_conn;
  uword *tcp_fin_wait_update_keys;
  hsi_worker_stats_t stats;
  u8 tcp_drain_time_registered;
  u8 tcp_drain_time_unregister_pending;
  u8 tcp_fin_wait_time_registered;
  u8 tcp_fin_wait_time_unregister_pending;
  uword *udp_track_peer_by_session_conn;
  hsi_udp_track_commit_req_t *udp_track_commit_reqs;
  hsi_udp_peer_update_req_t *udp_peer_update_reqs;
  hsi_udp_drain_start_req_t *udp_drain_start_reqs;
  hsi_udp_drain_cache_req_t *udp_drain_cache_reqs;
  hsi_udp_drain_t *udp_drains;
  uword *udp_drain_by_session_conn;
  session_handle_t *udp_drain_update_handles;
  uword *udp_idle_by_session_conn;
  uword *udp_idle_update_keys;
  u8 udp_drain_time_registered;
  u8 udp_drain_time_unregister_pending;
  u8 udp_idle_time_registered;
  u8 udp_idle_time_unregister_pending;
} hsi_worker_t;

#define hsi_worker_counter_inc(_wrk, _counter)                                                     \
  do                                                                                               \
    {                                                                                              \
      (_wrk)->stats._counter++;                                                                    \
    }                                                                                              \
  while (0)

#define hsi_worker_counter_add(_wrk, _counter, _value)                                             \
  do                                                                                               \
    {                                                                                              \
      (_wrk)->stats._counter += (_value);                                                          \
    }                                                                                              \
  while (0)

#define hsi_worker_proto_counter_inc(_wrk, _proto, _counter)                                       \
  do                                                                                               \
    {                                                                                              \
      if ((_proto) == TRANSPORT_PROTO_UDP)                                                         \
	hsi_worker_counter_inc (_wrk, udp_##_counter);                                             \
      else                                                                                         \
	hsi_worker_counter_inc (_wrk, tcp_##_counter);                                             \
    }                                                                                              \
  while (0)

typedef enum _hsi_error
{
#define hsi_error(n, s) HSI_ERROR_##n,
#include <hsi/hsi_error.def>
#undef hsi_error
  HSI_N_ERROR,
} hsi_error_t;

typedef struct hsi_main_
{
  hsi_worker_t *wrk;
  u8 intercept_type;
  u32 tcp_drain_cache_max_packets;
  f64 tcp_drain_no_progress_timeout;
  u32 udp_drain_cache_max_packets;
  f64 udp_drain_no_progress_timeout;
  f64 udp_idle_timeout;
  f64 tcp_fin_wait_timeout;

  /* ipv4 and ipv6 for tcp and udp */
  session_handle_t intercept_listeners[2][2];
} hsi_main_t;

extern hsi_main_t hsi_main;

#endif /* SRC_PLUGINS_HSI_HSI_TYPES_H_ */
