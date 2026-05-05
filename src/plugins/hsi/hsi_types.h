/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HSI_HSI_TYPES_H_
#define SRC_PLUGINS_HSI_HSI_TYPES_H_

#include <vnet/ip/ip46_address.h>
#include <vnet/session/session.h>

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
typedef struct hsi_udp_track_commit_req_ hsi_udp_track_commit_req_t;

typedef struct hsi_worker_
{
  hsi_tcp_track_commit_req_t *tcp_track_commit_reqs;
  hsi_tcp_drain_start_req_t *tcp_drain_start_reqs;
  hsi_tcp_drain_t *tcp_drains;
  uword *tcp_drain_by_session_conn;
  hsi_udp_track_commit_req_t *udp_track_commit_reqs;
} hsi_worker_t;

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

  /* ipv4 and ipv6 for tcp and udp */
  session_handle_t intercept_listeners[2][2];
} hsi_main_t;

extern hsi_main_t hsi_main;

#endif /* SRC_PLUGINS_HSI_HSI_TYPES_H_ */
