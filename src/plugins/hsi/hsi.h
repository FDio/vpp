/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HSI_HSI_H_
#define SRC_PLUGINS_HSI_HSI_H_

#include <vnet/session/session.h>

typedef struct hsi_tcp_track_commit_req_ hsi_tcp_track_commit_req_t;

typedef struct hsi_worker_
{
  hsi_tcp_track_commit_req_t *tcp_track_commit_reqs;
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
  u8 intercept_type;

  /* ipv4 and ipv6 for tcp and udp */
  session_handle_t intercept_listeners[2][2];

  hsi_worker_t *wrk;
} hsi_main_t;

extern hsi_main_t hsi_main;

__clib_export void hsi_intercept_proto (transport_proto_t proto, u8 is_ip4,
					u8 is_enable);
/*
 * s0 must belong to the calling worker. For sessions on different workers, the
 * app must call once from each worker with the local session passed as s0.
 */
__clib_export int hsi_track_session_pair (session_t *s0, session_t *s1);

#endif /* SRC_PLUGINS_HSI_HSI_H_ */
