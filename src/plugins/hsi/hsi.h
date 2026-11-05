/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HSI_HSI_H_
#define SRC_PLUGINS_HSI_HSI_H_

#include <hsi/hsi_types.h>
#include <vnet/tcp/tcp_types.h>
#include <vnet/udp/udp.h>

__clib_export void hsi_intercept_proto (transport_proto_t proto, u8 is_ip4,
					u8 is_enable);

/*
 * s must belong to the calling worker. For sessions on different workers, HSI
 * handles deferral and peer worker updates with RPCs. A return value of 0 means
 * HSI owns both sessions and the application must not use them afterwards.
 */
/*
 * Returns 0 once HSI owns both sessions. On success, the application must stop
 * using and closing them; on failure, ownership remains with the caller.
 */
__clib_export int hsi_track_session_pair (session_t *s, session_handle_t peer_session_handle);
__clib_export int hsi_track_session_pair_ext (session_t *s, session_handle_t peer_session_handle,
					      u32 app_session_index);

/* Application-level callbacks invoked by HSI during tracker lifecycle events.
 * Registered by the application plugin via hsi_register_app_session_cbs. */
typedef struct hsi_app_session_cbs_
{
  void (*cleanup) (u32 app_session_index);
} hsi_app_session_cbs_t;

__clib_export void hsi_register_app_session_cbs (hsi_app_session_cbs_t *cbs);

struct hsi_tcp_tracker_;
struct hsi_udp_tracker_;

/* VFT exported by hsi_plugin.so for other plugins to access tracker ops */
typedef struct hsi_tracker_vft_
{
  /* hand off a session pair to HSI for tracking; works for both TCP and UDP */
  int (*track_session_pair) (session_t *s, session_handle_t peer_sh, u32 app_session_index);
  /* process a TCP packet on a tracked connection; returns tracked action */
  int (*tcp_tracked_action) (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc, void *ip_hdr,
			     void *tcp_hdr, u8 is_ip4, u8 send_rst_on_drain_fail,
			     u8 *cleanup_session);
  /* retrieve the TCP tracker object for a tracked TCP connection */
  struct hsi_tcp_tracker_ *(*tcp_tracker_get) (tcp_connection_t *tc);
  /* process a UDP packet on a tracked connection */
  void (*udp_tracked_action) (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc, void *ip_hdr,
			      udp_header_t *udp_hdr, u8 is_ip4);
  /* retrieve the UDP tracker object for a tracked UDP connection */
  struct hsi_udp_tracker_ *(*udp_tracker_get) (udp_connection_t *uc);
} hsi_tracker_vft_t;

__clib_export hsi_tracker_vft_t *hsi_tracker_vft_get (void);

#endif /* SRC_PLUGINS_HSI_HSI_H_ */
