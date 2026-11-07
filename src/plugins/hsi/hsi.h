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

typedef enum hsi_track_flags_
{
  /*
   * Hand sessions back to the app for SESSION_CLEANUP_SESSION once HSI is done
   * with them. Transport and fifos are gone but opaque is kept. Migrated UDP
   * flows are reported on the migrated session. App worker must stay valid
   * until notified.
   */
  HSI_TRACK_F_NOTIFY_CLEANUP = 1 << 0,
} hsi_track_flags_t;

typedef struct hsi_track_args_
{
  session_t *s;
  session_handle_t peer_session_handle;
  hsi_track_flags_t flags;
} hsi_track_args_t;

/*
 * s must belong to the calling worker. For sessions on different workers, HSI
 * handles deferral and peer worker updates with RPCs. A return value of 0 means
 * HSI owns both sessions and the application must not use them afterwards.
 */
/*
 * Returns 0 once HSI owns both sessions. On success, the application must stop
 * using and closing them; on failure, ownership remains with the caller.
 *
 * Tracked tcp packets are forwarded from the worker of the connection that
 * received them. If tcp output of that connection is overridden, forwards
 * replayed from drain caches go through the override node, with the
 * connection's next_node_opaque, so both connections must use the same node.
 * Unlike the connection's own segments, forwards are not locally originated.
 */
__clib_export int hsi_track_pair (hsi_track_args_t *a);

/* Deprecated, use hsi_track_pair */
__clib_export int hsi_track_session_pair (session_t *s, session_handle_t peer_session_handle)
  __attribute__ ((deprecated ("use hsi_track_pair")));

struct hsi_tcp_tracker_;
struct hsi_udp_tracker_;

/* VFT exported by hsi_plugin.so for other plugins to access tracker ops */
typedef struct hsi_tracker_vft_
{
  /* deprecated, use track_pair */
  int (*track_session_pair) (session_t *s, session_handle_t peer_sh);
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
  /* hand off a session pair to HSI for tracking; works for both TCP and UDP */
  int (*track_pair) (hsi_track_args_t *a);
} hsi_tracker_vft_t;

__clib_export hsi_tracker_vft_t *hsi_tracker_vft_get (void);

#endif /* SRC_PLUGINS_HSI_HSI_H_ */
