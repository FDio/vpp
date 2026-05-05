/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HSI_HSI_TRACKER_H_
#define SRC_PLUGINS_HSI_HSI_TRACKER_H_

#include <hsi/hsi.h>
#include <vnet/buffer.h>
#include <vnet/tcp/tcp_types.h>
#include <vnet/udp/udp.h>

typedef enum hsi_tracked_action_
{
  HSI_TRACKED_ACTION_FORWARD,
  HSI_TRACKED_ACTION_HELD,
  HSI_TRACKED_ACTION_DROP,
} hsi_tracked_action_t;

typedef hsi_tracked_action_t hsi_tcp_tracked_action_t;
typedef hsi_tracked_action_t hsi_udp_tracked_action_t;

#define HSI_TCP_TRACKED_ACTION_FORWARD HSI_TRACKED_ACTION_FORWARD
#define HSI_TCP_TRACKED_ACTION_HELD    HSI_TRACKED_ACTION_HELD
#define HSI_TCP_TRACKED_ACTION_DROP    HSI_TRACKED_ACTION_DROP
#define HSI_UDP_TRACKED_ACTION_FORWARD HSI_TRACKED_ACTION_FORWARD
#define HSI_UDP_TRACKED_ACTION_HELD    HSI_TRACKED_ACTION_HELD
#define HSI_UDP_TRACKED_ACTION_DROP    HSI_TRACKED_ACTION_DROP

hsi_tcp_tracked_action_t hsi_tcp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b,
							    tcp_connection_t *tc, void *ip_hdr,
							    tcp_header_t *tcp_hdr, u8 is_ip4);
int hsi_tcp_try_complete_drain (vlib_main_t *vm, tcp_connection_t *tc);
hsi_tcp_tracked_action_t hsi_tcp_drain_cache_buffer (vlib_main_t *vm, vlib_buffer_t *b,
						     tcp_connection_t *tc, void *ip_hdr,
						     tcp_header_t *tcp_hdr, u8 is_ip4);
void hsi_tcp_drain_update_time (f64 time_now, u8 thread_index);
void hsi_tcp_fin_wait_update_time (f64 time_now, u8 thread_index);
void hsi_tracker_show (vlib_main_t *vm);

static_always_inline hsi_tcp_tracked_action_t
hsi_tcp_tracked_connection_action (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc,
				   void *ip_hdr, tcp_header_t *tcp_hdr, u8 is_ip4)
{
  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);

  if (tc->state == TCP_STATE_CLOSED || hsi_tcp_try_complete_drain (vm, tc))
    return hsi_tcp_handle_tracked_connection (vm, b, tc, ip_hdr, tcp_hdr, is_ip4);

  return hsi_tcp_drain_cache_buffer (vm, b, tc, ip_hdr, tcp_hdr, is_ip4);
}

void hsi_udp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc,
					void *ip_hdr, udp_header_t *udp_hdr, u8 is_ip4);
int hsi_udp_connection_is_draining (udp_connection_t *uc);
udp_connection_t *hsi_udp_migrate_tracked_connection (session_t **ps, udp_connection_t *uc);
int hsi_udp_try_complete_drain (vlib_main_t *vm, udp_connection_t *uc);
hsi_udp_tracked_action_t hsi_udp_drain_cache_buffer (vlib_main_t *vm, vlib_buffer_t *b,
						     udp_connection_t *uc, void *ip_hdr,
						     udp_header_t *udp_hdr, u8 is_ip4);
hsi_udp_tracked_action_t hsi_udp_drain_cache_buffer_remote (vlib_main_t *vm, vlib_buffer_t *b,
							    session_t *s, udp_connection_t *uc,
							    void *ip_hdr, udp_header_t *udp_hdr,
							    u8 is_ip4);
void hsi_udp_drain_update_time (f64 time_now, u8 thread_index);
void hsi_udp_idle_update_time (f64 time_now, u8 thread_index);
void hsi_udp_idle_timeout_update (void);

static_always_inline hsi_udp_tracked_action_t
hsi_udp_tracked_connection_action (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc,
				   void *ip_hdr, udp_header_t *udp_hdr, u8 is_ip4)
{
  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);

  if (!hsi_udp_try_complete_drain (vm, uc))
    return hsi_udp_drain_cache_buffer (vm, b, uc, ip_hdr, udp_hdr, is_ip4);

  hsi_udp_handle_tracked_connection (vm, b, uc, ip_hdr, udp_hdr, is_ip4);
  return HSI_UDP_TRACKED_ACTION_FORWARD;
}

#endif /* SRC_PLUGINS_HSI_HSI_TRACKER_H_ */
