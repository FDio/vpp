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

void hsi_tcp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc,
					void *ip_hdr, tcp_header_t *tcp_hdr, u8 is_ip4);
int hsi_tcp_try_complete_drain (tcp_connection_t *tc);

static_always_inline u8
hsi_tcp_tracked_connection_action (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc,
				   void *ip_hdr, tcp_header_t *tcp_hdr, u8 is_ip4)
{
  tcp_state_t state;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);

  state = tc->state;
  if (state != TCP_STATE_CLOSED && hsi_tcp_try_complete_drain (tc))
    state = TCP_STATE_CLOSED;

  if (state != TCP_STATE_CLOSED)
    {
      vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
      return 0;
    }

  hsi_tcp_handle_tracked_connection (vm, b, tc, ip_hdr, tcp_hdr, is_ip4);
  return 1;
}

void hsi_udp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc,
					void *ip_hdr, udp_header_t *udp_hdr, u8 is_ip4);

#endif /* SRC_PLUGINS_HSI_HSI_TRACKER_H_ */
