/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __included_wg_send_h__
#define __included_wg_send_h__

#include <wireguard/wireguard_peer.h>

u8 *wg_build_rewrite (ip46_address_t *src_addr, u16 src_port,
		      ip46_address_t *dst_addr, u16 dst_port, u8 is_ip4);
bool wg_send_keepalive (vlib_main_t * vm, wg_peer_t * peer);
bool wg_send_handshake (vlib_main_t * vm, wg_peer_t * peer, bool is_retry);
void wg_send_handshake_from_mt (u32 peer_index, bool is_retry);
bool wg_send_handshake_response (vlib_main_t * vm, wg_peer_t * peer);
bool wg_send_handshake_cookie (vlib_main_t *vm, u32 sender_index,
			       cookie_checker_t *cookie_checker,
			       message_macs_t *macs,
			       ip46_address_t *wg_if_addr, u16 wg_if_port,
			       ip46_address_t *remote_addr, u16 remote_port);

always_inline void
ip4_header_set_len_w_chksum (ip4_header_t * ip4, u16 len)
{
  ip_csum_t sum = ip4->checksum;
  u16 old = ip4->length;
  u16 new = len;

  sum = ip_csum_update (sum, old, new, ip4_header_t, length);
  ip4->checksum = ip_csum_fold (sum);
  ip4->length = new;
}

#endif /* __included_wg_send_h__ */
