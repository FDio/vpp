/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __included_wg_send_h__
#define __included_wg_send_h__

#include <wireguard/wireguard_peer.h>

bool wg_send_keepalive (vlib_main_t * vm, wg_peer_t * peer);
bool wg_send_handshake (vlib_main_t * vm, wg_peer_t * peer, bool is_retry);
void wg_send_handshake_from_mt (u32 peer_index, bool is_retry);
bool wg_send_handshake_response (vlib_main_t * vm, wg_peer_t * peer);

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
