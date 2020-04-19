/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#include <wg/wg_peer.h>

void wg_send_handshake (vlib_main_t * vm, wg_peer_t * peer, bool is_retry);
void wg_send_keepalive (vlib_main_t * vm, wg_peer_t * peer);

void wg_send_handshake_response (vlib_main_t * vm, wg_peer_t * peer);
bool wg_send_keep_key_fresh (vlib_main_t * vm, wg_peer_t * peer);

void wg_encrypt_message (message_data_t * packet,
			 const u8 * inp, size_t inp_len,
			 noise_keypair_t * keypair, u64 nonce);
#endif // __included_wg_send_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
