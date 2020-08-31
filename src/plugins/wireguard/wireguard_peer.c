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

#include <vnet/fib/ip4_fib.h>
#include <vnet/ipip/ipip.h>
#include <wireguard/wireguard_peer.h>
#include <wireguard/wireguard_messages.h>

void
wg_peer_init (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_timers_init (peer, vlib_time_now (vm));
  wg_peer_clear (vm, peer);
}

void
wg_peer_clear (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_timers_stop (peer);
  noise_remote_clear (vm, &peer->remote);
  peer->last_sent_handshake = vlib_time_now (vm) - (REKEY_TIMEOUT + 1);

  clib_memset (&peer->cookie_maker, 0, sizeof (peer->cookie_maker));
  peer->allowed_ip.as_u32 = 0;
  peer->ip4_address.as_u32 = 0;

  peer->persistent_keepalive_interval = 0;
  peer->port = 0;
  peer->timer_handshake_attempts = 0;
  peer->timer_need_another_keepalive = false;
  peer->is_dead = true;
}

int
wg_peer_fill (vlib_main_t * vm, wg_peer_t * peer, ip4_address_t ip4, u16 port,
	      u16 persistent_keepalive_interval, ip4_address_t allowed_ip,
	      u32 tun_sw_if_index)
{
  peer->sw_if_index = ~0;
  peer->ip4_address.as_u32 = ip4.as_u32;
  peer->port = port;
  peer->allowed_ip.as_u32 = allowed_ip.as_u32;
  peer->persistent_keepalive_interval = persistent_keepalive_interval;
  peer->tun_sw_if_index = tun_sw_if_index;
  peer->last_sent_handshake = vlib_time_now (vm) - (REKEY_TIMEOUT + 1);

  ipip_tunnel_t *ipip = ipip_tunnel_db_find_by_sw_if_index (tun_sw_if_index);

  if (NULL == ipip)
    return (VNET_API_ERROR_INVALID_INTERFACE);

  fib_node_index_t fib_entry_index =
    ip4_fib_table_lookup (ip4_fib_get (ipip->fib_index),
			  &peer->ip4_address,
			  32);
  if (fib_entry_index != FIB_NODE_INDEX_INVALID)
    {
      peer->sw_if_index = fib_entry_get_resolving_interface (fib_entry_index);
    }
  peer->is_dead = false;

  return (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
