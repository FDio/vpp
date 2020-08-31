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
#include <wireguard/wireguard_peer.h>
#include <wireguard/wireguard_itf.h>
#include <wireguard/wireguard_messages.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_send.h>
#include <wireguard/wireguard.h>

wg_peer_t *
wg_peer_get (index_t peeri)
{
  return (pool_elt_at_index (wg_main.peers, peeri));
}

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

  ip46_address_reset (&peer->src_address);
  ip46_address_reset (&peer->dst_address);

  peer->persistent_keepalive_interval = 0;
  peer->port = 0;
  peer->timer_handshake_attempts = 0;
  peer->timer_need_another_keepalive = false;
  peer->is_dead = true;
  vec_free (peer->allowed_ips);
}

static int
wg_peer_fill (vlib_main_t * vm, wg_peer_t * peer,
	      u32 table_id,
	      const ip46_address_t * dst,
	      u16 port,
	      u16 persistent_keepalive_interval,
	      const fib_prefix_t * allowed_ips, u32 wg_sw_if_index)
{
  ip46_address_copy (&peer->dst_address, dst);
  peer->port = port;
  peer->table_id = table_id;
  peer->persistent_keepalive_interval = persistent_keepalive_interval;
  peer->tun_sw_if_index = wg_sw_if_index;
  peer->last_sent_handshake = vlib_time_now (vm) - (REKEY_TIMEOUT + 1);
  peer->is_dead = false;

  const wg_itf_t *wgi = wg_itf_find_by_sw_if_index (wg_sw_if_index);

  if (NULL == wgi)
    return (VNET_API_ERROR_INVALID_INTERFACE);

  ip_address_to_46 (&wgi->src_ip, &peer->src_address);

  u32 ii;

  vec_validate (peer->allowed_ips, vec_len (allowed_ips) - 1);

  vec_foreach_index (ii, allowed_ips)
  {
    peer->allowed_ips[ii].prefix = allowed_ips[ii];

    // ADD ROUTE
  }

  return (0);
}

int
wg_peer_add (u32 tun_sw_if_index,
	     const u8 public_key_64[NOISE_KEY_LEN_BASE64],
	     u32 table_id,
	     const ip46_address_t * endpoint,
	     const fib_prefix_t * allowed_ips,
	     u16 port, u16 persistent_keepalive, u32 * peer_index)
{
  wg_itf_t *wg_itf;
  wg_peer_t *peer;
  int rv;

  vlib_main_t *vm = vlib_get_main ();

  if (tun_sw_if_index == ~0)
    return (VNET_API_ERROR_INVALID_SW_IF_INDEX);

  wg_itf = wg_itf_find_by_sw_if_index (tun_sw_if_index);
  if (!wg_itf)
    return (VNET_API_ERROR_INVALID_SW_IF_INDEX);

  u8 public_key[NOISE_PUBLIC_KEY_LEN];
  if (!key_from_base64 (public_key_64, NOISE_KEY_LEN_BASE64, public_key))
    return (VNET_API_ERROR_KEY_LENGTH);

  /* *INDENT-OFF* */
  pool_foreach (peer, wg_main.peers,
  ({
    if (!memcmp (peer->remote.r_public, public_key, NOISE_PUBLIC_KEY_LEN))
    {
      return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);
    }
  }));
  /* *INDENT-ON* */

  if (pool_elts (wg_main.peers) > MAX_PEERS)
    return (VNET_API_ERROR_LIMIT_EXCEEDED);

  pool_get (wg_main.peers, peer);

  wg_peer_init (vm, peer);

  rv = wg_peer_fill (vm, peer, table_id, endpoint, (u16) port,
		     persistent_keepalive, allowed_ips, tun_sw_if_index);

  if (rv)
    {
      wg_peer_clear (vm, peer);
      pool_put (wg_main.peers, peer);
      return (rv);
    }

  noise_remote_init (&peer->remote, peer - wg_main.peers, public_key,
		     &wg_itf->local);
  cookie_maker_init (&peer->cookie_maker, public_key);

  vnet_feature_enable_disable ("ip4-output", "wg-output-tun",
			       tun_sw_if_index, 1, 0, 0);

  if (peer->persistent_keepalive_interval != 0)
    {
      wg_send_keepalive (vm, peer);
    }

  *peer_index = peer - wg_main.peers;

  return (0);
}

int
wg_peer_remove (index_t peeri)
{
  wg_main_t *wmp = &wg_main;
  wg_peer_t *peer = NULL;

  if (pool_is_free_index (wmp->peers, peeri))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  peer = pool_elt_at_index (wmp->peers, peeri);

  vnet_feature_enable_disable ("ip4-output", "wg-output-tun",
			       peer->tun_sw_if_index, 0, 0, 0);
  wg_peer_clear (wmp->vlib_main, peer);
  pool_put (wmp->peers, peer);

  return (0);
}

void
wg_peer_walk (wg_peer_walk_cb_t fn, void *data)
{
  index_t peeri;

  /* *INDENT-OFF* */
  pool_foreach_index(peeri, wg_main.peers,
  {
    if (WALK_STOP == fn(peeri, data))
      break;
  });
  /* *INDENT-ON* */
}

u8 *
format_wg_peer (u8 * s, va_list * va)
{
  index_t peeri = va_arg (*va, index_t);
  u8 key_64[NOISE_KEY_LEN_BASE64];
  wg_peer_allowed_ip_t *allowed_ip;
  wg_peer_t *peer;

  peer = wg_peer_get (peeri);

  key_to_base64 (peer->remote.r_public, NOISE_PUBLIC_KEY_LEN, key_64);
  s = format (s, "[%d] key:%=45s endpoint:[%U->%U, %u] %U keep-alive:%d",
	      peeri,
	      key_64,
	      format_ip46_address, &peer->src_address, IP46_TYPE_ANY,
	      format_ip46_address, &peer->dst_address, IP46_TYPE_ANY,
	      peer->port,
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      peer->tun_sw_if_index, peer->persistent_keepalive_interval);

  s = format (s, "\n  allowed-ips:");
  vec_foreach (allowed_ip, peer->allowed_ips)
  {
    s = format (s, " %U", format_fib_prefix, &allowed_ip->prefix);
  }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
