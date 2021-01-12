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

#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_table.h>
#include <wireguard/wireguard_peer.h>
#include <wireguard/wireguard_if.h>
#include <wireguard/wireguard_messages.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_send.h>
#include <wireguard/wireguard.h>

static fib_source_t wg_fib_source;
wg_peer_t *wg_peer_pool;

index_t *wg_peer_by_adj_index;

static void
wg_peer_endpoint_reset (wg_peer_endpoint_t * ep)
{
  ip46_address_reset (&ep->addr);
  ep->port = 0;
}

static void
wg_peer_endpoint_init (wg_peer_endpoint_t * ep,
		       const ip46_address_t * addr, u16 port)
{
  ip46_address_copy (&ep->addr, addr);
  ep->port = port;
}

static void
wg_peer_fib_flush (wg_peer_t * peer)
{
  wg_peer_allowed_ip_t *allowed_ip;

  vec_foreach (allowed_ip, peer->allowed_ips)
  {
    fib_table_entry_delete_index (allowed_ip->fib_entry_index, wg_fib_source);
    allowed_ip->fib_entry_index = FIB_NODE_INDEX_INVALID;
  }
}

static void
wg_peer_fib_populate (wg_peer_t * peer, u32 fib_index)
{
  wg_peer_allowed_ip_t *allowed_ip;

  vec_foreach (allowed_ip, peer->allowed_ips)
  {
    allowed_ip->fib_entry_index =
      fib_table_entry_path_add (fib_index,
				&allowed_ip->prefix,
				wg_fib_source,
				FIB_ENTRY_FLAG_NONE,
				fib_proto_to_dpo (allowed_ip->
						  prefix.fp_proto),
				&peer->dst.addr, peer->wg_sw_if_index, ~0, 1,
				NULL, FIB_ROUTE_PATH_FLAG_NONE);
  }
}

static void
wg_peer_clear (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_timers_stop (peer);
  for (int i = 0; i < WG_N_TIMERS; i++)
    {
      peer->timers[i] = ~0;
      peer->timers_dispatched[i] = 0;
    }

  peer->last_sent_handshake = vlib_time_now (vm) - (REKEY_TIMEOUT + 1);

  clib_memset (&peer->cookie_maker, 0, sizeof (peer->cookie_maker));

  wg_peer_endpoint_reset (&peer->src);
  wg_peer_endpoint_reset (&peer->dst);

  if (INDEX_INVALID != peer->adj_index)
    {
      adj_unlock (peer->adj_index);
      wg_peer_by_adj_index[peer->adj_index] = INDEX_INVALID;
    }
  wg_peer_fib_flush (peer);

  peer->input_thread_index = ~0;
  peer->output_thread_index = ~0;
  peer->adj_index = INDEX_INVALID;
  peer->timer_wheel = 0;
  peer->persistent_keepalive_interval = 0;
  peer->timer_handshake_attempts = 0;
  peer->last_sent_packet = 0;
  peer->last_received_packet = 0;
  peer->session_derived = 0;
  peer->rehandshake_started = 0;
  peer->new_handshake_interval_tick = 0;
  peer->rehandshake_interval_tick = 0;
  peer->timer_need_another_keepalive = false;
  peer->is_dead = true;
  vec_free (peer->allowed_ips);
}

static void
wg_peer_init (vlib_main_t * vm, wg_peer_t * peer)
{
  peer->adj_index = INDEX_INVALID;
  wg_peer_clear (vm, peer);
}

static u8 *
wg_peer_build_rewrite (const wg_peer_t * peer)
{
  // v4 only for now
  ip4_udp_header_t *hdr;
  u8 *rewrite = NULL;

  vec_validate (rewrite, sizeof (*hdr) - 1);
  hdr = (ip4_udp_header_t *) rewrite;

  hdr->ip4.ip_version_and_header_length = 0x45;
  hdr->ip4.ttl = 64;
  hdr->ip4.src_address = peer->src.addr.ip4;
  hdr->ip4.dst_address = peer->dst.addr.ip4;
  hdr->ip4.protocol = IP_PROTOCOL_UDP;
  hdr->ip4.checksum = ip4_header_checksum (&hdr->ip4);

  hdr->udp.src_port = clib_host_to_net_u16 (peer->src.port);
  hdr->udp.dst_port = clib_host_to_net_u16 (peer->dst.port);
  hdr->udp.checksum = 0;

  return (rewrite);
}

static void
wg_peer_adj_stack (wg_peer_t * peer)
{
  ip_adjacency_t *adj;
  u32 sw_if_index;
  wg_if_t *wgi;

  adj = adj_get (peer->adj_index);
  sw_if_index = adj->rewrite_header.sw_if_index;

  wgi = wg_if_get (wg_if_find_by_sw_if_index (sw_if_index));

  if (!wgi)
    return;

  if (!vnet_sw_interface_is_admin_up (vnet_get_main (), wgi->sw_if_index))
    {
      adj_midchain_delegate_unstack (peer->adj_index);
    }
  else
    {
      /* *INDENT-OFF* */
      fib_prefix_t dst = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = peer->dst.addr,
      };
      /* *INDENT-ON* */
      u32 fib_index;

      fib_index = fib_table_find (FIB_PROTOCOL_IP4, peer->table_id);

      adj_midchain_delegate_stack (peer->adj_index, fib_index, &dst);
    }
}

walk_rc_t
wg_peer_if_admin_state_change (wg_if_t * wgi, index_t peeri, void *data)
{
  wg_peer_adj_stack (wg_peer_get (peeri));

  return (WALK_CONTINUE);
}

walk_rc_t
wg_peer_if_table_change (wg_if_t * wgi, index_t peeri, void *data)
{
  wg_peer_table_bind_ctx_t *ctx = data;
  wg_peer_t *peer;

  peer = wg_peer_get (peeri);

  wg_peer_fib_flush (peer);
  wg_peer_fib_populate (peer, ctx->new_fib_index);

  return (WALK_CONTINUE);
}

static int
wg_peer_fill (vlib_main_t * vm, wg_peer_t * peer,
	      u32 table_id,
	      const ip46_address_t * dst,
	      u16 port,
	      u16 persistent_keepalive_interval,
	      const fib_prefix_t * allowed_ips, u32 wg_sw_if_index)
{
  wg_peer_endpoint_init (&peer->dst, dst, port);

  peer->table_id = table_id;
  peer->wg_sw_if_index = wg_sw_if_index;
  peer->timer_wheel = &wg_main.timer_wheel;
  peer->persistent_keepalive_interval = persistent_keepalive_interval;
  peer->last_sent_handshake = vlib_time_now (vm) - (REKEY_TIMEOUT + 1);
  peer->is_dead = false;

  const wg_if_t *wgi = wg_if_get (wg_if_find_by_sw_if_index (wg_sw_if_index));

  if (NULL == wgi)
    return (VNET_API_ERROR_INVALID_INTERFACE);

  ip_address_to_46 (&wgi->src_ip, &peer->src.addr);
  peer->src.port = wgi->port;

  /*
   * and an adjacency for the endpoint address in the overlay
   * on the wg interface
   */
  peer->rewrite = wg_peer_build_rewrite (peer);

  peer->adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4,
					 VNET_LINK_IP4,
					 &peer->dst.addr, wgi->sw_if_index);

  vec_validate_init_empty (wg_peer_by_adj_index,
			   peer->adj_index, INDEX_INVALID);
  wg_peer_by_adj_index[peer->adj_index] = peer - wg_peer_pool;

  adj_nbr_midchain_update_rewrite (peer->adj_index,
				   NULL,
				   NULL,
				   ADJ_FLAG_MIDCHAIN_IP_STACK,
				   vec_dup (peer->rewrite));
  wg_peer_adj_stack (peer);

  /*
   * add a route in the overlay to each of the allowed-ips
   */
  u32 ii;

  vec_validate (peer->allowed_ips, vec_len (allowed_ips) - 1);

  vec_foreach_index (ii, allowed_ips)
  {
    peer->allowed_ips[ii].prefix = allowed_ips[ii];
  }

  wg_peer_fib_populate (peer,
			fib_table_get_index_for_sw_if_index
			(FIB_PROTOCOL_IP4, peer->wg_sw_if_index));

  return (0);
}

int
wg_peer_add (u32 tun_sw_if_index,
	     const u8 public_key[NOISE_PUBLIC_KEY_LEN],
	     u32 table_id,
	     const ip46_address_t * endpoint,
	     const fib_prefix_t * allowed_ips,
	     u16 port, u16 persistent_keepalive, u32 * peer_index)
{
  wg_if_t *wg_if;
  wg_peer_t *peer;
  int rv;

  vlib_main_t *vm = vlib_get_main ();

  if (tun_sw_if_index == ~0)
    return (VNET_API_ERROR_INVALID_SW_IF_INDEX);

  wg_if = wg_if_get (wg_if_find_by_sw_if_index (tun_sw_if_index));
  if (!wg_if)
    return (VNET_API_ERROR_INVALID_SW_IF_INDEX);

  /* *INDENT-OFF* */
  pool_foreach (peer, wg_peer_pool)
   {
    if (!memcmp (peer->remote.r_public, public_key, NOISE_PUBLIC_KEY_LEN))
    {
      return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);
    }
  }
  /* *INDENT-ON* */

  if (pool_elts (wg_peer_pool) > MAX_PEERS)
    return (VNET_API_ERROR_LIMIT_EXCEEDED);

  pool_get (wg_peer_pool, peer);

  wg_peer_init (vm, peer);

  rv = wg_peer_fill (vm, peer, table_id, endpoint, (u16) port,
		     persistent_keepalive, allowed_ips, tun_sw_if_index);

  if (rv)
    {
      wg_peer_clear (vm, peer);
      pool_put (wg_peer_pool, peer);
      return (rv);
    }

  noise_remote_init (&peer->remote, peer - wg_peer_pool, public_key,
		     wg_if->local_idx);
  cookie_maker_init (&peer->cookie_maker, public_key);

  if (peer->persistent_keepalive_interval != 0)
    {
      wg_send_keepalive (vm, peer);
    }

  *peer_index = peer - wg_peer_pool;
  wg_if_peer_add (wg_if, *peer_index);

  return (0);
}

int
wg_peer_remove (index_t peeri)
{
  wg_main_t *wmp = &wg_main;
  wg_peer_t *peer = NULL;
  wg_if_t *wgi;

  if (pool_is_free_index (wg_peer_pool, peeri))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  peer = pool_elt_at_index (wg_peer_pool, peeri);

  wgi = wg_if_get (wg_if_find_by_sw_if_index (peer->wg_sw_if_index));
  wg_if_peer_remove (wgi, peeri);

  vnet_feature_enable_disable ("ip4-output", "wg-output-tun",
			       peer->wg_sw_if_index, 0, 0, 0);

  noise_remote_clear (wmp->vlib_main, &peer->remote);
  wg_peer_clear (wmp->vlib_main, peer);
  pool_put (wg_peer_pool, peer);

  return (0);
}

index_t
wg_peer_walk (wg_peer_walk_cb_t fn, void *data)
{
  index_t peeri;

  /* *INDENT-OFF* */
  pool_foreach_index (peeri, wg_peer_pool)
  {
    if (WALK_STOP == fn(peeri, data))
      return peeri;
  }
  /* *INDENT-ON* */
  return INDEX_INVALID;
}

static u8 *
format_wg_peer_endpoint (u8 * s, va_list * args)
{
  wg_peer_endpoint_t *ep = va_arg (*args, wg_peer_endpoint_t *);

  s = format (s, "%U:%d",
	      format_ip46_address, &ep->addr, IP46_TYPE_ANY, ep->port);

  return (s);
}

u8 *
format_wg_peer (u8 * s, va_list * va)
{
  index_t peeri = va_arg (*va, index_t);
  wg_peer_allowed_ip_t *allowed_ip;
  u8 key[NOISE_KEY_LEN_BASE64];
  wg_peer_t *peer;

  peer = wg_peer_get (peeri);
  key_to_base64 (peer->remote.r_public, NOISE_PUBLIC_KEY_LEN, key);

  s = format (s, "[%d] endpoint:[%U->%U] %U keep-alive:%d adj:%d",
	      peeri,
	      format_wg_peer_endpoint, &peer->src,
	      format_wg_peer_endpoint, &peer->dst,
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      peer->wg_sw_if_index,
	      peer->persistent_keepalive_interval, peer->adj_index);
  s = format (s, "\n  key:%=s %U",
	      key, format_hex_bytes, peer->remote.r_public,
	      NOISE_PUBLIC_KEY_LEN);
  s = format (s, "\n  allowed-ips:");
  vec_foreach (allowed_ip, peer->allowed_ips)
  {
    s = format (s, " %U", format_fib_prefix, &allowed_ip->prefix);
  }

  return s;
}

static clib_error_t *
wg_peer_module_init (vlib_main_t * vm)
{
  /*
   * use a priority better than interface source, so that
   * if the same subnet is added to the wg interface and is
   * used as an allowed IP, then the wireguard soueced prefix
   * wins and traffic is routed to the endpoint rather than dropped
   */
  wg_fib_source = fib_source_allocate ("wireguard", 0x2, FIB_SOURCE_BH_API);

  return (NULL);
}

VLIB_INIT_FUNCTION (wg_peer_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
