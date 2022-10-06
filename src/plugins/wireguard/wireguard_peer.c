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
#include <vnet/tunnel/tunnel_dp.h>

wg_peer_t *wg_peer_pool;

index_t *wg_peer_by_adj_index;

static void
wg_peer_endpoint_reset (wg_peer_endpoint_t * ep)
{
  ip46_address_reset (&ep->addr);
  ep->port = 0;
}

static void
wg_peer_endpoint_init (wg_peer_endpoint_t *ep, const ip46_address_t *addr,
		       u16 port)
{
  ip46_address_copy (&ep->addr, addr);
  ep->port = port;
}

static void
wg_peer_clear (vlib_main_t * vm, wg_peer_t * peer)
{
  index_t perri = peer - wg_peer_pool;
  wg_timers_stop (peer);
  wg_peer_update_flags (perri, WG_PEER_ESTABLISHED, false);
  wg_peer_update_flags (perri, WG_PEER_STATUS_DEAD, true);
  for (int i = 0; i < WG_N_TIMERS; i++)
    {
      peer->timers[i] = ~0;
      peer->timers_dispatched[i] = 0;
    }

  peer->last_sent_handshake = vlib_time_now (vm) - (REKEY_TIMEOUT + 1);

  clib_memset (&peer->cookie_maker, 0, sizeof (peer->cookie_maker));

  wg_peer_endpoint_reset (&peer->src);
  wg_peer_endpoint_reset (&peer->dst);

  adj_index_t *adj_index;
  vec_foreach (adj_index, peer->adj_indices)
    {
      wg_peer_by_adj_index[*adj_index] = INDEX_INVALID;

      if (adj_is_valid (*adj_index))
	adj_midchain_delegate_unstack (*adj_index);
    }
  peer->input_thread_index = ~0;
  peer->output_thread_index = ~0;
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
  peer->handshake_is_sent = false;
  vec_free (peer->rewrite);
  vec_free (peer->allowed_ips);
  vec_free (peer->adj_indices);
}

static void
wg_peer_init (vlib_main_t * vm, wg_peer_t * peer)
{
  peer->api_client_by_client_index = hash_create (0, sizeof (u32));
  peer->api_clients = NULL;
  wg_peer_clear (vm, peer);
}

static void
wg_peer_adj_stack (wg_peer_t *peer, adj_index_t ai)
{
  ip_adjacency_t *adj;
  u32 sw_if_index;
  wg_if_t *wgi;
  fib_protocol_t fib_proto;

  if (!adj_is_valid (ai))
    return;

  adj = adj_get (ai);
  sw_if_index = adj->rewrite_header.sw_if_index;
  u8 is_ip4 = ip46_address_is_ip4 (&peer->src.addr);
  fib_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

  wgi = wg_if_get (wg_if_find_by_sw_if_index (sw_if_index));

  if (!wgi)
    return;

  if (!vnet_sw_interface_is_admin_up (vnet_get_main (), wgi->sw_if_index) ||
      !wg_peer_can_send (peer))
    {
      adj_midchain_delegate_unstack (ai);
    }
  else
    {
      /* *INDENT-OFF* */
      fib_prefix_t dst = {
	.fp_len = is_ip4 ? 32 : 128,
	.fp_proto = fib_proto,
	.fp_addr = peer->dst.addr,
      };
      /* *INDENT-ON* */
      u32 fib_index;

      fib_index = fib_table_find (fib_proto, peer->table_id);

      adj_midchain_delegate_stack (ai, fib_index, &dst);
    }
}

static void
wg_peer_adj_reset_stacking (adj_index_t ai)
{
  adj_midchain_delegate_remove (ai);
}

static void
wg_peer_66_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b,
		  const void *data)
{
  u8 iph_offset = 0;
  ip6_header_t *ip6_out;
  ip6_header_t *ip6_in;

  /* Must set locally originated otherwise we're not allowed to
     fragment the packet later */
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip6_out = vlib_buffer_get_current (b);
  iph_offset = vnet_buffer (b)->ip.save_rewrite_length;
  ip6_in = vlib_buffer_get_current (b) + iph_offset;

  ip6_out->ip_version_traffic_class_and_flow_label =
    ip6_in->ip_version_traffic_class_and_flow_label;
}

static void
wg_peer_46_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b,
		  const void *data)
{
  u8 iph_offset = 0;
  ip6_header_t *ip6_out;
  ip4_header_t *ip4_in;

  /* Must set locally originated otherwise we're not allowed to
     fragment the packet later */
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip6_out = vlib_buffer_get_current (b);
  iph_offset = vnet_buffer (b)->ip.save_rewrite_length;
  ip4_in = vlib_buffer_get_current (b) + iph_offset;

  u32 vtcfl = 0x6 << 28;
  vtcfl |= ip4_in->tos << 20;
  vtcfl |= vnet_buffer (b)->ip.flow_hash & 0x000fffff;

  ip6_out->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (vtcfl);
}

static adj_midchain_fixup_t
wg_peer_get_fixup (wg_peer_t *peer, vnet_link_t lt)
{
  if (!ip46_address_is_ip4 (&peer->dst.addr))
    {
      if (lt == VNET_LINK_IP4)
	return (wg_peer_46_fixup);
      if (lt == VNET_LINK_IP6)
	return (wg_peer_66_fixup);
    }
  return (NULL);
}

static void
wg_peer_disable (vlib_main_t *vm, wg_peer_t *peer)
{
  index_t peeri = peer - wg_peer_pool;

  wg_timers_stop (peer);
  wg_peer_update_flags (peeri, WG_PEER_ESTABLISHED, false);

  for (int i = 0; i < WG_N_TIMERS; i++)
    {
      peer->timers[i] = ~0;
      peer->timers_dispatched[i] = 0;
    }
  peer->timer_handshake_attempts = 0;

  peer->last_sent_handshake = vlib_time_now (vm) - (REKEY_TIMEOUT + 1);
  peer->last_sent_packet = 0;
  peer->last_received_packet = 0;
  peer->session_derived = 0;
  peer->rehandshake_started = 0;

  peer->new_handshake_interval_tick = 0;
  peer->rehandshake_interval_tick = 0;

  peer->timer_need_another_keepalive = false;

  noise_remote_clear (vm, &peer->remote);
}

static void
wg_peer_enable (vlib_main_t *vm, wg_peer_t *peer)
{
  index_t peeri = peer - wg_peer_pool;
  wg_if_t *wg_if;
  u8 public_key[NOISE_PUBLIC_KEY_LEN];

  wg_if = wg_if_get (wg_if_find_by_sw_if_index (peer->wg_sw_if_index));
  clib_memcpy (public_key, peer->remote.r_public, NOISE_PUBLIC_KEY_LEN);

  noise_remote_init (&peer->remote, peeri, public_key, wg_if->local_idx);

  wg_send_handshake (vm, peer, false);
  if (peer->persistent_keepalive_interval != 0)
    {
      wg_send_keepalive (vm, peer);
    }
}

walk_rc_t
wg_peer_if_admin_state_change (index_t peeri, void *data)
{
  wg_peer_t *peer;
  adj_index_t *adj_index;
  vlib_main_t *vm = vlib_get_main ();

  peer = wg_peer_get (peeri);
  vec_foreach (adj_index, peer->adj_indices)
    {
      wg_peer_adj_stack (peer, *adj_index);
    }

  if (vnet_sw_interface_is_admin_up (vnet_get_main (), peer->wg_sw_if_index))
    {
      wg_peer_enable (vm, peer);
    }
  else
    {
      wg_peer_disable (vm, peer);
    }

  return (WALK_CONTINUE);
}

walk_rc_t
wg_peer_if_adj_change (index_t peeri, void *data)
{
  adj_index_t *adj_index = data;
  adj_midchain_fixup_t fixup;
  ip_adjacency_t *adj;
  wg_peer_t *peer;
  fib_prefix_t *allowed_ip;

  adj = adj_get (*adj_index);

  peer = wg_peer_get (peeri);
  vec_foreach (allowed_ip, peer->allowed_ips)
    {
      if (fib_prefix_is_cover_addr_46 (allowed_ip,
				       &adj->sub_type.nbr.next_hop))
	{
	  vec_add1 (peer->adj_indices, *adj_index);

	  vec_validate_init_empty (wg_peer_by_adj_index, *adj_index,
				   INDEX_INVALID);
	  wg_peer_by_adj_index[*adj_index] = peeri;

	  fixup = wg_peer_get_fixup (peer, adj_get_link_type (*adj_index));
	  adj_nbr_midchain_update_rewrite (*adj_index, fixup, NULL,
					   ADJ_FLAG_MIDCHAIN_IP_STACK,
					   vec_dup (peer->rewrite));

	  wg_peer_adj_stack (peer, *adj_index);
	  return (WALK_STOP);
	}
    }

  return (WALK_CONTINUE);
}

adj_walk_rc_t
wg_peer_adj_walk (adj_index_t ai, void *data)
{
  return wg_peer_if_adj_change ((*(index_t *) (data)), &ai) == WALK_CONTINUE ?
	   ADJ_WALK_RC_CONTINUE :
	   ADJ_WALK_RC_STOP;
}

walk_rc_t
wg_peer_if_delete (index_t peeri, void *data)
{
  wg_peer_remove (peeri);
  return (WALK_CONTINUE);
}

static int
wg_peer_fill (vlib_main_t *vm, wg_peer_t *peer, u32 table_id,
	      const ip46_address_t *dst, u16 port,
	      u16 persistent_keepalive_interval,
	      const fib_prefix_t *allowed_ips, u32 wg_sw_if_index)
{
  index_t perri = peer - wg_peer_pool;
  wg_peer_endpoint_init (&peer->dst, dst, port);

  peer->table_id = table_id;
  peer->wg_sw_if_index = wg_sw_if_index;
  peer->timer_wheel = &wg_main.timer_wheel;
  peer->persistent_keepalive_interval = persistent_keepalive_interval;
  peer->last_sent_handshake = vlib_time_now (vm) - (REKEY_TIMEOUT + 1);
  wg_peer_update_flags (perri, WG_PEER_STATUS_DEAD, false);

  const wg_if_t *wgi = wg_if_get (wg_if_find_by_sw_if_index (wg_sw_if_index));

  if (NULL == wgi)
    return (VNET_API_ERROR_INVALID_INTERFACE);

  ip_address_to_46 (&wgi->src_ip, &peer->src.addr);
  peer->src.port = wgi->port;

  u8 is_ip4 = ip46_address_is_ip4 (&peer->dst.addr);
  peer->rewrite = wg_build_rewrite (&peer->src.addr, peer->src.port,
				    &peer->dst.addr, peer->dst.port, is_ip4);

  u32 ii;
  vec_validate (peer->allowed_ips, vec_len (allowed_ips) - 1);
  vec_foreach_index (ii, allowed_ips)
  {
    peer->allowed_ips[ii] = allowed_ips[ii];
  }

  fib_protocol_t proto;
  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    adj_nbr_walk (wg_sw_if_index, proto, wg_peer_adj_walk, &perri);
  }
  return (0);
}

void
wg_peer_update_flags (index_t peeri, wg_peer_flags flag, bool add_del)
{
  wg_peer_t *peer = wg_peer_get (peeri);
  if ((add_del && (peer->flags & flag)) || (!add_del && !(peer->flags & flag)))
    {
      return;
    }

  peer->flags ^= flag;
  wg_api_peer_event (peeri, peer->flags);
}

void
wg_peer_update_endpoint (index_t peeri, const ip46_address_t *addr, u16 port)
{
  wg_peer_t *peer = wg_peer_get (peeri);

  if (ip46_address_is_equal (&peer->dst.addr, addr) && peer->dst.port == port)
    return;

  wg_peer_endpoint_init (&peer->dst, addr, port);

  u8 is_ip4 = ip46_address_is_ip4 (&peer->dst.addr);
  vec_free (peer->rewrite);
  peer->rewrite = wg_build_rewrite (&peer->src.addr, peer->src.port,
				    &peer->dst.addr, peer->dst.port, is_ip4);

  adj_index_t *adj_index;
  vec_foreach (adj_index, peer->adj_indices)
    {
      if (adj_is_valid (*adj_index))
	{
	  adj_midchain_fixup_t fixup =
	    wg_peer_get_fixup (peer, adj_get_link_type (*adj_index));
	  adj_nbr_midchain_update_rewrite (*adj_index, fixup, NULL,
					   ADJ_FLAG_MIDCHAIN_IP_STACK,
					   vec_dup (peer->rewrite));

	  wg_peer_adj_reset_stacking (*adj_index);
	  wg_peer_adj_stack (peer, *adj_index);
	}
    }
}

typedef struct wg_peer_upd_ep_args_t_
{
  index_t peeri;
  ip46_address_t addr;
  u16 port;
} wg_peer_upd_ep_args_t;

static void
wg_peer_update_endpoint_thread_fn (wg_peer_upd_ep_args_t *args)
{
  wg_peer_update_endpoint (args->peeri, &args->addr, args->port);
}

void
wg_peer_update_endpoint_from_mt (index_t peeri, const ip46_address_t *addr,
				 u16 port)
{
  wg_peer_upd_ep_args_t args = {
    .peeri = peeri,
    .port = port,
  };

  ip46_address_copy (&args.addr, addr);
  vlib_rpc_call_main_thread (wg_peer_update_endpoint_thread_fn, (u8 *) &args,
			     sizeof (args));
}

int
wg_peer_add (u32 tun_sw_if_index, const u8 public_key[NOISE_PUBLIC_KEY_LEN],
	     u32 table_id, const ip46_address_t *endpoint,
	     const fib_prefix_t *allowed_ips, u16 port,
	     u16 persistent_keepalive, u32 *peer_index)
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

  pool_get_zero (wg_peer_pool, peer);

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

  if (vnet_sw_interface_is_admin_up (vnet_get_main (), tun_sw_if_index))
    {
      wg_send_handshake (vm, peer, false);
      if (peer->persistent_keepalive_interval != 0)
	{
	  wg_send_keepalive (vm, peer);
	}
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

  s = format (s, "%U:%d", format_ip46_address, &ep->addr, IP46_TYPE_ANY,
	      ep->port);

  return (s);
}

u8 *
format_wg_peer (u8 * s, va_list * va)
{
  index_t peeri = va_arg (*va, index_t);
  fib_prefix_t *allowed_ip;
  adj_index_t *adj_index;
  u8 key[NOISE_KEY_LEN_BASE64];
  wg_peer_t *peer;

  peer = wg_peer_get (peeri);
  key_to_base64 (peer->remote.r_public, NOISE_PUBLIC_KEY_LEN, key);

  s = format (
    s,
    "[%d] endpoint:[%U->%U] %U keep-alive:%d flags: %d, api-clients count: %d",
    peeri, format_wg_peer_endpoint, &peer->src, format_wg_peer_endpoint,
    &peer->dst, format_vnet_sw_if_index_name, vnet_get_main (),
    peer->wg_sw_if_index, peer->persistent_keepalive_interval, peer->flags,
    pool_elts (peer->api_clients));
  s = format (s, "\n  adj:");
  vec_foreach (adj_index, peer->adj_indices)
    {
      s = format (s, " %d", *adj_index);
    }
  s = format (s, "\n  key:%=s %U", key, format_hex_bytes,
	      peer->remote.r_public, NOISE_PUBLIC_KEY_LEN);
  s = format (s, "\n  allowed-ips:");
  vec_foreach (allowed_ip, peer->allowed_ips)
  {
    s = format (s, " %U", format_fib_prefix, allowed_ip);
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
