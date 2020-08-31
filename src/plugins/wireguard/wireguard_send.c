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

#include <vnet/vnet.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/pg/pg.h>
#include <vnet/udp/udp.h>
#include <vppinfra/error.h>
#include <wireguard/wireguard.h>
#include <wireguard/wireguard_send.h>

#define foreach_wg_send_error    \
_(NONE)		    \
_(NO_INTERFACE)     \
_(NO_TABLE)         \
_(NO_BUFFERS)       \

typedef enum
{
#define _(sym) WG_SEND_ERROR_##sym,
  foreach_wg_send_error
#undef _
    WG_SEND_N_ERROR,
} wg_send_error_t;


// This file has pieces of code for a future IP6 implementation.
static u32
ip46_fib_index_from_table_id (u32 table_id, int is_ip6)
{
  u32 fib_index = is_ip6 ?
    ip6_fib_index_from_table_id (table_id) :
    ip4_fib_index_from_table_id (table_id);
  return fib_index;
}

static fib_node_index_t
ip46_fib_table_lookup_host (u32 fib_index, ip46_address_t * pa46, int is_ip6)
{
  fib_node_index_t fib_entry_index = is_ip6 ?
    ip6_fib_table_lookup (fib_index, &pa46->ip6, 128) :
    ip4_fib_table_lookup (ip4_fib_get (fib_index), &pa46->ip4, 32);
  return fib_entry_index;
}

static u32
ip46_get_resolving_interface (u32 fib_index, ip46_address_t * pa46,
			      int is_ip6)
{
  u32 sw_if_index = ~0;
  if (~0 != fib_index)
    {
      fib_node_index_t fib_entry_index;
      fib_entry_index = ip46_fib_table_lookup_host (fib_index, pa46, is_ip6);
      sw_if_index = fib_entry_get_resolving_interface (fib_entry_index);
    }
  return sw_if_index;
}

static int
ip46_set_src_address (u32 sw_if_index, vlib_buffer_t * b0, int is_ip6)
{
  int res;
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      res = ip6_src_address_for_packet (sw_if_index,
					&ip6->dst_address, &ip6->src_address);
    }
  else
    {
      ip4_main_t *im = &ip4_main;
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      res = ip4_src_address_for_packet (&im->lookup_main,
					sw_if_index, &ip4->src_address);
      /* IP4 and IP6 paths have the inverse logic. Harmonize. */
      res = !res;
    }
  return res;
}

static int
ip46_fill_l3_header (ip46_address_t * ip46_dst, u32 sw_if_index,
		     vlib_buffer_t * b0, u32 len, u16 port_src, u16 port_dst,
		     int is_ip6)
{
//TODO IP6
  if (!is_ip6)
    {

      ip4_header_t *ip4;
      udp_header_t *udp0;

      vlib_buffer_advance (b0, -sizeof (udp_header_t));
      udp0 = vlib_buffer_get_current (b0);
      vlib_buffer_advance (b0, -sizeof (ip4_header_t));
      ip4 = vlib_buffer_get_current (b0);

      /* Fill in ip4 header fields */
      ip4->ip_version_and_header_length = 0x45;
      ip4->tos = 0;
      ip4->fragment_id = 0;
      ip4->flags_and_fragment_offset = 0;
      ip4->ttl = 0xff;
      ip4->protocol = IP_PROTOCOL_UDP;

      ip46_set_src_address (sw_if_index, b0, false);
      ip4->dst_address.as_u32 = ip46_dst->ip4.as_u32;

      udp0->src_port = clib_host_to_net_u16 (port_src);
      udp0->dst_port = clib_host_to_net_u16 (port_dst);

      udp0->length = clib_host_to_net_u16 (len + sizeof (udp_header_t));
      udp0->checksum = 0;
      b0->current_length =
	len + sizeof (ip4_header_t) + sizeof (udp_header_t);
      ip4->length = clib_host_to_net_u16 (b0->current_length);
      ip4->checksum = ip4_header_checksum (ip4);
    }
  return (sizeof (ip4_header_t) + sizeof (udp_header_t));
}

static int
ip46_enqueue_packet (vlib_main_t * vm, u32 bi0, int is_ip6)
{
  vlib_frame_t *f = 0;
  u32 lookup_node_index =
    is_ip6 ? ip6_lookup_node.index : ip4_lookup_node.index;

  f = vlib_get_frame_to_node (vm, lookup_node_index);
  /* f can not be NULL here - frame allocation failure causes panic */

  u32 *to_next = vlib_frame_vector_args (f);
  f->n_vectors = 1;
  to_next[0] = bi0;

  vlib_put_frame_to_node (vm, lookup_node_index, f);

  return f->n_vectors;
}

static wg_send_error_t
wg_create_buffer (vlib_main_t * vm, const u8 * packet, u32 packet_len,
		  u32 * bi, wg_peer_t * peer, u16 src_port)
{
  u32 sw_if_index = ~0;
  u32 fib_index = ~0;
  u32 table_id = 0;

  u32 n_buf0 = 0;
  vlib_buffer_t *b0;
  ip46_address_t ip46;

  ip46_address_set_ip4 (&ip46, &peer->ip4_address);

  if (~0 == sw_if_index)
    {
      fib_index = ip46_fib_index_from_table_id (table_id, false);
      sw_if_index = ip46_get_resolving_interface (fib_index, &ip46, false);
    }
  if (~0 == fib_index)
    {
      return WG_SEND_ERROR_NO_TABLE;
    }
  if (~0 == sw_if_index)
    {
      return WG_SEND_ERROR_NO_INTERFACE;
    }

  n_buf0 = vlib_buffer_alloc (vm, bi, 1);
  if (!n_buf0)
    {
      return WG_SEND_ERROR_NO_BUFFERS;
    }

  b0 = vlib_get_buffer (vm, *bi);

  u8 *payload = vlib_buffer_get_current (b0);
  clib_memcpy (payload, packet, packet_len);

  u16 port_src = src_port;
  u16 port_dst = peer->port;

  ip46_fill_l3_header (&ip46, sw_if_index, b0, packet_len, port_src, port_dst,
		       false);
  return true;
}

void
wg_send_handshake (vlib_main_t * vm, wg_peer_t * peer, bool is_retry)
{
  wg_main_t *wmp = &wg_main;
  message_handshake_initiation_t packet;

  if (!is_retry)
    peer->timer_handshake_attempts = 0;

  if (!wg_birthdate_has_expired (peer->last_sent_handshake,
				 REKEY_TIMEOUT) || peer->is_dead)
    {
      return;
    }

  if (noise_create_initiation (wmp->vlib_main,
			       &peer->remote,
			       &packet.sender_index,
			       packet.unencrypted_ephemeral,
			       packet.encrypted_static,
			       packet.encrypted_timestamp))
    {
      f64 now = vlib_time_now (vm);
      packet.header.type = MESSAGE_HANDSHAKE_INITIATION;
      cookie_maker_mac (&peer->cookie_maker, &packet.macs, &packet,
			sizeof (packet));
      wg_timers_any_authenticated_packet_traversal (peer);
      wg_timers_any_authenticated_packet_sent (peer);
      peer->last_sent_handshake = now;
      wg_timers_handshake_initiated (peer);
    }
  else
    return;

  u32 bi0 = 0;
  if (wg_create_buffer
      (vm, (u8 *) & packet, sizeof (packet), &bi0, peer,
       wmp->port_src) != WG_SEND_ERROR_NONE)
    return;
  ip46_enqueue_packet (vm, bi0, false);
}

void
wg_send_keepalive (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_main_t *wmp = &wg_main;
  u32 size_of_packet = message_data_len (0);
  message_data_t *packet = clib_mem_alloc (size_of_packet);
  u32 bi0 = 0;
  enum noise_state_crypt state;

  if (!peer->remote.r_current)
    {
      wg_send_handshake (vm, peer, false);
      goto out;
    }

  state =
    noise_remote_encrypt (wmp->vlib_main,
			  &peer->remote,
			  &packet->receiver_index,
			  &packet->counter, NULL, 0, packet->encrypted_data);
  switch (state)
    {
    case SC_OK:
      break;
    case SC_KEEP_KEY_FRESH:
      wg_send_handshake (vm, peer, false);
      break;
    case SC_FAILED:
      goto out;
    default:
      break;
    }
  packet->header.type = MESSAGE_DATA;

  if (wg_create_buffer
      (vm, (u8 *) packet, size_of_packet, &bi0, peer,
       wmp->port_src) != WG_SEND_ERROR_NONE)
    {
      goto out;
    }
  ip46_enqueue_packet (vm, bi0, false);
  wg_timers_any_authenticated_packet_traversal (peer);
  wg_timers_any_authenticated_packet_sent (peer);

out:
  clib_mem_free (packet);
}

void
wg_send_handshake_response (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_main_t *wmp = &wg_main;
  message_handshake_response_t packet;

  peer->last_sent_handshake = vlib_time_now (vm);

  if (noise_create_response (wmp->vlib_main,
			     &peer->remote,
			     &packet.sender_index,
			     &packet.receiver_index,
			     packet.unencrypted_ephemeral,
			     packet.encrypted_nothing))
    {
      f64 now = vlib_time_now (vm);
      packet.header.type = MESSAGE_HANDSHAKE_RESPONSE;
      cookie_maker_mac (&peer->cookie_maker, &packet.macs, &packet,
			sizeof (packet));

      if (noise_remote_begin_session (wmp->vlib_main, &peer->remote))
	{
	  wg_timers_session_derived (peer);
	  wg_timers_any_authenticated_packet_traversal (peer);
	  wg_timers_any_authenticated_packet_sent (peer);
	  peer->last_sent_handshake = now;

	  u32 bi0 = 0;
	  if (wg_create_buffer
	      (vm, (u8 *) & packet, sizeof (packet), &bi0, peer,
	       wmp->port_src) != WG_SEND_ERROR_NONE)
	    return;

	  ip46_enqueue_packet (vm, bi0, false);
	}
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
