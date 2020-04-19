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
#include <wg/wg.h>
#include <wg/wg_send.h>

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
//TODO Ip6
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

      ip46_set_src_address (sw_if_index, b0, false);	// set src adress
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

static bool
wg_create_buffer (vlib_main_t * vm, const u8 * packet, u32 packet_len,
		  u32 * bi, wg_peer_t * peer, u16 src_port)
{
  u32 sw_if_index = ~0;
  u32 fib_index = ~0;
  u32 table_id = 0;

  int n_buf0 = 0;
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
      vlib_cli_output (vm, "Error fib");
      return false;
    }
  if (~0 == sw_if_index)
    {
      vlib_cli_output (vm, "Error sw");
      return false;
    }

  n_buf0 = vlib_buffer_alloc (vm, bi, 1);
  if (!n_buf0)
    {
      vlib_cli_output (vm, "Error while buffer allocation");
      return false;
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
				 REKEY_TIMEOUT, vlib_time_now (vm)) ||
      peer->is_dead)
    {
      return;
    }

  if (wg_noise_handshake_create_initiation
      (vm, &packet, peer, &wmp->index_table, wmp->peers))
    {
      f64 now = vlib_time_now (vm);
      wg_cookie_add_mac_to_packet (&packet, sizeof (packet), peer, now);
      wg_timers_any_authenticated_packet_traversal (peer);
      wg_timers_any_authenticated_packet_sent (peer);
      peer->last_sent_handshake = now;
      wg_timers_handshake_initiated (peer);
    }

  u32 bi0 = 0;
  if (!wg_create_buffer
      (vm, (u8 *) & packet, sizeof (packet), &bi0, peer, wmp->port_src))
    return;
  ip46_enqueue_packet (vm, bi0, false);
}

void
wg_encrypt_message (message_data_t * packet, const u8 * inp,
		    size_t inp_len, noise_keypair_t * keypair, u64 nonce)
{
  if (!keypair || !keypair->sending.is_valid)
    {
      return;
    }
  packet->header.type = MESSAGE_DATA;
  packet->receiver_index = keypair->remote_index;
  packet->counter = nonce;

  chacha20poly1305_encrypt (packet->encrypted_data, inp, inp_len, NULL, 0,
			    nonce, keypair->sending.key);
}

void
wg_send_keepalive (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_main_t *wmp = &wg_main;
  message_data_t *packet = clib_mem_alloc (MESSAGE_MINIMUM_LENGTH);
  u32 size_of_packet = MESSAGE_MINIMUM_LENGTH;

  if (!peer->keypairs.current_keypair)
    {
      wg_send_handshake (vm, peer, false);
      return;
    }

  u64 nonce = peer->keypairs.current_keypair->sending.counter.counter;

  wg_encrypt_message (packet, NULL, 0, peer->keypairs.current_keypair, nonce);

  u32 bi0 = 0;
  if (!wg_create_buffer
      (vm, (u8 *) packet, size_of_packet, &bi0, peer, wmp->port_src))
    return;

  ip46_enqueue_packet (vm, bi0, false);

  wg_timers_any_authenticated_packet_traversal (peer);
  wg_timers_any_authenticated_packet_sent (peer);

  wg_send_keep_key_fresh (vm, peer);

  peer->keypairs.current_keypair->sending.counter.counter++;

  clib_mem_free (packet);
}

void
wg_send_handshake_response (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_main_t *wmp = &wg_main;
  message_handshake_response_t packet;

  peer->last_sent_handshake = vlib_time_now (vm);

  if (wg_noise_handshake_create_response
      (&packet, peer, &wmp->index_table, wmp->peers))
    {
      f64 now = vlib_time_now (vm);
      wg_cookie_add_mac_to_packet (&packet, sizeof (packet), peer, now);
      if (wg_noise_handshake_begin_session (vm, &peer->handshake,
					    &peer->keypairs))
	{
	  wg_timers_session_derived (peer);
	  wg_timers_any_authenticated_packet_traversal (peer);
	  wg_timers_any_authenticated_packet_sent (peer);
	  peer->last_sent_handshake = now;

	  u32 bi0 = 0;
	  if (!wg_create_buffer
	      (vm, (u8 *) & packet, sizeof (packet), &bi0, peer,
	       wmp->port_src))
	    return;

	  ip46_enqueue_packet (vm, bi0, false);
	}
    }
}

bool
wg_send_keep_key_fresh (vlib_main_t * vm, wg_peer_t * peer)
{
  noise_keypair_t *keypair;
  bool send = false;
  f64 now = vlib_time_now (vm);
  keypair = peer->keypairs.current_keypair;

  if ((keypair && keypair->sending.is_valid) &&
      ((keypair->sending.counter.counter >
	REKEY_AFTER_MESSAGES) ||
       (keypair->i_am_the_initiator &&
	wg_birthdate_has_expired (keypair->sending.birthdate,
				  REKEY_AFTER_TIME, now))))
    send = true;

  if (send)
    {
      wg_send_handshake (vm, peer, false);
    }
  return send;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
