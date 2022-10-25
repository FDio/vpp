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

#include <vnet/vnet.h>
#include <vnet/ip/ip6_link.h>
#include <vppinfra/error.h>
#include <vlibmemory/api.h>
#include <wireguard/wireguard.h>
#include <wireguard/wireguard_send.h>

static int
ip46_enqueue_packet (vlib_main_t *vm, u32 bi0, int is_ip4)
{
  vlib_frame_t *f = 0;
  u32 lookup_node_index =
    is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;

  f = vlib_get_frame_to_node (vm, lookup_node_index);
  /* f can not be NULL here - frame allocation failure causes panic */

  u32 *to_next = vlib_frame_vector_args (f);
  f->n_vectors = 1;
  to_next[0] = bi0;

  vlib_put_frame_to_node (vm, lookup_node_index, f);

  return f->n_vectors;
}

static void
wg_buffer_prepend_rewrite (vlib_main_t *vm, vlib_buffer_t *b0,
			   const u8 *rewrite, u8 is_ip4)
{
  if (is_ip4)
    {
      ip4_udp_header_t *hdr4;

      vlib_buffer_advance (b0, -sizeof (*hdr4));

      hdr4 = vlib_buffer_get_current (b0);

      /* copy only ip4 and udp header; wireguard header not needed */
      clib_memcpy (hdr4, rewrite, sizeof (ip4_udp_header_t));

      hdr4->udp.length =
	clib_host_to_net_u16 (b0->current_length - sizeof (ip4_header_t));
      ip4_header_set_len_w_chksum (&hdr4->ip4,
				   clib_host_to_net_u16 (b0->current_length));
    }
  else
    {
      ip6_udp_header_t *hdr6;

      vlib_buffer_advance (b0, -sizeof (*hdr6));

      hdr6 = vlib_buffer_get_current (b0);

      /* copy only ip6 and udp header; wireguard header not needed */
      clib_memcpy (hdr6, rewrite, sizeof (ip6_udp_header_t));

      hdr6->ip6.payload_length = hdr6->udp.length =
	clib_host_to_net_u16 (b0->current_length - sizeof (ip6_header_t));

      /* IPv6 UDP checksum is mandatory */
      int bogus = 0;
      ip6_header_t *ip6_0 = &(hdr6->ip6);
      hdr6->udp.checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6_0, &bogus);
      ASSERT (bogus == 0);
    }
}

static bool
wg_create_buffer (vlib_main_t *vm, const u8 *rewrite, const u8 *packet,
		  u32 packet_len, u32 *bi, u8 is_ip4)
{
  u32 n_buf0 = 0;
  vlib_buffer_t *b0;

  n_buf0 = vlib_buffer_alloc (vm, bi, 1);
  if (!n_buf0)
    return false;

  b0 = vlib_get_buffer (vm, *bi);

  u8 *payload = vlib_buffer_get_current (b0);
  clib_memcpy (payload, packet, packet_len);

  b0->current_length = packet_len;

  wg_buffer_prepend_rewrite (vm, b0, rewrite, is_ip4);

  return true;
}

u8 *
wg_build_rewrite (ip46_address_t *src_addr, u16 src_port,
		  ip46_address_t *dst_addr, u16 dst_port, u8 is_ip4)
{
  if (ip46_address_is_zero (dst_addr) || 0 == dst_port)
    return NULL;

  u8 *rewrite = NULL;
  if (is_ip4)
    {
      ip4_udp_header_t *hdr;

      /* reserve space for ip4, udp and wireguard headers */
      vec_validate (rewrite, sizeof (ip4_udp_wg_header_t) - 1);
      hdr = (ip4_udp_header_t *) rewrite;

      hdr->ip4.ip_version_and_header_length = 0x45;
      hdr->ip4.ttl = 64;
      hdr->ip4.src_address = src_addr->ip4;
      hdr->ip4.dst_address = dst_addr->ip4;
      hdr->ip4.protocol = IP_PROTOCOL_UDP;
      hdr->ip4.checksum = ip4_header_checksum (&hdr->ip4);

      hdr->udp.src_port = clib_host_to_net_u16 (src_port);
      hdr->udp.dst_port = clib_host_to_net_u16 (dst_port);
      hdr->udp.checksum = 0;
    }
  else
    {
      ip6_udp_header_t *hdr;

      /* reserve space for ip6, udp and wireguard headers */
      vec_validate (rewrite, sizeof (ip6_udp_wg_header_t) - 1);
      hdr = (ip6_udp_header_t *) rewrite;

      hdr->ip6.ip_version_traffic_class_and_flow_label = 0x60;
      ip6_address_copy (&hdr->ip6.src_address, &src_addr->ip6);
      ip6_address_copy (&hdr->ip6.dst_address, &dst_addr->ip6);
      hdr->ip6.protocol = IP_PROTOCOL_UDP;
      hdr->ip6.hop_limit = 64;

      hdr->udp.src_port = clib_host_to_net_u16 (src_port);
      hdr->udp.dst_port = clib_host_to_net_u16 (dst_port);
      hdr->udp.checksum = 0;
    }

  return (rewrite);
}

bool
wg_send_handshake (vlib_main_t * vm, wg_peer_t * peer, bool is_retry)
{
  ASSERT (vm->thread_index == 0);

  if (!wg_peer_can_send (peer))
    return false;

  message_handshake_initiation_t packet;

  if (!is_retry)
    peer->timer_handshake_attempts = 0;

  if (!wg_birthdate_has_expired (peer->last_sent_handshake, REKEY_TIMEOUT) ||
      wg_peer_is_dead (peer))
    return true;

  if (noise_create_initiation (vm,
			       &peer->remote,
			       &packet.sender_index,
			       packet.unencrypted_ephemeral,
			       packet.encrypted_static,
			       packet.encrypted_timestamp))
    {
      packet.header.type = MESSAGE_HANDSHAKE_INITIATION;
      cookie_maker_mac (&peer->cookie_maker, &packet.macs, &packet,
			sizeof (packet));
      wg_timers_any_authenticated_packet_sent (peer);
      wg_timers_handshake_initiated (peer);
      wg_timers_any_authenticated_packet_traversal (peer);

      peer->last_sent_handshake = vlib_time_now (vm);
    }
  else
    return false;

  u8 is_ip4 = ip46_address_is_ip4 (&peer->dst.addr);
  u32 bi0 = 0;
  if (!wg_create_buffer (vm, peer->rewrite, (u8 *) &packet, sizeof (packet),
			 &bi0, is_ip4))
    return false;

  ip46_enqueue_packet (vm, bi0, is_ip4);
  return true;
}

typedef struct
{
  u32 peer_idx;
  bool is_retry;
} wg_send_args_t;

static void *
wg_send_handshake_thread_fn (void *arg)
{
  wg_send_args_t *a = arg;

  wg_main_t *wmp = &wg_main;
  wg_peer_t *peer = wg_peer_get (a->peer_idx);

  wg_send_handshake (wmp->vlib_main, peer, a->is_retry);
  return 0;
}

void
wg_send_handshake_from_mt (u32 peer_idx, bool is_retry)
{
  wg_send_args_t a = {
    .peer_idx = peer_idx,
    .is_retry = is_retry,
  };

  vl_api_rpc_call_main_thread (wg_send_handshake_thread_fn,
			       (u8 *) & a, sizeof (a));
}

bool
wg_send_keepalive (vlib_main_t * vm, wg_peer_t * peer)
{
  ASSERT (vm->thread_index == 0);

  if (!wg_peer_can_send (peer))
    return false;

  u32 size_of_packet = message_data_len (0);
  message_data_t *packet =
    (message_data_t *) wg_main.per_thread_data[vm->thread_index].data;
  u32 bi0 = 0;
  bool ret = true;
  enum noise_state_crypt state;

  if (!peer->remote.r_current)
    {
      wg_send_handshake (vm, peer, false);
      goto out;
    }

  state =
    noise_remote_encrypt (vm,
			  &peer->remote,
			  &packet->receiver_index,
			  &packet->counter, NULL, 0, packet->encrypted_data);

  if (PREDICT_FALSE (state == SC_KEEP_KEY_FRESH))
    {
      wg_send_handshake (vm, peer, false);
    }
  else if (PREDICT_FALSE (state == SC_FAILED))
    {
      wg_peer_update_flags (peer - wg_peer_pool, WG_PEER_ESTABLISHED, false);
      ret = false;
      goto out;
    }

  u8 is_ip4 = ip46_address_is_ip4 (&peer->dst.addr);
  packet->header.type = MESSAGE_DATA;

  if (!wg_create_buffer (vm, peer->rewrite, (u8 *) packet, size_of_packet,
			 &bi0, is_ip4))
    {
      ret = false;
      goto out;
    }

  ip46_enqueue_packet (vm, bi0, is_ip4);

  wg_timers_any_authenticated_packet_sent (peer);
  wg_timers_any_authenticated_packet_traversal (peer);

out:
  return ret;
}

bool
wg_send_handshake_response (vlib_main_t * vm, wg_peer_t * peer)
{
  message_handshake_response_t packet;

  if (!wg_peer_can_send (peer))
    return false;

  if (noise_create_response (vm,
			     &peer->remote,
			     &packet.sender_index,
			     &packet.receiver_index,
			     packet.unencrypted_ephemeral,
			     packet.encrypted_nothing))
    {
      packet.header.type = MESSAGE_HANDSHAKE_RESPONSE;
      cookie_maker_mac (&peer->cookie_maker, &packet.macs, &packet,
			sizeof (packet));

      if (noise_remote_begin_session (vm, &peer->remote))
	{
	  wg_timers_session_derived (peer);
	  wg_timers_any_authenticated_packet_sent (peer);
	  wg_timers_any_authenticated_packet_traversal (peer);

	  u32 bi0 = 0;
	  u8 is_ip4 = ip46_address_is_ip4 (&peer->dst.addr);
	  if (!wg_create_buffer (vm, peer->rewrite, (u8 *) &packet,
				 sizeof (packet), &bi0, is_ip4))
	    return false;

	  ip46_enqueue_packet (vm, bi0, is_ip4);
	  return true;
	}
      return false;
    }
  return false;
}

bool
wg_send_handshake_cookie (vlib_main_t *vm, u32 sender_index,
			  cookie_checker_t *cookie_checker,
			  message_macs_t *macs, ip46_address_t *wg_if_addr,
			  u16 wg_if_port, ip46_address_t *remote_addr,
			  u16 remote_port)
{
  message_handshake_cookie_t packet;
  u8 *rewrite;

  packet.header.type = MESSAGE_HANDSHAKE_COOKIE;
  packet.receiver_index = sender_index;

  cookie_checker_create_payload (vm, cookie_checker, macs, packet.nonce,
				 packet.encrypted_cookie, remote_addr,
				 remote_port);

  u32 bi0 = 0;
  u8 is_ip4 = ip46_address_is_ip4 (remote_addr);
  bool ret;
  rewrite = wg_build_rewrite (wg_if_addr, wg_if_port, remote_addr, remote_port,
			      is_ip4);

  ret = wg_create_buffer (vm, rewrite, (u8 *) &packet, sizeof (packet), &bi0,
			  is_ip4);
  vec_free (rewrite);
  if (!ret)
    return false;

  ip46_enqueue_packet (vm, bi0, is_ip4);

  return true;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
