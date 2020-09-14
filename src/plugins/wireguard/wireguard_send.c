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
#include <vlibmemory/api.h>
#include <wireguard/wireguard.h>
#include <wireguard/wireguard_send.h>

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

static void
wg_buffer_prepend_rewrite (vlib_buffer_t * b0, const wg_peer_t * peer)
{
  ip4_udp_header_t *hdr;

  vlib_buffer_advance (b0, -sizeof (*hdr));

  hdr = vlib_buffer_get_current (b0);
  clib_memcpy (hdr, peer->rewrite, vec_len (peer->rewrite));

  hdr->udp.length =
    clib_host_to_net_u16 (b0->current_length - sizeof (ip4_header_t));
  ip4_header_set_len_w_chksum (&hdr->ip4,
			       clib_host_to_net_u16 (b0->current_length));
}

static bool
wg_create_buffer (vlib_main_t * vm,
		  const wg_peer_t * peer,
		  const u8 * packet, u32 packet_len, u32 * bi)
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

  wg_buffer_prepend_rewrite (b0, peer);

  return true;
}

bool
wg_send_handshake (vlib_main_t * vm, wg_peer_t * peer, bool is_retry)
{
  ASSERT (vm->thread_index == 0);

  message_handshake_initiation_t packet;

  if (!is_retry)
    peer->timer_handshake_attempts = 0;

  if (!wg_birthdate_has_expired (peer->last_sent_handshake,
				 REKEY_TIMEOUT) || peer->is_dead)
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

  u32 bi0 = 0;
  if (!wg_create_buffer (vm, peer, (u8 *) & packet, sizeof (packet), &bi0))
    return false;

  ip46_enqueue_packet (vm, bi0, false);
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
  wg_peer_t *peer = pool_elt_at_index (wmp->peers, a->peer_idx);

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

  u32 size_of_packet = message_data_len (0);
  message_data_t *packet = clib_mem_alloc (size_of_packet);
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
  switch (state)
    {
    case SC_OK:
      break;
    case SC_KEEP_KEY_FRESH:
      wg_send_handshake (vm, peer, false);
      break;
    case SC_FAILED:
      ret = false;
      goto out;
    default:
      break;
    }
  packet->header.type = MESSAGE_DATA;

  if (!wg_create_buffer (vm, peer, (u8 *) packet, size_of_packet, &bi0))
    {
      ret = false;
      goto out;
    }

  ip46_enqueue_packet (vm, bi0, false);

  wg_timers_any_authenticated_packet_sent (peer);
  wg_timers_any_authenticated_packet_traversal (peer);

out:
  clib_mem_free (packet);
  return ret;
}

bool
wg_send_handshake_response (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_main_t *wmp = &wg_main;
  message_handshake_response_t packet;

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

      if (noise_remote_begin_session (wmp->vlib_main, &peer->remote))
	{
	  wg_timers_session_derived (peer);
	  wg_timers_any_authenticated_packet_sent (peer);
	  wg_timers_any_authenticated_packet_traversal (peer);
	  peer->last_sent_handshake = vlib_time_now (vm);

	  u32 bi0 = 0;
	  if (!wg_create_buffer (vm, peer, (u8 *) & packet,
				 sizeof (packet), &bi0))
	    return false;

	  ip46_enqueue_packet (vm, bi0, false);
	}
      else
	return false;
    }
  else
    return false;
  return true;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
