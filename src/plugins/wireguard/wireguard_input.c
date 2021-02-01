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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <wireguard/wireguard.h>

#include <wireguard/wireguard_send.h>
#include <wireguard/wireguard_if.h>

#define foreach_wg_input_error                          \
  _(NONE, "No error")                                   \
  _(HANDSHAKE_MAC, "Invalid MAC handshake")             \
  _(PEER, "Peer error")                                 \
  _(INTERFACE, "Interface error")                       \
  _(DECRYPTION, "Failed during decryption")             \
  _(KEEPALIVE_SEND, "Failed while sending Keepalive")   \
  _(HANDSHAKE_SEND, "Failed while sending Handshake")   \
  _(TOO_BIG, "Packet too big")                          \
  _(UNDEFINED, "Undefined error")

typedef enum
{
#define _(sym,str) WG_INPUT_ERROR_##sym,
  foreach_wg_input_error
#undef _
    WG_INPUT_N_ERROR,
} wg_input_error_t;

static char *wg_input_error_strings[] = {
#define _(sym,string) string,
  foreach_wg_input_error
#undef _
};

typedef struct
{
  message_type_t type;
  u16 current_length;
  bool is_keepalive;
  index_t peer;
} wg_input_trace_t;

u8 *
format_wg_message_type (u8 * s, va_list * args)
{
  message_type_t type = va_arg (*args, message_type_t);

  switch (type)
    {
#define _(v,a) case MESSAGE_##v: return (format (s, "%s", a));
      foreach_wg_message_type
#undef _
    }
  return (format (s, "unknown"));
}

/* packet trace format function */
static u8 *
format_wg_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  wg_input_trace_t *t = va_arg (*args, wg_input_trace_t *);

  s = format (s, "WG input: \n");
  s = format (s, "  Type: %U\n", format_wg_message_type, t->type);
  s = format (s, "  peer: %d\n", t->peer);
  s = format (s, "  Length: %d\n", t->current_length);
  s = format (s, "  Keepalive: %s", t->is_keepalive ? "true" : "false");

  return s;
}

typedef enum
{
  WG_INPUT_NEXT_HANDOFF_HANDSHAKE,
  WG_INPUT_NEXT_HANDOFF_DATA,
  WG_INPUT_NEXT_IP4_INPUT,
  WG_INPUT_NEXT_PUNT,
  WG_INPUT_NEXT_ERROR,
  WG_INPUT_N_NEXT,
} wg_input_next_t;

/* static void */
/* set_peer_address (wg_peer_t * peer, ip4_address_t ip4, u16 udp_port) */
/* { */
/*   if (peer) */
/*     { */
/*       ip46_address_set_ip4 (&peer->dst.addr, &ip4); */
/*       peer->dst.port = udp_port; */
/*     } */
/* } */

static wg_input_error_t
wg_handshake_process (vlib_main_t * vm, wg_main_t * wmp, vlib_buffer_t * b)
{
  ASSERT (vm->thread_index == 0);

  enum cookie_mac_state mac_state;
  bool packet_needs_cookie;
  bool under_load;
  wg_if_t *wg_if;
  wg_peer_t *peer = NULL;

  void *current_b_data = vlib_buffer_get_current (b);

  udp_header_t *uhd = current_b_data - sizeof (udp_header_t);
  ip4_header_t *iph =
    current_b_data - sizeof (udp_header_t) - sizeof (ip4_header_t);
  ip4_address_t ip4_src = iph->src_address;
  u16 udp_src_port = clib_host_to_net_u16 (uhd->src_port);;
  u16 udp_dst_port = clib_host_to_net_u16 (uhd->dst_port);;

  message_header_t *header = current_b_data;
  under_load = false;

  wg_if = wg_if_get_by_port (udp_dst_port);

  if (NULL == wg_if)
    return WG_INPUT_ERROR_INTERFACE;

  if (PREDICT_FALSE (header->type == MESSAGE_HANDSHAKE_COOKIE))
    {
      message_handshake_cookie_t *packet =
	(message_handshake_cookie_t *) current_b_data;
      u32 *entry =
	wg_index_table_lookup (&wmp->index_table, packet->receiver_index);
      if (entry)
	peer = wg_peer_get (*entry);
      else
	return WG_INPUT_ERROR_PEER;

      // TODO: Implement cookie_maker_consume_payload

      return WG_INPUT_ERROR_NONE;
    }

  u32 len = (header->type == MESSAGE_HANDSHAKE_INITIATION ?
	     sizeof (message_handshake_initiation_t) :
	     sizeof (message_handshake_response_t));

  message_macs_t *macs = (message_macs_t *)
    ((u8 *) current_b_data + len - sizeof (*macs));

  mac_state =
    cookie_checker_validate_macs (vm, &wg_if->cookie_checker, macs,
				  current_b_data, len, under_load, ip4_src,
				  udp_src_port);

  if ((under_load && mac_state == VALID_MAC_WITH_COOKIE)
      || (!under_load && mac_state == VALID_MAC_BUT_NO_COOKIE))
    packet_needs_cookie = false;
  else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE)
    packet_needs_cookie = true;
  else
    return WG_INPUT_ERROR_HANDSHAKE_MAC;

  switch (header->type)
    {
    case MESSAGE_HANDSHAKE_INITIATION:
      {
	message_handshake_initiation_t *message = current_b_data;

	if (packet_needs_cookie)
	  {
	    // TODO: Add processing
	  }
	noise_remote_t *rp;
	if (noise_consume_initiation
	    (vm, noise_local_get (wg_if->local_idx), &rp,
	     message->sender_index, message->unencrypted_ephemeral,
	     message->encrypted_static, message->encrypted_timestamp))
	  {
	    peer = wg_peer_get (rp->r_peer_idx);
	  }
	else
	  {
	    return WG_INPUT_ERROR_PEER;
	  }

	// set_peer_address (peer, ip4_src, udp_src_port);
	if (PREDICT_FALSE (!wg_send_handshake_response (vm, peer)))
	  {
	    vlib_node_increment_counter (vm, wg_input_node.index,
					 WG_INPUT_ERROR_HANDSHAKE_SEND, 1);
	  }
	break;
      }
    case MESSAGE_HANDSHAKE_RESPONSE:
      {
	message_handshake_response_t *resp = current_b_data;
	u32 *entry =
	  wg_index_table_lookup (&wmp->index_table, resp->receiver_index);

	if (PREDICT_TRUE (entry != NULL))
	  {
	    peer = wg_peer_get (*entry);
	    if (peer->is_dead)
	      return WG_INPUT_ERROR_PEER;
	  }
	else
	  return WG_INPUT_ERROR_PEER;

	if (!noise_consume_response
	    (vm, &peer->remote, resp->sender_index,
	     resp->receiver_index, resp->unencrypted_ephemeral,
	     resp->encrypted_nothing))
	  {
	    return WG_INPUT_ERROR_PEER;
	  }
	if (packet_needs_cookie)
	  {
	    // TODO: Add processing
	  }

	// set_peer_address (peer, ip4_src, udp_src_port);
	if (noise_remote_begin_session (vm, &peer->remote))
	  {

	    wg_timers_session_derived (peer);
	    wg_timers_handshake_complete (peer);
	    if (PREDICT_FALSE (!wg_send_keepalive (vm, peer)))
	      {
		vlib_node_increment_counter (vm, wg_input_node.index,
					     WG_INPUT_ERROR_KEEPALIVE_SEND,
					     1);
	      }
	  }
	break;
      }
    default:
      break;
    }

  wg_timers_any_authenticated_packet_received (peer);
  wg_timers_any_authenticated_packet_traversal (peer);
  return WG_INPUT_ERROR_NONE;
}

static_always_inline bool
fib_prefix_is_cover_addr_4 (const fib_prefix_t * p1,
			    const ip4_address_t * ip4)
{
  switch (p1->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
      return (ip4_destination_matches_route (&ip4_main,
					     &p1->fp_addr.ip4,
					     ip4, p1->fp_len) != 0);
    case FIB_PROTOCOL_IP6:
      return (false);
    case FIB_PROTOCOL_MPLS:
      break;
    }
  return (false);
}

VLIB_NODE_FN (wg_input_node) (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  message_type_t header_type;
  u32 n_left_from;
  u32 *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left_from);

  wg_main_t *wmp = &wg_main;
  wg_peer_t *peer = NULL;

  while (n_left_from > 0)
    {
      bool is_keepalive = false;
      next[0] = WG_INPUT_NEXT_PUNT;
      header_type =
	((message_header_t *) vlib_buffer_get_current (b[0]))->type;
      u32 *peer_idx;

      if (PREDICT_TRUE (header_type == MESSAGE_DATA))
	{
	  message_data_t *data = vlib_buffer_get_current (b[0]);

	  peer_idx = wg_index_table_lookup (&wmp->index_table,
					    data->receiver_index);

	  if (peer_idx)
	    {
	      peer = wg_peer_get (*peer_idx);
	    }
	  else
	    {
	      next[0] = WG_INPUT_NEXT_ERROR;
	      b[0]->error = node->errors[WG_INPUT_ERROR_PEER];
	      goto out;
	    }

	  if (PREDICT_FALSE (~0 == peer->input_thread_index))
	    {
	      /* this is the first packet to use this peer, claim the peer
	       * for this thread.
	       */
	      clib_atomic_cmp_and_swap (&peer->input_thread_index, ~0,
					wg_peer_assign_thread (thread_index));
	    }

	  if (PREDICT_TRUE (thread_index != peer->input_thread_index))
	    {
	      next[0] = WG_INPUT_NEXT_HANDOFF_DATA;
	      goto next;
	    }

	  u16 encr_len = b[0]->current_length - sizeof (message_data_t);
	  u16 decr_len = encr_len - NOISE_AUTHTAG_LEN;
	  if (PREDICT_FALSE (decr_len >= WG_DEFAULT_DATA_SIZE))
	    {
	      b[0]->error = node->errors[WG_INPUT_ERROR_TOO_BIG];
	      goto out;
	    }

	  u8 *decr_data = wmp->per_thread_data[thread_index].data;

	  enum noise_state_crypt state_cr = noise_remote_decrypt (vm,
								  &peer->remote,
								  data->receiver_index,
								  data->counter,
								  data->encrypted_data,
								  encr_len,
								  decr_data);

	  if (PREDICT_FALSE (state_cr == SC_CONN_RESET))
	    {
	      wg_timers_handshake_complete (peer);
	    }
	  else if (PREDICT_FALSE (state_cr == SC_KEEP_KEY_FRESH))
	    {
	      wg_send_handshake_from_mt (*peer_idx, false);
	    }
	  else if (PREDICT_FALSE (state_cr == SC_FAILED))
	    {
	      next[0] = WG_INPUT_NEXT_ERROR;
	      b[0]->error = node->errors[WG_INPUT_ERROR_DECRYPTION];
	      goto out;
	    }

	  clib_memcpy (vlib_buffer_get_current (b[0]), decr_data, decr_len);
	  b[0]->current_length = decr_len;
	  vnet_buffer_offload_flags_clear (b[0],
					   VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);

	  wg_timers_any_authenticated_packet_received (peer);
	  wg_timers_any_authenticated_packet_traversal (peer);

	  /* Keepalive packet has zero length */
	  if (decr_len == 0)
	    {
	      is_keepalive = true;
	      goto out;
	    }

	  wg_timers_data_received (peer);

	  ip4_header_t *iph = vlib_buffer_get_current (b[0]);

	  const wg_peer_allowed_ip_t *allowed_ip;
	  bool allowed = false;

	  /*
	   * we could make this into an ACL, but the expectation
	   * is that there aren't many allowed IPs and thus a linear
	   * walk is fater than an ACL
	   */
	  vec_foreach (allowed_ip, peer->allowed_ips)
	  {
	    if (fib_prefix_is_cover_addr_4 (&allowed_ip->prefix,
					    &iph->src_address))
	      {
		allowed = true;
		break;
	      }
	  }
	  if (allowed)
	    {
	      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = peer->wg_sw_if_index;
	      next[0] = WG_INPUT_NEXT_IP4_INPUT;
	    }
	}
      else
	{
	  peer_idx = NULL;

	  /* Handshake packets should be processed in main thread */
	  if (thread_index != 0)
	    {
	      next[0] = WG_INPUT_NEXT_HANDOFF_HANDSHAKE;
	      goto next;
	    }

	  wg_input_error_t ret = wg_handshake_process (vm, wmp, b[0]);
	  if (ret != WG_INPUT_ERROR_NONE)
	    {
	      next[0] = WG_INPUT_NEXT_ERROR;
	      b[0]->error = node->errors[ret];
	    }
	}

    out:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_input_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->type = header_type;
	  t->current_length = b[0]->current_length;
	  t->is_keepalive = is_keepalive;
	  t->peer = peer_idx ? *peer_idx : INDEX_INVALID;
	}
    next:
      n_left_from -= 1;
      next += 1;
      b += 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (wg_input_node) =
{
  .name = "wg-input",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_input_error_strings),
  .error_strings = wg_input_error_strings,
  .n_next_nodes = WG_INPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
        [WG_INPUT_NEXT_HANDOFF_HANDSHAKE] = "wg-handshake-handoff",
        [WG_INPUT_NEXT_HANDOFF_DATA] = "wg-input-data-handoff",
        [WG_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [WG_INPUT_NEXT_PUNT] = "error-punt",
        [WG_INPUT_NEXT_ERROR] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
