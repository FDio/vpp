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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <wg/wg.h>

#include <wg/wg_send.h>

#define foreach_wg_input_error                                     \
_(NONE, "No error")							\
_(HANDSHAKE_MAC, "Invalid MAC of handshake")                              \
_(PEER, "Peer error")                     \
_(DECRYPTION, "Failed while decryption")

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

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_wg_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  wg_input_trace_t *t = va_arg (*args, wg_input_trace_t *);

  s = format (s, "wg input \n");
  s = format (s, "  Type: %U", format_wg_message_type, t->type);

  return s;
}

#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  WG_INPUT_NEXT_IP4_INPUT,
  WG_INPUT_NEXT_PUNT,
  WG_INPUT_NEXT_ERROR,
  WG_INPUT_N_NEXT,
} wg_input_next_t;

static bool
decrypt_message (u8 * dst, message_data_t * src, u32 src_len,
		 noise_keypair_t * keypair, f64 now)
{
  if (!keypair)
    return false;

  noise_symmetric_key_t *key = &keypair->receiving;

  if (!key)
    return false;

  if (!(key->is_valid) ||
      wg_birthdate_has_expired (key->birthdate, REJECT_AFTER_TIME, now) ||
      key->counter.receive.counter >= REJECT_AFTER_MESSAGES)
    {
      key->is_valid = false;
      return false;
    }

  u64 nonce = src->counter;
  if (!chacha20poly1305_decrypt (dst, src->encrypted_data, src_len, NULL,
				 0, nonce, key->key))
    return false;

  return true;
}

static void
keep_key_fresh (vlib_main_t * vm, wg_peer_t * peer)
{
  noise_keypair_t *keypair;
  bool send = false;
  f64 now = vlib_time_now (vm);

  if (peer->sent_lastminute_handshake)
    return;

  keypair = peer->keypairs.current_keypair;
  if (keypair && keypair->sending.is_valid &&
      keypair->i_am_the_initiator &&
      wg_birthdate_has_expired (keypair->sending.birthdate,
				REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT -
				REKEY_TIMEOUT, now))
    send = true;

  if (send)
    {
      peer->sent_lastminute_handshake = true;
      wg_send_handshake (vm, peer, false);
    }
}

static void
set_peer_address (wg_peer_t * peer, ip4_address_t ip4, u16 udp_port)
{
  peer->ip4_address = ip4;
  peer->port = udp_port;
}

static wg_input_error_t
wg_handshake_process (vlib_main_t * vm, wg_main_t * wmp, vlib_buffer_t * b)
{
  enum cookie_mac_state mac_state;
  bool packet_needs_cookie;
  bool under_load;
  wg_peer_t *peer;

  void *current_b_data = vlib_buffer_get_current (b);

  udp_header_t *uhd = current_b_data - sizeof (udp_header_t);
  ip4_header_t *iph =
    current_b_data - sizeof (udp_header_t) - sizeof (ip4_header_t);
  ip4_address_t ip4_src = iph->src_address;
  u16 udp_src_port = clib_host_to_net_u16 (uhd->src_port);;

  message_header_t *header = current_b_data;
  under_load = false;

  if (header->type == MESSAGE_HANDSHAKE_COOKIE)
    {
      wg_cookie_message_consume (vm, &wmp->index_table, wmp->peers,
				 (message_handshake_cookie_t *)
				 current_b_data);
      return true;
    }

  u32 len = header->type == MESSAGE_HANDSHAKE_INITIATION
    ? sizeof (message_handshake_initiation_t)
    : sizeof (message_handshake_response_t);
  mac_state =
    wg_cookie_validate_packet (vm, &wmp->cookie_checker, current_b_data, len,
			       ip4_src, udp_src_port, under_load);
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
	peer =
	  wg_noise_handshake_consume_initiation (message,
						 &wmp->static_identity,
						 wmp->peers);
	if (!peer)
	  return WG_INPUT_ERROR_PEER;

	set_peer_address (peer, ip4_src, udp_src_port);
	wg_send_handshake_response (vm, peer);
	break;
      }
    case MESSAGE_HANDSHAKE_RESPONSE:
      {

	message_handshake_response_t *resp = current_b_data;
	peer =
	  wg_noise_handshake_consume_response (resp, &wmp->static_identity,
					       &wmp->index_table, wmp->peers);

	if (!peer)
	  {
	    return WG_INPUT_ERROR_PEER;
	  }
	if (packet_needs_cookie)
	  {
	    // TODO: Add processing
	  }
	set_peer_address (peer, ip4_src, udp_src_port);
	if (wg_noise_handshake_begin_session (vm, &peer->handshake,
					      &peer->keypairs))
	  {
	    wg_timers_session_derived (peer);
	    wg_timers_handshake_complete (peer, vlib_time_now (vm));
	    wg_send_keepalive (vm, peer);
	  }
	break;
      }
    default:
      break;
    }
  return WG_INPUT_ERROR_NONE;
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

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left_from);

  wg_main_t *wmp = &wg_main;
  wg_peer_t *peer = NULL;

  while (n_left_from > 0)
    {
      next[0] = WG_INPUT_NEXT_PUNT;
      header_type =
	((message_header_t *) vlib_buffer_get_current (b[0]))->type;

      switch (header_type)
	{
	case MESSAGE_HANDSHAKE_INITIATION:
	case MESSAGE_HANDSHAKE_RESPONSE:
	case MESSAGE_HANDSHAKE_COOKIE:
	  {

	    wg_input_error_t ret = wg_handshake_process (vm, wmp, b[0]);
	    if (ret != WG_INPUT_ERROR_NONE)
	      {
		next[0] = WG_INPUT_NEXT_ERROR;
		b[0]->error = node->errors[ret];
	      }

	    break;
	  }
	case MESSAGE_DATA:
	  {

	    noise_keypair_t *keypair = NULL;
	    f64 now = vlib_time_now (vm);

	    message_data_t *data = vlib_buffer_get_current (b[0]);
	    index_table_entry_t *entry =
	      wg_index_table_lookup (&wmp->index_table, data->receiver_index);

	    if (entry)
	      {
		peer = pool_elt_at_index (wmp->peers, entry->peer_pool_idx);
		keypair = entry->keypair;
	      }
	    if (!peer)
	      {
		next[0] = WG_INPUT_NEXT_ERROR;
		b[0]->error = node->errors[WG_INPUT_ERROR_PEER];
		goto out;
	      }

	    u16 encr_len = b[0]->current_length - sizeof (message_data_t);
	    u16 decr_len = encr_len - NOISE_AUTHTAG_LEN;
	    u8 *decr_data = clib_mem_alloc (decr_len);

	    if (!decrypt_message (decr_data, data, encr_len, keypair, now))
	      {
		next[0] = WG_INPUT_NEXT_ERROR;
		b[0]->error = node->errors[WG_INPUT_ERROR_DECRYPTION];
		goto out;
	      }

	    clib_memcpy (vlib_buffer_get_current (b[0]), decr_data, decr_len);
	    b[0]->current_length = decr_len;

	    clib_mem_free (decr_data);

	    if (wg_noise_received_with_keypair
		(&wmp->index_table, &peer->keypairs, keypair))
	      {
		wg_timers_handshake_complete (peer, now);
	      }
	    keep_key_fresh (vm, peer);

	    wg_timers_any_authenticated_packet_received (peer);
	    wg_timers_any_authenticated_packet_traversal (peer);

	    if (decr_len == 0)
	      {
		goto out;
	      }

	    wg_timers_data_received (peer);

	    ip4_header_t *iph = vlib_buffer_get_current (b[0]);
	    if (ip4_address_compare (&peer->allowed_ip, &iph->src_address) ==
		0)
	      {
		next[0] = WG_INPUT_NEXT_IP4_INPUT;
	      }
	    break;
	  }
	default:
	  break;
	}

    out:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_input_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->type = header_type;
	}

      n_left_from -= 1;
      next += 1;
      b += 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
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
        [WG_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [WG_INPUT_NEXT_PUNT] = "error-punt",
        [WG_INPUT_NEXT_ERROR] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
