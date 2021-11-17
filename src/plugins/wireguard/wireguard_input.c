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

#define foreach_wg_input_error                                                \
  _ (NONE, "No error")                                                        \
  _ (HANDSHAKE_MAC, "Invalid MAC handshake")                                  \
  _ (PEER, "Peer error")                                                      \
  _ (INTERFACE, "Interface error")                                            \
  _ (DECRYPTION, "Failed during decryption")                                  \
  _ (KEEPALIVE_SEND, "Failed while sending Keepalive")                        \
  _ (HANDSHAKE_SEND, "Failed while sending Handshake")                        \
  _ (HANDSHAKE_RECEIVE, "Failed while receiving Handshake")                   \
  _ (TOO_BIG, "Packet too big")                                               \
  _ (UNDEFINED, "Undefined error")                                            \
  _ (CRYPTO_ENGINE_ERROR, "crypto engine error (packet dropped)")

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

typedef struct
{
  index_t peer;
  u16 next;
} wg_input_post_trace_t;

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

  s = format (s, "Wireguard input: \n");
  s = format (s, "    Type: %U\n", format_wg_message_type, t->type);
  s = format (s, "    Peer: %d\n", t->peer);
  s = format (s, "    Length: %d\n", t->current_length);
  s = format (s, "    Keepalive: %s", t->is_keepalive ? "true" : "false");

  return s;
}

/* post-node packet trace format function */
static u8 *
format_wg_input_post_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  wg_input_post_trace_t *t = va_arg (*args, wg_input_post_trace_t *);

  s = format (s, "WG input post: \n");
  s = format (s, "  peer: %u\n", t->peer);
  s = format (s, "  next: %u\n", t->next);

  return s;
}

typedef enum
{
  WG_INPUT_NEXT_HANDOFF_HANDSHAKE,
  WG_INPUT_NEXT_HANDOFF_DATA,
  WG_INPUT_NEXT_IP4_INPUT,
  WG_INPUT_NEXT_IP6_INPUT,
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

static u8
is_ip4_header (u8 *data)
{
  return (data[0] >> 4) == 0x4;
}

static wg_input_error_t
wg_handshake_process (vlib_main_t *vm, wg_main_t *wmp, vlib_buffer_t *b,
		      u32 node_idx, u8 is_ip4)
{
  ASSERT (vm->thread_index == 0);

  enum cookie_mac_state mac_state;
  bool packet_needs_cookie;
  bool under_load;
  index_t *wg_ifs;
  wg_if_t *wg_if;
  wg_peer_t *peer = NULL;

  void *current_b_data = vlib_buffer_get_current (b);

  ip46_address_t src_ip;
  if (is_ip4)
    {
      ip4_header_t *iph4 =
	current_b_data - sizeof (udp_header_t) - sizeof (ip4_header_t);
      ip46_address_set_ip4 (&src_ip, &iph4->src_address);
    }
  else
    {
      ip6_header_t *iph6 =
	current_b_data - sizeof (udp_header_t) - sizeof (ip6_header_t);
      ip46_address_set_ip6 (&src_ip, &iph6->src_address);
    }

  udp_header_t *uhd = current_b_data - sizeof (udp_header_t);
  u16 udp_src_port = clib_host_to_net_u16 (uhd->src_port);;
  u16 udp_dst_port = clib_host_to_net_u16 (uhd->dst_port);;

  message_header_t *header = current_b_data;
  under_load = false;

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

  index_t *ii;
  wg_ifs = wg_if_indexes_get_by_port (udp_dst_port);
  if (NULL == wg_ifs)
    return WG_INPUT_ERROR_INTERFACE;

  vec_foreach (ii, wg_ifs)
    {
      wg_if = wg_if_get (*ii);
      if (NULL == wg_if)
	continue;

      mac_state = cookie_checker_validate_macs (
	vm, &wg_if->cookie_checker, macs, current_b_data, len, under_load,
	&src_ip, udp_src_port);
      if (mac_state == INVALID_MAC)
	{
	  wg_if = NULL;
	  continue;
	}
      break;
    }

  if (NULL == wg_if)
    return WG_INPUT_ERROR_HANDSHAKE_MAC;

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
	    vlib_node_increment_counter (vm, node_idx,
					 WG_INPUT_ERROR_HANDSHAKE_SEND, 1);
	  }
	else
	  {
	    wg_peer_update_flags (rp->r_peer_idx, WG_PEER_ESTABLISHED, true);
	  }
	break;
      }
    case MESSAGE_HANDSHAKE_RESPONSE:
      {
	message_handshake_response_t *resp = current_b_data;
	index_t peeri = INDEX_INVALID;
	u32 *entry =
	  wg_index_table_lookup (&wmp->index_table, resp->receiver_index);

	if (PREDICT_TRUE (entry != NULL))
	  {
	    peeri = *entry;
	    peer = wg_peer_get (peeri);
	    if (wg_peer_is_dead (peer))
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
		vlib_node_increment_counter (vm, node_idx,
					     WG_INPUT_ERROR_KEEPALIVE_SEND, 1);
	      }
	    else
	      {
		wg_peer_update_flags (peeri, WG_PEER_ESTABLISHED, true);
	      }
	  }
	break;
      }
    default:
      return WG_INPUT_ERROR_HANDSHAKE_RECEIVE;
    }

  wg_timers_any_authenticated_packet_received (peer);
  wg_timers_any_authenticated_packet_traversal (peer);
  return WG_INPUT_ERROR_NONE;
}

<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
static_always_inline int
wg_input_post_process (vlib_main_t *vm, vlib_buffer_t *b, u16 *next,
		       wg_peer_t *peer, message_data_t *data,
		       bool *is_keepalive)
{
  next[0] = WG_INPUT_NEXT_PUNT;

  noise_keypair_t *kp =
    wg_get_active_keypair (&peer->remote, data->receiver_index);

  if (!noise_counter_recv (&kp->kp_ctr, data->counter))
    {
      return -1;
    }

  u16 encr_len = b->current_length - sizeof (message_data_t);
  u16 decr_len = encr_len - NOISE_AUTHTAG_LEN;

  vlib_buffer_advance (b, sizeof (message_data_t));
  b->current_length = decr_len;
  vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);

  /* Keepalive packet has zero length */
  if (decr_len == 0)
    {
      *is_keepalive = true;
      return -1;
    }

  wg_timers_data_received (peer);

  ip46_address_t src_ip;
  u8 is_ip4_inner = is_ip4_header (vlib_buffer_get_current (b));
  if (is_ip4_inner)
    {
      ip46_address_set_ip4 (
	&src_ip, &((ip4_header_t *) vlib_buffer_get_current (b))->src_address);
    }
  else
    {
      ip46_address_set_ip6 (
	&src_ip, &((ip6_header_t *) vlib_buffer_get_current (b))->src_address);
    }

  const fib_prefix_t *allowed_ip;
  bool allowed = false;

  /*
   * we could make this into an ACL, but the expectation
   * is that there aren't many allowed IPs and thus a linear
   * walk is faster than an ACL
   */
  vec_foreach (allowed_ip, peer->allowed_ips)
    {
      if (fib_prefix_is_cover_addr_46 (allowed_ip, &src_ip))
	{
	  allowed = true;
	  break;
	}
    }
  if (allowed)
    {
      vnet_buffer (b)->sw_if_index[VLIB_RX] = peer->wg_sw_if_index;
      next[0] =
	is_ip4_inner ? WG_INPUT_NEXT_IP4_INPUT : WG_INPUT_NEXT_IP6_INPUT;
    }

  return 0;
}

static_always_inline void
wg_input_process_ops (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vnet_crypto_op_t *ops, vlib_buffer_t *b[], u16 *nexts,
		      u16 drop_next)
{
  u32 n_fail, n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

  n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 bi = op->user_data;
	  b[bi]->error = node->errors[WG_INPUT_ERROR_DECRYPTION];
	  nexts[bi] = drop_next;
	  n_fail--;
	}
      op++;
    }
}

always_inline void
wg_prepare_sync_dec_op (vlib_main_t *vm, vnet_crypto_op_t **crypto_ops,
			u8 *src, u32 src_len, u8 *dst, u8 *aad, u32 aad_len,
			vnet_crypto_key_index_t key_index, u32 bi, u8 *iv)
{
  vnet_crypto_op_t _op, *op = &_op;
  u8 src_[] = {};

  vec_add2_aligned (crypto_ops[0], op, 1, CLIB_CACHE_LINE_BYTES);
  vnet_crypto_op_init (op, VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC);

  op->tag_len = NOISE_AUTHTAG_LEN;
  op->tag = src + src_len;
  op->src = !src ? src_ : src;
  op->len = src_len;
  op->dst = dst;
  op->key_index = key_index;
  op->aad = aad;
  op->aad_len = aad_len;
  op->iv = iv;
  op->user_data = bi;
  op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
}

static_always_inline void
wg_input_add_to_frame (vlib_main_t *vm, vnet_crypto_async_frame_t *f,
		       u32 key_index, u32 crypto_len, i16 crypto_start_offset,
		       u32 buffer_index, u16 next_node, u8 *iv, u8 *tag,
		       u8 flags)
{
  vnet_crypto_async_frame_elt_t *fe;
  u16 index;

  ASSERT (f->n_elts < VNET_CRYPTO_FRAME_SIZE);

  index = f->n_elts;
  fe = &f->elts[index];
  f->n_elts++;
  fe->key_index = key_index;
  fe->crypto_total_length = crypto_len;
  fe->crypto_start_offset = crypto_start_offset;
  fe->iv = iv;
  fe->tag = tag;
  fe->flags = flags;
  f->buffer_indices[index] = buffer_index;
  f->next_node_index[index] = next_node;
}

static_always_inline enum noise_state_crypt
wg_input_process (vlib_main_t *vm, wg_per_thread_data_t *ptd,
		  vnet_crypto_op_t **crypto_ops,
		  vnet_crypto_async_frame_t **async_frame, vlib_buffer_t *b,
		  u32 buf_idx, noise_remote_t *r, uint32_t r_idx,
		  uint64_t nonce, uint8_t *src, size_t srclen, uint8_t *dst,
		  u32 from_idx, u8 *iv, f64 time, u8 is_async,
		  u16 async_next_node)
{
  noise_keypair_t *kp;
  enum noise_state_crypt ret = SC_FAILED;

  if ((kp = wg_get_active_keypair (r, r_idx)) == NULL)
    {
      goto error;
    }

  /* We confirm that our values are within our tolerances. These values
   * are the same as the encrypt routine.
   *
   * kp_ctr isn't locked here, we're happy to accept a racy read. */
  if (wg_birthdate_has_expired_opt (kp->kp_birthdate, REJECT_AFTER_TIME,
				    time) ||
      kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES)
    goto error;

  /* Decrypt, then validate the counter. We don't want to validate the
   * counter before decrypting as we do not know the message is authentic
   * prior to decryption. */

  clib_memset (iv, 0, 4);
  clib_memcpy (iv + 4, &nonce, sizeof (nonce));

  if (is_async)
    {
      if (NULL == *async_frame ||
	  vnet_crypto_async_frame_is_full (*async_frame))
	{
	  *async_frame = vnet_crypto_async_get_frame (
	    vm, VNET_CRYPTO_OP_CHACHA20_POLY1305_TAG16_AAD0_DEC);
	  /* Save the frame to the list we'll submit at the end */
	  vec_add1 (ptd->async_frames, *async_frame);
	}

      wg_input_add_to_frame (vm, *async_frame, kp->kp_recv_index, srclen,
			     src - b->data, buf_idx, async_next_node, iv,
			     src + srclen, VNET_CRYPTO_OP_FLAG_HMAC_CHECK);
    }
  else
    {
      wg_prepare_sync_dec_op (vm, crypto_ops, src, srclen, dst, NULL, 0,
			      kp->kp_recv_index, from_idx, iv);
    }

  /* If we've received the handshake confirming data packet then move the
   * next keypair into current. If we do slide the next keypair in, then
   * we skip the REKEY_AFTER_TIME_RECV check. This is safe to do as a
   * data packet can't confirm a session that we are an INITIATOR of. */
  if (kp == r->r_next)
    {
      clib_rwlock_writer_lock (&r->r_keypair_lock);
      if (kp == r->r_next && kp->kp_local_index == r_idx)
	{
	  noise_remote_keypair_free (vm, r, &r->r_previous);
	  r->r_previous = r->r_current;
	  r->r_current = r->r_next;
	  r->r_next = NULL;

	  ret = SC_CONN_RESET;
	  clib_rwlock_writer_unlock (&r->r_keypair_lock);
	  goto error;
	}
      clib_rwlock_writer_unlock (&r->r_keypair_lock);
    }

  /* Similar to when we encrypt, we want to notify the caller when we
   * are approaching our tolerances. We notify if:
   *  - we're the initiator and the current keypair is older than
   *    REKEY_AFTER_TIME_RECV seconds. */
  ret = SC_KEEP_KEY_FRESH;
  kp = r->r_current;
  if (kp != NULL && kp->kp_valid && kp->kp_is_initiator &&
      wg_birthdate_has_expired_opt (kp->kp_birthdate, REKEY_AFTER_TIME_RECV,
				    time))
    goto error;

  ret = SC_OK;
error:
  return ret;
}

>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)
always_inline uword
wg_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vlib_frame_t *frame, u8 is_ip4, u16 async_next_node)
{
  message_type_t header_type;
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
  u32 n_left_from;
  u32 *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  b = bufs;
  next = nexts;
=======
  vlib_buffer_t *data_bufs[VLIB_FRAME_SIZE];
  u32 data_bi[VLIB_FRAME_SIZE];	 /* buffer index for data */
  u32 other_bi[VLIB_FRAME_SIZE]; /* buffer index for drop or handoff */
  u16 other_nexts[VLIB_FRAME_SIZE], *other_next = other_nexts, n_other = 0;
  u16 data_nexts[VLIB_FRAME_SIZE], *data_next = data_nexts, n_data = 0;
  u16 n_async = 0;
  const u8 is_async = wg_op_mode_is_set_ASYNC ();
  vnet_crypto_async_frame_t *async_frame = NULL;
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)

  vlib_get_buffers (vm, from, bufs, n_left_from);
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->async_frames);
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)

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
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)

=======
	  u8 *iv_data = b[0]->pre_data;
	  u32 buf_idx = from[b - bufs];
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)
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
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
	      other_bi[n_other] = buf_idx;
	      n_other += 1;
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)
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
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
	      next[0] = WG_INPUT_NEXT_HANDOFF_DATA;
=======
	      other_next[n_other] = WG_INPUT_NEXT_HANDOFF_DATA;
	      other_bi[n_other] = buf_idx;
	      n_other += 1;
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)
	      goto next;
	    }

	  u16 encr_len = b[0]->current_length - sizeof (message_data_t);
	  u16 decr_len = encr_len - NOISE_AUTHTAG_LEN;
	  if (PREDICT_FALSE (decr_len >= WG_DEFAULT_DATA_SIZE))
	    {
	      b[0]->error = node->errors[WG_INPUT_ERROR_TOO_BIG];
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
	      other_bi[n_other] = buf_idx;
	      n_other += 1;
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)
	      goto out;
	    }

<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
	  enum noise_state_crypt state_cr = noise_remote_decrypt (
	    vm, &peer->remote, data->receiver_index, data->counter,
	    data->encrypted_data, encr_len, data->encrypted_data);
=======
	  enum noise_state_crypt state_cr = wg_input_process (
	    vm, ptd, crypto_ops, &async_frame, b[0], buf_idx, &peer->remote,
	    data->receiver_index, data->counter, data->encrypted_data,
	    decr_len, data->encrypted_data, n_data, iv_data, time, is_async,
	    async_next_node);

	  if (PREDICT_FALSE (state_cr == SC_FAILED))
	    {
	      wg_peer_update_flags (*peer_idx, WG_PEER_ESTABLISHED, false);
	      other_next[n_other] = WG_INPUT_NEXT_ERROR;
	      b[0]->error = node->errors[WG_INPUT_ERROR_DECRYPTION];
	      other_bi[n_other] = buf_idx;
	      n_other += 1;
	      goto out;
	    }
	  if (!is_async)
	    {
	      data_bufs[n_data] = b[0];
	      data_bi[n_data] = buf_idx;
	      n_data += 1;
	    }
	  else
	    {
	      n_async += 1;
	    }
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)

	  if (PREDICT_FALSE (state_cr == SC_CONN_RESET))
	    {
	      wg_timers_handshake_complete (peer);
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
	      goto next;
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)
	    }
	  else if (PREDICT_FALSE (state_cr == SC_KEEP_KEY_FRESH))
	    {
	      wg_send_handshake_from_mt (*peer_idx, false);
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
	      goto next;
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)
	    }
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
	  else if (PREDICT_FALSE (state_cr == SC_FAILED))
	    {
	      wg_peer_update_flags (*peer_idx, WG_PEER_ESTABLISHED, false);
	      next[0] = WG_INPUT_NEXT_ERROR;
	      b[0]->error = node->errors[WG_INPUT_ERROR_DECRYPTION];
	      goto out;
	    }

	  vlib_buffer_advance (b[0], sizeof (message_data_t));
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

	  ip46_address_t src_ip;
	  u8 is_ip4_inner = is_ip4_header (vlib_buffer_get_current (b[0]));
	  if (is_ip4_inner)
	    {
	      ip46_address_set_ip4 (
		&src_ip, &((ip4_header_t *) vlib_buffer_get_current (b[0]))
			    ->src_address);
	    }
	  else
	    {
	      ip46_address_set_ip6 (
		&src_ip, &((ip6_header_t *) vlib_buffer_get_current (b[0]))
			    ->src_address);
	    }

	  const fib_prefix_t *allowed_ip;
	  bool allowed = false;

	  /*
	   * we could make this into an ACL, but the expectation
	   * is that there aren't many allowed IPs and thus a linear
	   * walk is fater than an ACL
	   */

	  vec_foreach (allowed_ip, peer->allowed_ips)
	  {
	    if (fib_prefix_is_cover_addr_46 (allowed_ip, &src_ip))
	      {
		allowed = true;
		break;
	      }
	  }
	  if (allowed)
	    {
	      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = peer->wg_sw_if_index;
	      next[0] = is_ip4_inner ? WG_INPUT_NEXT_IP4_INPUT :
				       WG_INPUT_NEXT_IP6_INPUT;
	    }
=======
	  else if (PREDICT_TRUE (state_cr == SC_OK))
	    goto next;
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)
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

	  wg_input_error_t ret =
	    wg_handshake_process (vm, wmp, b[0], node->node_index, is_ip4);
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
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
=======

  /* decrypt packets */
  wg_input_process_ops (vm, node, ptd->crypto_ops, data_bufs, data_nexts,
			drop_next);

  /* process after decryption */
  b = data_bufs;
  n_left_from = n_data;
  last_rec_idx = ~0;
  last_peer_time_idx = NULL;

  while (n_left_from > 0)
    {
      bool is_keepalive = false;
      u32 *peer_idx = NULL;

      if (PREDICT_FALSE (data_next[0] == WG_INPUT_NEXT_PUNT))
	{
	  goto trace;
	}
      if (n_left_from > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (vlib_buffer_get_tail (b[1]), CLIB_CACHE_LINE_BYTES,
			 LOAD);
	}

      message_data_t *data = vlib_buffer_get_current (b[0]);

      if (data->receiver_index != last_rec_idx)
	{
	  peer_idx =
	    wg_index_table_lookup (&wmp->index_table, data->receiver_index);
	  peer = wg_peer_get (*peer_idx);
	  last_rec_idx = data->receiver_index;
	}

      if (PREDICT_FALSE (wg_input_post_process (vm, b[0], data_next, peer,
						data, &is_keepalive) < 0))
	goto trace;

      if (PREDICT_FALSE (peer_idx && (last_peer_time_idx != peer_idx)))
	{
	  wg_timers_any_authenticated_packet_received_opt (peer, time);
	  wg_timers_any_authenticated_packet_traversal (peer);
	  last_peer_time_idx = peer_idx;
	}

    trace:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_input_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->type = header_type;
	  t->current_length = b[0]->current_length;
	  t->is_keepalive = is_keepalive;
	  t->peer = peer_idx ? *peer_idx : INDEX_INVALID;
	}

      b += 1;
      n_left_from -= 1;
      data_next += 1;
    }

  if (n_async)
    {
      /* submit all of the open frames */
      vnet_crypto_async_frame_t **async_frame;
      vec_foreach (async_frame, ptd->async_frames)
	{
	  if (PREDICT_FALSE (
		vnet_crypto_async_submit_open_frame (vm, *async_frame) < 0))
	    {
	      u32 n_drop = (*async_frame)->n_elts;
	      u32 *bi = (*async_frame)->buffer_indices;
	      u16 index = n_other;
	      while (n_drop--)
		{
		  other_bi[index] = bi[0];
		  vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
		  other_nexts[index] = drop_next;
		  b->error = node->errors[WG_INPUT_ERROR_CRYPTO_ENGINE_ERROR];
		  bi++;
		  index++;
		}
	      n_other += (*async_frame)->n_elts;

	      vnet_crypto_async_reset_frame (*async_frame);
	      vnet_crypto_async_free_frame (vm, *async_frame);
	    }
	}
    }

  /* enqueue other bufs */
  if (n_other)
    vlib_buffer_enqueue_to_next (vm, node, other_bi, other_next, n_other);

  /* enqueue data bufs */
  if (n_data)
    vlib_buffer_enqueue_to_next (vm, node, data_bi, data_nexts, n_data);
>>>>>>> CHANGE (77e69a wireguard: add async mode for decryption packets)

  return frame->n_vectors;
}

always_inline uword
wg_input_post (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  wg_main_t *wmp = &wg_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  wg_peer_t *peer = NULL;
  u32 *peer_idx = NULL;
  u32 *last_peer_time_idx = NULL;
  u32 last_rec_idx = ~0;
  f64 time = clib_time_now (&vm->clib_time) + vm->time_offset;

  vlib_get_buffers (vm, from, b, n_left);

  if (n_left >= 2)
    {
      vlib_prefetch_buffer_header (b[0], LOAD);
      vlib_prefetch_buffer_header (b[1], LOAD);
    }

  while (n_left > 0)
    {
      if (n_left > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      bool is_keepalive = false;
      message_data_t *data = vlib_buffer_get_current (b[0]);

      if (data->receiver_index != last_rec_idx)
	{
	  peer_idx =
	    wg_index_table_lookup (&wmp->index_table, data->receiver_index);

	  peer = wg_peer_get (*peer_idx);
	  last_rec_idx = data->receiver_index;
	}

      if (PREDICT_FALSE (wg_input_post_process (vm, b[0], next, peer, data,
						&is_keepalive) < 0))
	goto trace;

      if (PREDICT_FALSE (peer_idx && (last_peer_time_idx != peer_idx)))
	{
	  wg_timers_any_authenticated_packet_received_opt (peer, time);
	  wg_timers_any_authenticated_packet_traversal (peer);
	  last_peer_time_idx = peer_idx;
	}
    trace:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_input_post_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next = next[0];
	  t->peer = peer_idx ? *peer_idx : INDEX_INVALID;
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (wg4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return wg_input_inline (vm, node, frame, /* is_ip4 */ 1,
			  wg_decrypt_async_next.wg4_post_next);
}

VLIB_NODE_FN (wg6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return wg_input_inline (vm, node, frame, /* is_ip4 */ 0,
			  wg_decrypt_async_next.wg6_post_next);
}

VLIB_NODE_FN (wg4_input_post_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return wg_input_post (vm, node, from_frame);
}

VLIB_NODE_FN (wg6_input_post_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return wg_input_post (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (wg4_input_node) =
{
  .name = "wg4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_input_error_strings),
  .error_strings = wg_input_error_strings,
  .n_next_nodes = WG_INPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
        [WG_INPUT_NEXT_HANDOFF_HANDSHAKE] = "wg4-handshake-handoff",
        [WG_INPUT_NEXT_HANDOFF_DATA] = "wg4-input-data-handoff",
        [WG_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [WG_INPUT_NEXT_IP6_INPUT] = "ip6-input",
        [WG_INPUT_NEXT_PUNT] = "error-punt",
        [WG_INPUT_NEXT_ERROR] = "error-drop",
  },
};

VLIB_REGISTER_NODE (wg6_input_node) =
{
  .name = "wg6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_input_error_strings),
  .error_strings = wg_input_error_strings,
  .n_next_nodes = WG_INPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
        [WG_INPUT_NEXT_HANDOFF_HANDSHAKE] = "wg6-handshake-handoff",
        [WG_INPUT_NEXT_HANDOFF_DATA] = "wg6-input-data-handoff",
        [WG_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [WG_INPUT_NEXT_IP6_INPUT] = "ip6-input",
        [WG_INPUT_NEXT_PUNT] = "error-punt",
        [WG_INPUT_NEXT_ERROR] = "error-drop",
  },
};

VLIB_REGISTER_NODE (wg4_input_post_node) = {
  .name = "wg4-input-post-node",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_input_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "wg4-input",

  .n_errors = ARRAY_LEN (wg_input_error_strings),
  .error_strings = wg_input_error_strings,
};

VLIB_REGISTER_NODE (wg6_input_post_node) = {
  .name = "wg6-input-post-node",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_input_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "wg6-input",

  .n_errors = ARRAY_LEN (wg_input_error_strings),
  .error_strings = wg_input_error_strings,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
