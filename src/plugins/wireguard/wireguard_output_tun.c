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

#define foreach_wg_output_error                                               \
  _ (NONE, "No error")                                                        \
  _ (PEER, "Peer error")                                                      \
  _ (KEYPAIR, "Keypair error")                                                \
  _ (TOO_BIG, "packet too big")                                               \
  _ (CRYPTO_ENGINE_ERROR, "crypto engine error (packet dropped)")

typedef enum
{
#define _(sym,str) WG_OUTPUT_ERROR_##sym,
  foreach_wg_output_error
#undef _
    WG_OUTPUT_N_ERROR,
} wg_output_error_t;

static char *wg_output_error_strings[] = {
#define _(sym,string) string,
  foreach_wg_output_error
#undef _
};

typedef enum
{
  WG_OUTPUT_NEXT_ERROR,
  WG_OUTPUT_NEXT_HANDOFF,
  WG_OUTPUT_NEXT_INTERFACE_OUTPUT,
  WG_OUTPUT_N_NEXT,
} wg_output_next_t;

typedef struct
{
  index_t peer;
  u8 header[sizeof (ip6_udp_header_t)];
  u8 is_ip4;
} wg_output_tun_trace_t;

typedef struct
{
  index_t peer;
  u32 next_index;
} wg_output_tun_post_trace_t;

u8 *
format_ip4_udp_header (u8 * s, va_list * args)
{
  ip4_udp_header_t *hdr4 = va_arg (*args, ip4_udp_header_t *);

  s = format (s, "%U:$U", format_ip4_header, &hdr4->ip4, format_udp_header,
	      &hdr4->udp);
  return (s);
}

u8 *
format_ip6_udp_header (u8 *s, va_list *args)
{
  ip6_udp_header_t *hdr6 = va_arg (*args, ip6_udp_header_t *);

  s = format (s, "%U:$U", format_ip6_header, &hdr6->ip6, format_udp_header,
	      &hdr6->udp);
  return (s);
}

/* packet trace format function */
static u8 *
format_wg_output_tun_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  wg_output_tun_trace_t *t = va_arg (*args, wg_output_tun_trace_t *);

  s = format (s, "peer: %d\n", t->peer);
  s = format (s, "  Encrypted packet: ");

  s = t->is_ip4 ? format (s, "%U", format_ip4_udp_header, t->header) :
		  format (s, "%U", format_ip6_udp_header, t->header);
  return s;
}

<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
/* post node - packet trace format function */
static u8 *
format_wg_output_tun_post_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  wg_output_tun_post_trace_t *t = va_arg (*args, wg_output_tun_post_trace_t *);

  s = format (s, "peer: %d\n", t->peer);
  s = format (s, "  wg-post: next node index %u", t->next_index);
  return s;
}

static_always_inline void
wg_prepare_sync_enc_op (vlib_main_t *vm, vnet_crypto_op_t **crypto_ops,
			u8 *src, u32 src_len, u8 *dst, u8 *aad, u32 aad_len,
			u64 nonce, vnet_crypto_key_index_t key_index, u32 bi,
			u8 *iv)
{
  vnet_crypto_op_t _op, *op = &_op;
  u8 src_[] = {};

  clib_memset (iv, 0, 4);
  clib_memcpy (iv + 4, &nonce, sizeof (nonce));

  vec_add2_aligned (crypto_ops[0], op, 1, CLIB_CACHE_LINE_BYTES);
  vnet_crypto_op_init (op, VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC);

  op->tag_len = NOISE_AUTHTAG_LEN;
  op->tag = dst + src_len;
  op->src = !src ? src_ : src;
  op->len = src_len;
  op->dst = dst;
  op->key_index = key_index;
  op->aad = aad;
  op->aad_len = aad_len;
  op->iv = iv;
  op->user_data = bi;
}

static_always_inline void
wg_output_process_ops (vlib_main_t *vm, vlib_node_runtime_t *node,
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
	  b[bi]->error = node->errors[WG_OUTPUT_ERROR_KEYPAIR];
	  nexts[bi] = drop_next;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline void
wg_output_tun_add_to_frame (vlib_main_t *vm, vnet_crypto_async_frame_t *f,
			    u32 key_index, u32 crypto_len,
			    i16 crypto_start_offset, u32 buffer_index,
			    u16 next_node, u8 *iv, u8 *tag, u8 flags)
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
wq_output_tun_process (vlib_main_t *vm, vnet_crypto_op_t **crypto_ops,
		       noise_remote_t *r, uint32_t *r_idx, uint64_t *nonce,
		       uint8_t *src, size_t srclen, uint8_t *dst, u32 bi,
		       u8 *iv, f64 time)
{
  noise_keypair_t *kp;
  enum noise_state_crypt ret = SC_FAILED;

  if ((kp = r->r_current) == NULL)
    goto error;

  /* We confirm that our values are within our tolerances. We want:
   *  - a valid keypair
   *  - our keypair to be less than REJECT_AFTER_TIME seconds old
   *  - our receive counter to be less than REJECT_AFTER_MESSAGES
   *  - our send counter to be less than REJECT_AFTER_MESSAGES
   */
  if (!kp->kp_valid ||
      wg_birthdate_has_expired_opt (kp->kp_birthdate, REJECT_AFTER_TIME,
				    time) ||
      kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
      ((*nonce = noise_counter_send (&kp->kp_ctr)) > REJECT_AFTER_MESSAGES))
    goto error;

  /* We encrypt into the same buffer, so the caller must ensure that buf
   * has NOISE_AUTHTAG_LEN bytes to store the MAC. The nonce and index
   * are passed back out to the caller through the provided data pointer. */
  *r_idx = kp->kp_remote_index;

  wg_prepare_sync_enc_op (vm, crypto_ops, src, srclen, dst, NULL, 0, *nonce,
			  kp->kp_send_index, bi, iv);

  /* If our values are still within tolerances, but we are approaching
   * the tolerances, we notify the caller with ESTALE that they should
   * establish a new keypair. The current keypair can continue to be used
   * until the tolerances are hit. We notify if:
   *  - our send counter is valid and not less than REKEY_AFTER_MESSAGES
   *  - we're the initiator and our keypair is older than
   *    REKEY_AFTER_TIME seconds */
  ret = SC_KEEP_KEY_FRESH;
  if ((kp->kp_valid && *nonce >= REKEY_AFTER_MESSAGES) ||
      (kp->kp_is_initiator && wg_birthdate_has_expired_opt (
				kp->kp_birthdate, REKEY_AFTER_TIME, time)))
    goto error;

  ret = SC_OK;
error:
  return ret;
}

static_always_inline enum noise_state_crypt
wg_add_to_async_frame (vlib_main_t *vm, wg_per_thread_data_t *ptd,
		       vnet_crypto_async_frame_t *async_frame,
		       vlib_buffer_t *b, u8 *payload, u32 payload_len, u32 bi,
		       u16 next, u16 async_next, noise_remote_t *r,
		       uint32_t *r_idx, uint64_t *nonce, u8 *iv, f64 time)
{
  wg_post_data_t *post = wg_post_data (b);
  u8 flag = 0;
  noise_keypair_t *kp;

  post->next_index = next;

  /* crypto */
  enum noise_state_crypt ret = SC_FAILED;

  if ((kp = r->r_current) == NULL)
    goto error;

  /* We confirm that our values are within our tolerances. We want:
   *  - a valid keypair
   *  - our keypair to be less than REJECT_AFTER_TIME seconds old
   *  - our receive counter to be less than REJECT_AFTER_MESSAGES
   *  - our send counter to be less than REJECT_AFTER_MESSAGES
   */
  if (!kp->kp_valid ||
      wg_birthdate_has_expired_opt (kp->kp_birthdate, REJECT_AFTER_TIME,
				    time) ||
      kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
      ((*nonce = noise_counter_send (&kp->kp_ctr)) > REJECT_AFTER_MESSAGES))
    goto error;

  /* We encrypt into the same buffer, so the caller must ensure that buf
   * has NOISE_AUTHTAG_LEN bytes to store the MAC. The nonce and index
   * are passed back out to the caller through the provided data pointer. */
  *r_idx = kp->kp_remote_index;

  clib_memset (iv, 0, 4);
  clib_memcpy (iv + 4, nonce, sizeof (nonce));

  /* this always succeeds because we know the frame is not full */
  wg_output_tun_add_to_frame (vm, async_frame, kp->kp_send_index, payload_len,
			      payload - b->data, bi, async_next, iv,
			      payload + payload_len, flag);

  /* If our values are still within tolerances, but we are approaching
   * the tolerances, we notify the caller with ESTALE that they should
   * establish a new keypair. The current keypair can continue to be used
   * until the tolerances are hit. We notify if:
   *  - our send counter is valid and not less than REKEY_AFTER_MESSAGES
   *  - we're the initiator and our keypair is older than
   *    REKEY_AFTER_TIME seconds */
  ret = SC_KEEP_KEY_FRESH;
  if ((kp->kp_valid && *nonce >= REKEY_AFTER_MESSAGES) ||
      (kp->kp_is_initiator && wg_birthdate_has_expired_opt (
				kp->kp_birthdate, REKEY_AFTER_TIME, time)))
    goto error;

  ret = SC_OK;
error:
  return ret;
}

>>>>>>> CHANGE (492d77 wireguard: add async mode for encryption packets)
/* is_ip4 - inner header flag */
always_inline uword
wg_output_tun_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, u8 is_ip4, u16 async_next_node)
{
  u32 n_left_from;
  u32 *from;
  ip4_udp_wg_header_t *hdr4_out = NULL;
  ip6_udp_wg_header_t *hdr6_out = NULL;
  message_data_t *message_data_wg = NULL;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 thread_index = vm->thread_index;
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  b = bufs;
  next = nexts;
=======
  u16 n_sync = 0;
  const u16 drop_next = WG_OUTPUT_NEXT_ERROR;
  const u8 is_async = wg_op_mode_is_set_ASYNC ();
  vnet_crypto_async_frame_t *async_frame = NULL;
  u16 n_async = 0;
  u16 noop_nexts[VLIB_FRAME_SIZE], *noop_next = noop_nexts, n_noop = 0;
  u16 err = !0;
  u32 sync_bi[VLIB_FRAME_SIZE];
  u32 noop_bi[VLIB_FRAME_SIZE];
>>>>>>> CHANGE (492d77 wireguard: add async mode for encryption packets)

  vlib_get_buffers (vm, from, bufs, n_left_from);
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->async_frames);
>>>>>>> CHANGE (492d77 wireguard: add async mode for encryption packets)

  wg_peer_t *peer = NULL;

  while (n_left_from > 0)
    {
      index_t peeri;
      u8 iph_offset = 0;
      u8 is_ip4_out = 1;
      u8 *plain_data;
      u16 plain_data_len;

      if (n_left_from > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	}

<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
      next[0] = WG_OUTPUT_NEXT_ERROR;
      peeri =
	wg_peer_get_by_adj_index (vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);
      peer = wg_peer_get (peeri);
=======
      noop_next[0] = WG_OUTPUT_NEXT_ERROR;
      err = WG_OUTPUT_NEXT_ERROR;
>>>>>>> CHANGE (492d77 wireguard: add async mode for encryption packets)

      if (wg_peer_is_dead (peer))
	{
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_PEER];
	  goto out;
	}
      if (PREDICT_FALSE (~0 == peer->output_thread_index))
	{
	  /* this is the first packet to use this peer, claim the peer
	   * for this thread.
	   */
	  clib_atomic_cmp_and_swap (&peer->output_thread_index, ~0,
				    wg_peer_assign_thread (thread_index));
	}

      if (PREDICT_FALSE (thread_index != peer->output_thread_index))
	{
	  noop_next[0] = WG_OUTPUT_NEXT_HANDOFF;
	  err = WG_OUTPUT_NEXT_HANDOFF;
	  goto next;
	}

      if (PREDICT_FALSE (!peer->remote.r_current))
	{
	  wg_send_handshake_from_mt (peeri, false);
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_KEYPAIR];
	  goto out;
	}

      is_ip4_out = ip46_address_is_ip4 (&peer->src.addr);
      if (is_ip4_out)
	{
	  hdr4_out = vlib_buffer_get_current (b[0]);
	  message_data_wg = &hdr4_out->wg;
	}
      else
	{
	  hdr6_out = vlib_buffer_get_current (b[0]);
	  message_data_wg = &hdr6_out->wg;
	}

      iph_offset = vnet_buffer (b[0])->ip.save_rewrite_length;
      plain_data = vlib_buffer_get_current (b[0]) + iph_offset;
      plain_data_len = vlib_buffer_length_in_chain (vm, b[0]) - iph_offset;

      size_t encrypted_packet_len = message_data_len (plain_data_len);

      /*
       * Ensure there is enough space to write the encrypted data
       * into the packet
       */
      if (PREDICT_FALSE (encrypted_packet_len >= WG_DEFAULT_DATA_SIZE) ||
	  PREDICT_FALSE ((b[0]->current_data + encrypted_packet_len) >=
			 vlib_buffer_get_default_data_size (vm)))
	{
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_TOO_BIG];
	  goto out;
	}

<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
      if (PREDICT_FALSE (last_adj_index != adj_index))
	{
	  wg_timers_any_authenticated_packet_sent_opt (peer, time);
	  wg_timers_data_sent_opt (peer, time);
	  wg_timers_any_authenticated_packet_traversal (peer);
	  last_adj_index = adj_index;
	}

      /* Here we are sure that can send packet to next node */
      next[0] = WG_OUTPUT_NEXT_INTERFACE_OUTPUT;

>>>>>>> CHANGE (492d77 wireguard: add async mode for encryption packets)
      enum noise_state_crypt state;

<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
      state = noise_remote_encrypt (
	vm, &peer->remote, &message_data_wg->receiver_index,
	&message_data_wg->counter, plain_data, plain_data_len, plain_data);
=======
      if (is_async)
	{
	  /* get a frame for this op if we don't yet have one or it's full  */
	  if (NULL == async_frame ||
	      vnet_crypto_async_frame_is_full (async_frame))
	    {
	      async_frame = vnet_crypto_async_get_frame (
		vm, VNET_CRYPTO_OP_CHACHA20_POLY1305_TAG16_AAD0_ENC);
	      /* Save the frame to the list we'll submit at the end */
	      vec_add1 (ptd->async_frames, async_frame);
	    }
	  state = wg_add_to_async_frame (
	    vm, ptd, async_frame, b[0], plain_data, plain_data_len,
	    from[b - bufs], next[0], async_next_node, &peer->remote,
	    &message_data_wg->receiver_index, &message_data_wg->counter,
	    iv_data, time);
	}
      else
	{
	  state = wq_output_tun_process (
	    vm, crypto_ops, &peer->remote, &message_data_wg->receiver_index,
	    &message_data_wg->counter, plain_data, plain_data_len, plain_data,
	    n_sync, iv_data, time);
	}
>>>>>>> CHANGE (492d77 wireguard: add async mode for encryption packets)

      if (PREDICT_FALSE (state == SC_KEEP_KEY_FRESH))
	{
	  wg_send_handshake_from_mt (peeri, false);
	}
      else if (PREDICT_FALSE (state == SC_FAILED))
	{
	  //TODO: Maybe wrong
	  wg_send_handshake_from_mt (peeri, false);
	  wg_peer_update_flags (peeri, WG_PEER_ESTABLISHED, false);
	  noop_next[0] = WG_OUTPUT_NEXT_ERROR;
	  goto out;
	}

      err = WG_OUTPUT_NEXT_INTERFACE_OUTPUT;

      if (is_ip4_out)
	{
	  hdr4_out->wg.header.type = MESSAGE_DATA;
	  hdr4_out->udp.length = clib_host_to_net_u16 (encrypted_packet_len +
						       sizeof (udp_header_t));
	  b[0]->current_length =
	    (encrypted_packet_len + sizeof (ip4_udp_header_t));
	  ip4_header_set_len_w_chksum (
	    &hdr4_out->ip4, clib_host_to_net_u16 (b[0]->current_length));
	}
      else
	{
	  hdr6_out->wg.header.type = MESSAGE_DATA;
	  hdr6_out->udp.length = clib_host_to_net_u16 (encrypted_packet_len +
						       sizeof (udp_header_t));
	  b[0]->current_length =
	    (encrypted_packet_len + sizeof (ip6_udp_header_t));
	  hdr6_out->ip6.payload_length =
	    clib_host_to_net_u16 (b[0]->current_length);
	}

      wg_timers_any_authenticated_packet_sent (peer);
      wg_timers_data_sent (peer);
      wg_timers_any_authenticated_packet_traversal (peer);

    out:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_output_tun_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));

	  t->peer = peeri;
	  t->is_ip4 = is_ip4_out;
	  if (hdr4_out)
	    clib_memcpy (t->header, hdr4_out, sizeof (ip4_udp_header_t));
	  else if (hdr6_out)
	    clib_memcpy (t->header, hdr6_out, sizeof (ip6_udp_header_t));
	}

    next:
<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
=======
      if (PREDICT_FALSE (err != WG_OUTPUT_NEXT_INTERFACE_OUTPUT))
	{
	  noop_bi[n_noop] = from[b - bufs];
	  n_noop++;
	  noop_next++;
	  goto next_left;
	}
      if (!is_async)
	{
	  sync_bi[n_sync] = from[b - bufs];
	  sync_bufs[n_sync] = b[0];
	  n_sync += 1;
	  next += 1;
	}
      else
	{
	  n_async++;
	}
    next_left:
>>>>>>> CHANGE (492d77 wireguard: add async mode for encryption packets)
      n_left_from -= 1;
      b += 1;
    }

<<<<<<< HEAD   (93e5be misc: Initial changes for stable/2202 branch)
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
=======
  if (n_sync)
    {
      /* wg-output-process-ops */
      wg_output_process_ops (vm, node, ptd->crypto_ops, sync_bufs, nexts,
			     drop_next);
      vlib_buffer_enqueue_to_next (vm, node, sync_bi, nexts, n_sync);
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
	      u16 index = n_noop;
	      while (n_drop--)
		{
		  noop_bi[index] = bi[0];
		  vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
		  noop_nexts[index] = drop_next;
		  b->error = node->errors[WG_OUTPUT_ERROR_CRYPTO_ENGINE_ERROR];
		  bi++;
		  index++;
		}
	      n_noop += (*async_frame)->n_elts;

	      vnet_crypto_async_reset_frame (*async_frame);
	      vnet_crypto_async_free_frame (vm, *async_frame);
	    }
	}
    }
  if (n_noop)
    {
      vlib_buffer_enqueue_to_next (vm, node, noop_bi, noop_nexts, n_noop);
    }

>>>>>>> CHANGE (492d77 wireguard: add async mode for encryption packets)
  return frame->n_vectors;
}

always_inline uword
wg_output_tun_post (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  index_t peeri = ~0;

  vlib_get_buffers (vm, from, b, n_left);

  if (n_left >= 4)
    {
      vlib_prefetch_buffer_header (b[0], LOAD);
      vlib_prefetch_buffer_header (b[1], LOAD);
      vlib_prefetch_buffer_header (b[2], LOAD);
      vlib_prefetch_buffer_header (b[3], LOAD);
    }

  while (n_left > 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      next[0] = (wg_post_data (b[0]))->next_index;
      next[1] = (wg_post_data (b[1]))->next_index;
      next[2] = (wg_post_data (b[2]))->next_index;
      next[3] = (wg_post_data (b[3]))->next_index;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      wg_output_tun_post_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      peeri = wg_peer_get_by_adj_index (
		vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);
	      tr->peer = peeri;
	      tr->next_index = next[0];
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      wg_output_tun_post_trace_t *tr =
		vlib_add_trace (vm, node, b[1], sizeof (*tr));
	      peeri = wg_peer_get_by_adj_index (
		vnet_buffer (b[1])->ip.adj_index[VLIB_TX]);
	      tr->next_index = next[1];
	    }
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      wg_output_tun_post_trace_t *tr =
		vlib_add_trace (vm, node, b[2], sizeof (*tr));
	      peeri = wg_peer_get_by_adj_index (
		vnet_buffer (b[2])->ip.adj_index[VLIB_TX]);
	      tr->next_index = next[2];
	    }
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      wg_output_tun_post_trace_t *tr =
		vlib_add_trace (vm, node, b[3], sizeof (*tr));
	      peeri = wg_peer_get_by_adj_index (
		vnet_buffer (b[3])->ip.adj_index[VLIB_TX]);
	      tr->next_index = next[3];
	    }
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      next[0] = (wg_post_data (b[0]))->next_index;
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_output_tun_post_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  peeri = wg_peer_get_by_adj_index (
	    vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);
	  tr->next_index = next[0];
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (wg4_output_tun_post_node) = {
  .name = "wg4-output-tun-post-node",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_output_tun_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "wg4-output-tun",
  .n_errors = ARRAY_LEN (wg_output_error_strings),
  .error_strings = wg_output_error_strings,
};

VLIB_REGISTER_NODE (wg6_output_tun_post_node) = {
  .name = "wg6-output-tun-post-node",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_output_tun_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "wg6-output-tun",
  .n_errors = ARRAY_LEN (wg_output_error_strings),
  .error_strings = wg_output_error_strings,
};

VLIB_NODE_FN (wg4_output_tun_post_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return wg_output_tun_post (vm, node, from_frame);
}

VLIB_NODE_FN (wg6_output_tun_post_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return wg_output_tun_post (vm, node, from_frame);
}

VLIB_NODE_FN (wg4_output_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return wg_output_tun_inline (vm, node, frame, /* is_ip4 */ 1,
			       wg_encrypt_async_next.wg4_post_next);
}

VLIB_NODE_FN (wg6_output_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return wg_output_tun_inline (vm, node, frame, /* is_ip4 */ 0,
			       wg_encrypt_async_next.wg6_post_next);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (wg4_output_tun_node) =
{
  .name = "wg4-output-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_output_tun_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_output_error_strings),
  .error_strings = wg_output_error_strings,
  .n_next_nodes = WG_OUTPUT_N_NEXT,
  .next_nodes = {
        [WG_OUTPUT_NEXT_HANDOFF] = "wg4-output-tun-handoff",
        [WG_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
        [WG_OUTPUT_NEXT_ERROR] = "error-drop",
  },
};

VLIB_REGISTER_NODE (wg6_output_tun_node) =
{
  .name = "wg6-output-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_output_tun_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_output_error_strings),
  .error_strings = wg_output_error_strings,
  .n_next_nodes = WG_OUTPUT_N_NEXT,
  .next_nodes = {
        [WG_OUTPUT_NEXT_HANDOFF] = "wg6-output-tun-handoff",
        [WG_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
        [WG_OUTPUT_NEXT_ERROR] = "error-drop",
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
