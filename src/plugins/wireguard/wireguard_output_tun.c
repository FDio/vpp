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

#define foreach_wg_output_error                                         \
 _(NONE, "No error")							\
 _(PEER, "Peer error")                                                  \
 _(KEYPAIR, "Keypair error")                                            \
 _(TOO_BIG, "packet too big")                                           \

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

/* is_ip4 - inner header flag */
always_inline uword
wg_output_tun_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, u8 is_ip4)
{
  wg_main_t *wmp = &wg_main;
  wg_per_thread_data_t *ptd =
    vec_elt_at_index (wmp->per_thread_data, vm->thread_index);
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;
  ip4_udp_wg_header_t *hdr4_out = NULL;
  ip6_udp_wg_header_t *hdr6_out = NULL;
  message_data_t *message_data_wg = NULL;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vnet_crypto_op_t **crypto_ops = &ptd->crypto_ops;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_buffer_t *sync_bufs[VLIB_FRAME_SIZE];
  u32 thread_index = vm->thread_index;
  u16 sync_nexts[VLIB_FRAME_SIZE], *sync_next = sync_nexts, n_sync = 0;
  u16 drop_next = WG_OUTPUT_NEXT_ERROR;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  vec_reset_length (ptd->crypto_ops);

  wg_peer_t *peer = NULL;
  u32 adj_index = 0;
  u32 last_adj_index = ~0;
  index_t peeri = INDEX_INVALID;

  f64 time = clib_time_now (&vm->clib_time) + vm->time_offset;

  while (n_left_from > 0)
    {
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
	  CLIB_PREFETCH (vlib_buffer_get_tail (b[1]), CLIB_CACHE_LINE_BYTES,
			 LOAD);
	}

      next[0] = WG_OUTPUT_NEXT_ERROR;

      adj_index = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];

      if (PREDICT_FALSE (last_adj_index != adj_index))
	{
	  peeri = wg_peer_get_by_adj_index (adj_index);
	  peer = wg_peer_get (peeri);
	}

      if (!peer || wg_peer_is_dead (peer))
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

      if (PREDICT_TRUE (thread_index != peer->output_thread_index))
	{
	  next[0] = WG_OUTPUT_NEXT_HANDOFF;
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
      u8 *iv_data = b[0]->pre_data;

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

      if (PREDICT_FALSE (last_adj_index != adj_index))
	{
	  wg_timers_any_authenticated_packet_sent_opt (peer, time);
	  wg_timers_data_sent_opt (peer, time);
	  wg_timers_any_authenticated_packet_traversal (peer);
	  last_adj_index = adj_index;
	}

      enum noise_state_crypt state;

      state = noise_sync_remote_encrypt (
	vm, crypto_ops, &peer->remote, &message_data_wg->receiver_index,
	&message_data_wg->counter, plain_data, plain_data_len, plain_data,
	n_sync, iv_data, time);

      if (PREDICT_FALSE (state == SC_KEEP_KEY_FRESH))
	{
	  wg_send_handshake_from_mt (peeri, false);
	}
      else if (PREDICT_FALSE (state == SC_FAILED))
	{
	  // TODO: Maybe wrong
	  wg_send_handshake_from_mt (peeri, false);
	  wg_peer_update_flags (peeri, WG_PEER_ESTABLISHED, false);
	  goto out;
	}

      /* Here we are sure that can send packet to next node */
      next[0] = WG_OUTPUT_NEXT_INTERFACE_OUTPUT;

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
      sync_bufs[n_sync] = b[0];
      sync_next += 1;
      n_sync += 1;
      n_left_from -= 1;
      next += 1;
      b += 1;
    }

  /* wg-output-process-ops */
  wg_output_process_ops (vm, node, ptd->crypto_ops, sync_bufs, nexts,
			 drop_next);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_sync);
  return frame->n_vectors;
}

VLIB_NODE_FN (wg4_output_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return wg_output_tun_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (wg6_output_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return wg_output_tun_inline (vm, node, frame, /* is_ip4 */ 0);
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
