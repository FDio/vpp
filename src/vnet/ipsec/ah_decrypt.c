/*
 * ah_decrypt.c : IPSec AH decrypt node
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>
#include <vnet/ipsec/ipsec_io.h>

#define foreach_ah_decrypt_next                 \
  _(DROP, "error-drop")                         \
  _(IP4_INPUT, "ip4-input")                     \
  _(IP6_INPUT, "ip6-input")                     \
  _(HANDOFF, "handoff")

#define _(v, s) AH_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_ah_decrypt_next
#undef _
    AH_DECRYPT_N_NEXT,
} ah_decrypt_next_t;

typedef struct
{
  ipsec_integ_alg_t integ_alg;
  u32 seq_num;
} ah_decrypt_trace_t;

/* packet trace format function */
static u8 *
format_ah_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ah_decrypt_trace_t *t = va_arg (*args, ah_decrypt_trace_t *);

  s = format (s, "ah: integrity %U seq-num %d",
	      format_ipsec_integ_alg, t->integ_alg, t->seq_num);
  return s;
}

typedef struct
{
  union
  {
    struct
    {
      u8 hop_limit;
      u8 nexthdr;
      u32 ip_version_traffic_class_and_flow_label;
    };

    struct
    {
      u8 ttl;
      u8 tos;
    };
  };
  u32 sa_index;
  u32 seq;
  u32 seq_hi;
  u8 icv_padding_len;
  u8 icv_size;
  u8 ip_hdr_size;
  i16 current_data;
  u8 nexthdr_cached;
} ah_decrypt_packet_data_t;

static_always_inline void
ah_process_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
		vnet_crypto_op_t * ops, vlib_buffer_t * b[], u16 * nexts)
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
	  ah_decrypt_set_next_index (
	    b[bi], node, vm->thread_index, AH_DECRYPT_ERROR_INTEG_ERROR, bi,
	    nexts, AH_DECRYPT_NEXT_DROP, vnet_buffer (b[bi])->ipsec.sad_index);
	  n_fail--;
	}
      op++;
    }
}

always_inline uword
ah_decrypt_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		   int is_ip6)
{
  u32 n_left, *from;
  clib_thread_index_t thread_index = vm->thread_index;
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  ah_decrypt_packet_data_t pkt_data[VLIB_FRAME_SIZE], *pd = pkt_data;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  ipsec_main_t *im = &ipsec_main;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, thread_index);
  from = vlib_frame_vector_args (from_frame);
  n_left = from_frame->n_vectors;
  ipsec_sa_inb_rt_t *irt = 0;
  bool anti_replay_result;
  u32 current_sa_index = ~0, current_sa_bytes = 0, current_sa_pkts = 0;

  clib_memset (pkt_data, 0, VLIB_FRAME_SIZE * sizeof (pkt_data[0]));
  vlib_get_buffers (vm, from, b, n_left);
  clib_memset_u16 (nexts, -1, n_left);
  vec_reset_length (ptd->integ_ops);

  while (n_left > 0)
    {
      ah_header_t *ah0;
      ip4_header_t *ih4;
      ip6_header_t *ih6;

      if (vnet_buffer (b[0])->ipsec.sad_index != current_sa_index)
	{
	  if (current_sa_index != ~0)
	    vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					     current_sa_index, current_sa_pkts,
					     current_sa_bytes);
	  current_sa_index = vnet_buffer (b[0])->ipsec.sad_index;
	  irt = ipsec_sa_get_inb_rt_by_index (current_sa_index);

	  current_sa_bytes = current_sa_pkts = 0;
	  vlib_prefetch_combined_counter (&ipsec_sa_counters,
					  thread_index, current_sa_index);
	}

      if (PREDICT_FALSE ((u16) ~0 == irt->thread_index))
	{
	  /* this is the first packet to use this SA, claim the SA
	   * for this thread. this could happen simultaneously on
	   * another thread */
	  clib_atomic_cmp_and_swap (&irt->thread_index, ~0,
				    ipsec_sa_assign_thread (thread_index));
	}

      if (PREDICT_TRUE (thread_index != irt->thread_index))
	{
	  vnet_buffer (b[0])->ipsec.thread_index = irt->thread_index;
	  next[0] = AH_DECRYPT_NEXT_HANDOFF;
	  goto next;
	}

      pd->sa_index = current_sa_index;

      ih4 = vlib_buffer_get_current (b[0]);
      ih6 = vlib_buffer_get_current (b[0]);
      pd->current_data = b[0]->current_data;

      if (is_ip6)
	{
	  ip6_ext_header_t *prev = NULL;
	  ah0 =
	    ip6_ext_header_find (vm, b[0], ih6, IP_PROTOCOL_IPSEC_AH, &prev);
	  pd->ip_hdr_size = sizeof (ip6_header_t);
	  ASSERT ((u8 *) ah0 - (u8 *) ih6 == pd->ip_hdr_size);
	}
      else
	{
	  if (ip4_is_fragment (ih4))
	    {
	      ah_decrypt_set_next_index (
		b[0], node, vm->thread_index, AH_DECRYPT_ERROR_DROP_FRAGMENTS,
		0, next, AH_DECRYPT_NEXT_DROP, current_sa_index);
	      goto next;
	    }
	  pd->ip_hdr_size = ip4_header_bytes (ih4);
	  ah0 = (ah_header_t *) ((u8 *) ih4 + pd->ip_hdr_size);
	}

      pd->seq = clib_host_to_net_u32 (ah0->seq_no);

      /* anti-replay check */
      anti_replay_result = ipsec_sa_anti_replay_and_sn_advance (
	irt, pd->seq, ~0, false, &pd->seq_hi);
      if (anti_replay_result)
	{
	  ah_decrypt_set_next_index (b[0], node, vm->thread_index,
				     AH_DECRYPT_ERROR_REPLAY, 0, next,
				     AH_DECRYPT_NEXT_DROP, current_sa_index);
	  goto next;
	}

      current_sa_bytes += b[0]->current_length;
      current_sa_pkts += 1;

      pd->icv_size = irt->integ_icv_size;
      pd->nexthdr_cached = ah0->nexthdr;
      if (PREDICT_TRUE (irt->integ_icv_size))
	{
	  if (PREDICT_FALSE (irt->use_esn && pd->current_data +
						 b[0]->current_length +
						 sizeof (u32) >
					       buffer_data_size))
	    {
	      ah_decrypt_set_next_index (
		b[0], node, vm->thread_index, AH_DECRYPT_ERROR_NO_TAIL_SPACE,
		0, next, AH_DECRYPT_NEXT_DROP, current_sa_index);
	      goto next;
	    }

	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ptd->integ_ops, op, 1, CLIB_CACHE_LINE_BYTES);
	  vnet_crypto_key_t *key = vnet_crypto_get_key (irt->key_index);
	  if (key->is_link)
	    key = vnet_crypto_get_key (key->index_integ);
	  vnet_crypto_op_id_t *op_ids = vnet_crypto_ops_from_alg (key->alg);
	  vnet_crypto_op_init (op, op_ids[VNET_CRYPTO_OP_TYPE_HMAC]);

	  op->src = (u8 *) ih4;
	  op->len = b[0]->current_length;
	  op->digest = (u8 *) ih4 - pd->icv_size;
	  op->flags = VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
	  op->digest_len = pd->icv_size;
	  op->key_index = key->index;
	  op->user_data = b - bufs;
	  if (irt->use_esn)
	    {
	      u32 seq_hi = clib_host_to_net_u32 (pd->seq_hi);

	      op->len += sizeof (seq_hi);
	      clib_memcpy (op->src + b[0]->current_length, &seq_hi,
			   sizeof (seq_hi));
	    }
	  clib_memcpy (op->digest, ah0->auth_data, pd->icv_size);
	  clib_memset (ah0->auth_data, 0, pd->icv_size);

	  if (is_ip6)
	    {
	      pd->ip_version_traffic_class_and_flow_label =
		ih6->ip_version_traffic_class_and_flow_label;
	      pd->hop_limit = ih6->hop_limit;
	      ih6->ip_version_traffic_class_and_flow_label = 0x60;
	      ih6->hop_limit = 0;
	      pd->nexthdr = ah0->nexthdr;
	      pd->icv_padding_len =
		ah_calc_icv_padding_len (pd->icv_size, 1 /* is_ipv6 */ );
	    }
	  else
	    {
	      pd->tos = ih4->tos;
	      pd->ttl = ih4->ttl;
	      ih4->tos = 0;
	      ih4->ttl = 0;
	      ih4->checksum = 0;
	      pd->icv_padding_len =
		ah_calc_icv_padding_len (pd->icv_size, 0 /* is_ipv6 */ );
	    }
	}

    next:
      n_left -= 1;
      pd += 1;
      next += 1;
      b += 1;
    }

  n_left = from_frame->n_vectors;
  next = nexts;
  pd = pkt_data;
  b = bufs;

  vlib_node_increment_counter (vm, node->node_index, AH_DECRYPT_ERROR_RX_PKTS,
			       n_left);
  vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				   current_sa_index, current_sa_pkts,
				   current_sa_bytes);

  ah_process_ops (vm, node, ptd->integ_ops, bufs, nexts);

  while (n_left > 0)
    {
      ip4_header_t *oh4;
      ip6_header_t *oh6;
      u64 n_lost = 0;

      if (next[0] < AH_DECRYPT_N_NEXT)
	goto trace;

      irt = ipsec_sa_get_inb_rt_by_index (pd->sa_index);

      if (PREDICT_TRUE (irt->integ_icv_size))
	{
	  /* redo the anti-reply check. see esp_decrypt for details */
	  if (ipsec_sa_anti_replay_and_sn_advance (irt, pd->seq, pd->seq_hi,
						   true, NULL))
	    {
	      ah_decrypt_set_next_index (b[0], node, vm->thread_index,
					 AH_DECRYPT_ERROR_REPLAY, 0, next,
					 AH_DECRYPT_NEXT_DROP, pd->sa_index);
	      goto trace;
	    }
	  n_lost = ipsec_sa_anti_replay_advance (irt, thread_index, pd->seq,
						 pd->seq_hi);
	  vlib_prefetch_simple_counter (
	    &ipsec_sa_err_counters[IPSEC_SA_ERROR_LOST], thread_index,
	    pd->sa_index);
	}

      u16 ah_hdr_len = sizeof (ah_header_t) + pd->icv_size
	+ pd->icv_padding_len;
      vlib_buffer_advance (b[0], pd->ip_hdr_size + ah_hdr_len);
      b[0]->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
      b[0]->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
		       VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

      if (PREDICT_TRUE (irt->is_tunnel))
	{			/* tunnel mode */
	  if (PREDICT_TRUE (pd->nexthdr_cached == IP_PROTOCOL_IP_IN_IP))
	    next[0] = AH_DECRYPT_NEXT_IP4_INPUT;
	  else if (pd->nexthdr_cached == IP_PROTOCOL_IPV6)
	    next[0] = AH_DECRYPT_NEXT_IP6_INPUT;
	  else
	    {
	      ah_decrypt_set_next_index (b[0], node, vm->thread_index,
					 AH_DECRYPT_ERROR_DECRYPTION_FAILED, 0,
					 next, AH_DECRYPT_NEXT_DROP,
					 pd->sa_index);
	      goto trace;
	    }
	}
      else
	{			/* transport mode */
	  if (is_ip6)
	    {
	      vlib_buffer_advance (b[0], -sizeof (ip6_header_t));
	      oh6 = vlib_buffer_get_current (b[0]);
	      if (ah_hdr_len >= sizeof (ip6_header_t))
		clib_memcpy (oh6, b[0]->data + pd->current_data,
			     sizeof (ip6_header_t));
	      else
		memmove (oh6, b[0]->data + pd->current_data,
			 sizeof (ip6_header_t));

	      next[0] = AH_DECRYPT_NEXT_IP6_INPUT;
	      oh6->protocol = pd->nexthdr;
	      oh6->hop_limit = pd->hop_limit;
	      oh6->ip_version_traffic_class_and_flow_label =
		pd->ip_version_traffic_class_and_flow_label;
	      oh6->payload_length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain
				      (vm, b[0]) - sizeof (ip6_header_t));
	    }
	  else
	    {
	      vlib_buffer_advance (b[0], -sizeof (ip4_header_t));
	      oh4 = vlib_buffer_get_current (b[0]);
	      if (ah_hdr_len >= sizeof (ip4_header_t))
		clib_memcpy (oh4, b[0]->data + pd->current_data,
			     sizeof (ip4_header_t));
	      else
		memmove (oh4, b[0]->data + pd->current_data,
			 sizeof (ip4_header_t));

	      next[0] = AH_DECRYPT_NEXT_IP4_INPUT;
	      oh4->ip_version_and_header_length = 0x45;
	      oh4->fragment_id = 0;
	      oh4->flags_and_fragment_offset = 0;
	      oh4->protocol = pd->nexthdr_cached;
	      oh4->length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0]));
	      oh4->ttl = pd->ttl;
	      oh4->tos = pd->tos;
	      oh4->checksum = ip4_header_checksum (oh4);
	    }
	}

      if (PREDICT_FALSE (n_lost))
	vlib_increment_simple_counter (
	  &ipsec_sa_err_counters[IPSEC_SA_ERROR_LOST], thread_index,
	  pd->sa_index, n_lost);

      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = (u32) ~ 0;
    trace:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsec_sa_t *sa = ipsec_sa_get (vnet_buffer (b[0])->ipsec.sad_index);
	  ah_decrypt_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->integ_alg = sa->integ_alg;
	  tr->seq_num = pd->seq;
	}

      n_left -= 1;
      pd += 1;
      next += 1;
      b += 1;
    }

  n_left = from_frame->n_vectors;
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);

  return n_left;
}

VLIB_NODE_FN (ah4_decrypt_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ah_decrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

VLIB_REGISTER_NODE (ah4_decrypt_node) = {
  .name = "ah4-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ah_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = AH_DECRYPT_N_ERROR,
  .error_counters = ah_decrypt_error_counters,

  .n_next_nodes = AH_DECRYPT_N_NEXT,
  .next_nodes = {
    [AH_DECRYPT_NEXT_DROP] = "ip4-drop",
    [AH_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [AH_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [AH_DECRYPT_NEXT_HANDOFF] = "ah4-decrypt-handoff",
  },
};

VLIB_NODE_FN (ah6_decrypt_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ah_decrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

VLIB_REGISTER_NODE (ah6_decrypt_node) = {
  .name = "ah6-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ah_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = AH_DECRYPT_N_ERROR,
  .error_counters = ah_decrypt_error_counters,

  .n_next_nodes = AH_DECRYPT_N_NEXT,
  .next_nodes = {
    [AH_DECRYPT_NEXT_DROP] = "ip6-drop",
    [AH_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [AH_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [AH_DECRYPT_NEXT_HANDOFF] = "ah6-decrypt-handoff",
  },
};

#ifndef CLIB_MARCH_VARIANT

static clib_error_t *
ah_decrypt_init (vlib_main_t *vm)
{
  ipsec_main_t *im = &ipsec_main;

  im->ah4_dec_fq_index = vlib_frame_queue_main_init (ah4_decrypt_node.index,
						     im->handoff_queue_size);
  im->ah6_dec_fq_index = vlib_frame_queue_main_init (ah6_decrypt_node.index,
						     im->handoff_queue_size);

  return 0;
}

VLIB_INIT_FUNCTION (ah_decrypt_init);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
