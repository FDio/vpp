/*
 * ah_encrypt.c : IPSec AH encrypt node
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
#include <vnet/ipsec/ipsec.api_enum.h>
#include <vnet/tunnel/tunnel_dp.h>

#define foreach_ah_encrypt_next \
  _ (DROP, "error-drop")                           \
  _ (HANDOFF, "handoff")                           \
  _ (INTERFACE_OUTPUT, "interface-output")


#define _(v, s) AH_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_ah_encrypt_next
#undef _
    AH_ENCRYPT_N_NEXT,
} ah_encrypt_next_t;

typedef struct
{
  u32 sa_index;
  u32 spi;
  u64 seq;
  ipsec_integ_alg_t integ_alg;
} ah_encrypt_trace_t;

/* packet trace format function */
static u8 *
format_ah_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ah_encrypt_trace_t *t = va_arg (*args, ah_encrypt_trace_t *);

  s = format (s, "ah: sa-index %d spi %u (0x%08x) seq %lu integrity %U",
	      t->sa_index, t->spi, t->spi, t->seq, format_ipsec_integ_alg,
	      t->integ_alg);
  return s;
}

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
	  ah_encrypt_set_next_index (b[bi], node, vm->thread_index,
				     AH_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR, bi,
				     nexts, AH_ENCRYPT_NEXT_DROP,
				     vnet_buffer (b[bi])->ipsec.sad_index);
	  n_fail--;
	}
      op++;
    }
}

typedef struct
{
  union
  {
    /* Variable fields in the IP header not covered by the AH
     * integrity check */
    struct
    {
      u32 ip_version_traffic_class_and_flow_label;
      u8 hop_limit;
    };
    struct
    {
      u8 ttl;
      u8 tos;
    };
  };
  u8 skip;
  i16 current_data;
  u32 sa_index;
} ah_encrypt_packet_data_t;

always_inline uword
ah_encrypt_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame,
		   int is_ip6)
{
  u32 n_left, *from, thread_index;
  int icv_size = 0;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  ah_encrypt_packet_data_t pkt_data[VLIB_FRAME_SIZE], *pd = pkt_data;
  thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, thread_index);
  ipsec_sa_outb_rt_t *ort = 0;
  ip4_and_ah_header_t *ih0, *oh0 = 0;
  ip6_and_ah_header_t *ih6_0, *oh6_0 = 0;
  u32 current_sa_index = ~0, current_sa_bytes = 0, current_sa_pkts = 0;
  const static ip4_header_t ip4_hdr_template = {
    .ip_version_and_header_length = 0x45,
    .protocol = IP_PROTOCOL_IPSEC_AH,
  };
  const static ip6_header_t ip6_hdr_template = {
    .ip_version_traffic_class_and_flow_label = 0x60,
    .protocol = IP_PROTOCOL_IPSEC_AH,
  };

  clib_memset (pkt_data, 0, VLIB_FRAME_SIZE * sizeof (pkt_data[0]));
  vlib_get_buffers (vm, from, b, n_left);
  vec_reset_length (ptd->integ_ops);

  while (n_left > 0)
    {
      u8 ip_hdr_size;
      u8 next_hdr_type;

      if (vnet_buffer (b[0])->ipsec.sad_index != current_sa_index)
	{
	  if (current_sa_index != ~0)
	    vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					     current_sa_index, current_sa_pkts,
					     current_sa_bytes);
	  current_sa_index = vnet_buffer (b[0])->ipsec.sad_index;
	  ort = ipsec_sa_get_outb_rt_by_index (current_sa_index);

	  current_sa_bytes = current_sa_pkts = 0;
	  vlib_prefetch_combined_counter (&ipsec_sa_counters, thread_index,
					  current_sa_index);
	}

      pd->sa_index = current_sa_index;
      next[0] = AH_ENCRYPT_NEXT_DROP;

      if (PREDICT_FALSE ((u16) ~0 == ort->thread_index))
	{
	  /* this is the first packet to use this SA, claim the SA
	   * for this thread. this could happen simultaneously on
	   * another thread */
	  clib_atomic_cmp_and_swap (&ort->thread_index, ~0,
				    ipsec_sa_assign_thread (thread_index));
	}

      if (PREDICT_TRUE (thread_index != ort->thread_index))
	{
	  vnet_buffer (b[0])->ipsec.thread_index = ort->thread_index;
	  next[0] = AH_ENCRYPT_NEXT_HANDOFF;
	  goto next;
	}

      if (PREDICT_FALSE (esp_seq_advance (ort)))
	{
	  ah_encrypt_set_next_index (b[0], node, vm->thread_index,
				     AH_ENCRYPT_ERROR_SEQ_CYCLED, 0, next,
				     AH_ENCRYPT_NEXT_DROP, current_sa_index);
	  pd->skip = 1;
	  goto next;
	}

      current_sa_pkts += 1;
      current_sa_bytes += b[0]->current_length;

      ssize_t adv;
      ih0 = vlib_buffer_get_current (b[0]);

      if (PREDICT_TRUE (ort->is_tunnel))
	{
	  if (is_ip6)
	    adv = -sizeof (ip6_and_ah_header_t);
	  else
	    adv = -sizeof (ip4_and_ah_header_t);
	}
      else
	{
	  adv = -sizeof (ah_header_t);
	}

      icv_size = ort->integ_icv_size;
      const u8 padding_len = ah_calc_icv_padding_len (icv_size, is_ip6);
      adv -= padding_len;
      /* transport mode save the eth header before it is overwritten */
      if (PREDICT_FALSE (!ort->is_tunnel))
	{
	  const u32 l2_len = vnet_buffer (b[0])->ip.save_rewrite_length;
	  u8 *l2_hdr_in = (u8 *) vlib_buffer_get_current (b[0]) - l2_len;

	  u8 *l2_hdr_out = l2_hdr_in + adv - icv_size;

	  clib_memcpy_le32 (l2_hdr_out, l2_hdr_in, l2_len);
	}

      vlib_buffer_advance (b[0], adv - icv_size);

      if (is_ip6)
	{
	  ih6_0 = (ip6_and_ah_header_t *) ih0;
	  ip_hdr_size = sizeof (ip6_header_t);
	  oh6_0 = vlib_buffer_get_current (b[0]);
	  pd->current_data = b[0]->current_data;
	  pd->hop_limit = ih6_0->ip6.hop_limit;

	  oh6_0->ip6.ip_version_traffic_class_and_flow_label =
	    ih6_0->ip6.ip_version_traffic_class_and_flow_label;

	  if (PREDICT_FALSE (ort->is_tunnel))
	    {
	      ip6_set_dscp_network_order (&oh6_0->ip6, ort->t_dscp);
	      tunnel_encap_fixup_6o6 (ort->tunnel_flags, &ih6_0->ip6,
				      &oh6_0->ip6);
	    }
	  pd->ip_version_traffic_class_and_flow_label =
	    oh6_0->ip6.ip_version_traffic_class_and_flow_label;

	  if (PREDICT_TRUE (ort->is_tunnel))
	    {
	      next_hdr_type = IP_PROTOCOL_IPV6;
	    }
	  else
	    {
	      next_hdr_type = ih6_0->ip6.protocol;
	      memmove (oh6_0, ih6_0, sizeof (ip6_header_t));
	    }

	  clib_memcpy_fast (&oh6_0->ip6, &ip6_hdr_template, 8);
	  oh6_0->ah.reserved = 0;
	  oh6_0->ah.nexthdr = next_hdr_type;
	  oh6_0->ah.spi = ort->spi_be;
	  oh6_0->ah.seq_no = clib_net_to_host_u32 (ort->seq64);
	  oh6_0->ip6.payload_length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0]) -
				  sizeof (ip6_header_t));
	  oh6_0->ah.hdrlen =
	    (sizeof (ah_header_t) + icv_size + padding_len) / 4 - 2;
	}
      else
	{
	  ip_hdr_size = sizeof (ip4_header_t);
	  oh0 = vlib_buffer_get_current (b[0]);
	  pd->ttl = ih0->ip4.ttl;

	  if (PREDICT_FALSE (ort->is_tunnel))
	    {
	      if (ort->t_dscp)
		pd->tos = ort->t_dscp << 2;
	      else
		{
		  pd->tos = ih0->ip4.tos;

		  if (!(ort->tunnel_flags &
			TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP))
		    pd->tos &= 0x3;
		  if (!(ort->tunnel_flags &
			TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN))
		    pd->tos &= 0xfc;
		}
	    }
	  else
	    {
	      pd->tos = ih0->ip4.tos;
	    }

	  pd->current_data = b[0]->current_data;
	  clib_memset (oh0, 0, sizeof (ip4_and_ah_header_t));

	  if (PREDICT_TRUE (ort->is_tunnel))
	    {
	      next_hdr_type = IP_PROTOCOL_IP_IN_IP;
	    }
	  else
	    {
	      next_hdr_type = ih0->ip4.protocol;
	      memmove (oh0, ih0, sizeof (ip4_header_t));
	    }

	  clib_memcpy_fast (&oh0->ip4, &ip4_hdr_template,
			    sizeof (ip4_header_t) -
			    sizeof (ip4_address_pair_t));

	  oh0->ip4.length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0]));
	  oh0->ah.spi = ort->spi_be;
	  oh0->ah.seq_no = clib_net_to_host_u32 (ort->seq64);
	  oh0->ah.nexthdr = next_hdr_type;
	  oh0->ah.hdrlen =
	    (sizeof (ah_header_t) + icv_size + padding_len) / 4 - 2;
	}

      if (PREDICT_TRUE (!is_ip6 && ort->is_tunnel && !ort->is_tunnel_v6))
	{
	  clib_memcpy_fast (&oh0->ip4.address_pair, &ort->ip4_hdr.address_pair,
			    sizeof (ip4_address_pair_t));

	  next[0] = ort->dpo.dpoi_next_node;
	  vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = ort->dpo.dpoi_index;
	}
      else if (is_ip6 && ort->is_tunnel && ort->is_tunnel_v6)
	{
	  clib_memcpy_fast (&oh6_0->ip6.src_address, &ort->ip6_hdr.src_address,
			    sizeof (ip6_address_t) * 2);
	  next[0] = ort->dpo.dpoi_next_node;
	  vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = ort->dpo.dpoi_index;
	}

      if (PREDICT_TRUE (ort->integ_icv_size && !ort->is_aead))
	{
	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ptd->integ_ops, op, 1, CLIB_CACHE_LINE_BYTES);
	  vnet_crypto_key_t *key = vnet_crypto_get_key (ort->key_index);
	  if (key->is_link)
	    key = vnet_crypto_get_key (key->index_integ);
	  vnet_crypto_op_id_t *op_ids = vnet_crypto_ops_from_alg (key->alg);
	  vnet_crypto_op_init (op, op_ids[VNET_CRYPTO_OP_TYPE_HMAC]);
	  op->src = vlib_buffer_get_current (b[0]);
	  op->len = b[0]->current_length;
	  op->digest = vlib_buffer_get_current (b[0]) + ip_hdr_size +
	    sizeof (ah_header_t);
	  clib_memset (op->digest, 0, icv_size);
	  op->digest_len = icv_size;
	  op->key_index = key->index;
	  op->user_data = b - bufs;
	  if (ort->use_esn)
	    {
	      *(u32u *) (op->src + b[0]->current_length) =
		clib_host_to_net_u32 (ort->seq64 >> 32);
	      op->len += sizeof (u32);
	    }
	}

      if (!ort->is_tunnel)
	{
	  next[0] = AH_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	  vlib_buffer_advance (b[0], -sizeof (ethernet_header_t));
	}

    next:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsec_sa_t *sa = ipsec_sa_get (pd->sa_index);
	  ipsec_sa_outb_rt_t *ort =
	    ipsec_sa_get_outb_rt_by_index (pd->sa_index);
	  ah_encrypt_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->spi = sa->spi;
	  tr->seq = ort->seq64;
	  tr->integ_alg = sa->integ_alg;
	  tr->sa_index = pd->sa_index;
	}

      n_left -= 1;
      next += 1;
      pd += 1;
      b += 1;
    }

  n_left = frame->n_vectors;
  next = nexts;
  pd = pkt_data;
  b = bufs;

  vlib_node_increment_counter (vm, node->node_index,
			       AH_ENCRYPT_ERROR_RX_PKTS, n_left);
  vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				   current_sa_index, current_sa_pkts,
				   current_sa_bytes);

  ah_process_ops (vm, node, ptd->integ_ops, bufs, nexts);

  while (n_left)
    {
      if (pd->skip)
	goto next_pkt;

      if (is_ip6)
	{
	  oh6_0 = (ip6_and_ah_header_t *) (b[0]->data + pd->current_data);
	  oh6_0->ip6.hop_limit = pd->hop_limit;
	  oh6_0->ip6.ip_version_traffic_class_and_flow_label =
	    pd->ip_version_traffic_class_and_flow_label;
	}
      else
	{
	  oh0 = (ip4_and_ah_header_t *) (b[0]->data + pd->current_data);
	  oh0->ip4.ttl = pd->ttl;
	  oh0->ip4.tos = pd->tos;
	  oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
	}

    next_pkt:
      n_left -= 1;
      next += 1;
      pd += 1;
      b += 1;
    }

  n_left = frame->n_vectors;
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);

  return n_left;
}

VLIB_NODE_FN (ah4_encrypt_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ah_encrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

VLIB_REGISTER_NODE (ah4_encrypt_node) = {
  .name = "ah4-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ah_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = AH_ENCRYPT_N_ERROR,
  .error_counters = ah_encrypt_error_counters,

  .n_next_nodes = AH_ENCRYPT_N_NEXT,
  .next_nodes = {
    [AH_ENCRYPT_NEXT_DROP] = "ip4-drop",
    [AH_ENCRYPT_NEXT_HANDOFF] = "ah4-encrypt-handoff",
    [AH_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};

VLIB_NODE_FN (ah6_encrypt_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ah_encrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

VLIB_REGISTER_NODE (ah6_encrypt_node) = {
  .name = "ah6-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ah_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = AH_ENCRYPT_N_ERROR,
  .error_counters = ah_encrypt_error_counters,

  .n_next_nodes = AH_ENCRYPT_N_NEXT,
  .next_nodes = {
    [AH_ENCRYPT_NEXT_DROP] = "ip6-drop",
    [AH_ENCRYPT_NEXT_HANDOFF] = "ah6-encrypt-handoff",
    [AH_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};

#ifndef CLIB_MARCH_VARIANT

static clib_error_t *
ah_encrypt_init (vlib_main_t *vm)
{
  ipsec_main_t *im = &ipsec_main;

  im->ah4_enc_fq_index = vlib_frame_queue_main_init (ah4_encrypt_node.index,
						     im->handoff_queue_size);
  im->ah6_enc_fq_index = vlib_frame_queue_main_init (ah6_encrypt_node.index,
						     im->handoff_queue_size);

  return 0;
}

VLIB_INIT_FUNCTION (ah_encrypt_init);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
