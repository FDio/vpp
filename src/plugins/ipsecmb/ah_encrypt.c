/*
 * ah_encrypt.c : ipsecmb AH encrypt node
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

#include <ipsecmb/ipsecmb.h>

#define foreach_ah_encrypt_next                   \
_(DROP, "error-drop")                              \
_(IP4_LOOKUP, "ip4-lookup")                        \
_(IP6_LOOKUP, "ip6-lookup")                        \
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) AH_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_ah_encrypt_next
#undef _
    AH_ENCRYPT_N_NEXT,
} ah_encrypt_next_t;

#define foreach_ah_encrypt_error                   \
 _(RX_PKTS, "AH pkts received")                    \
 _(SEQ_CYCLED, "sequence number cycled")


typedef enum
{
#define _(sym,str) AH_ENCRYPT_ERROR_##sym,
  foreach_ah_encrypt_error
#undef _
    AH_ENCRYPT_N_ERROR,
} ah_encrypt_error_t;

static char *ah_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_ah_encrypt_error
#undef _
};

typedef struct
{
  u32 spi;
  u32 seq;
  ipsec_integ_alg_t integ_alg;
} ah_encrypt_trace_t;

/* packet trace format function */
static u8 *
format_ah_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ah_encrypt_trace_t *t = va_arg (*args, ah_encrypt_trace_t *);

  s = format (s, "ah: spi %u seq %u integrity %U",
	      t->spi, t->seq, format_ipsec_integ_alg, t->integ_alg);
  return s;
}

#ifdef CLIB_MARCH_VARIANT
always_inline void
ah_finish_encrypt (vlib_main_t * vm, vlib_buffer_t * b0, ipsec_sa_t * sa0,
		   int is_ip6)
{
  if (is_ip6)
    {
      ip6_header_t *oh6 = 0;
      oh6 = vlib_buffer_get_current (b0);
      oh6->ip_version_traffic_class_and_flow_label =
	vnet_buffer (b0)->ipsec.ip_version_traffic_class_and_flow_label;
      oh6->hop_limit = vnet_buffer (b0)->ipsec.ttl_or_hop_limit;
    }
  else
    {
      ip4_header_t *oh4 = 0;
      oh4 = vlib_buffer_get_current (b0);
      oh4->ttl = vnet_buffer (b0)->ipsec.ttl_or_hop_limit;
      oh4->tos = vnet_buffer (b0)->ipsec.tos;
      oh4->checksum = ip4_header_checksum (oh4);
    }
}

always_inline uword
ah_encrypt_ipsecmb_inline (vlib_main_t * vm,
			   vlib_node_runtime_t * node,
			   vlib_frame_t * from_frame, int is_ip6)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  int icv_size = 0;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  next_index = node->cached_next_index;
  u32 thread_index = vlib_get_thread_index ();
  MB_MGR *mgr = imbm->mb_mgr[thread_index];
  u32 packets_in_flight = 0;

  while (n_left_from > 0 || packets_in_flight > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0 = 0;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ipsecmb_sa_t *samb0;
	  ip4_header_t *ih4, *oh4 = 0;
	  ip6_header_t *ih6, *oh6 = 0;
	  ah_header_t *ah = 0;
	  u8 next_hdr_type;
	  u8 transport_mode = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = AH_ENCRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);
	  samb0 = pool_elt_at_index (imbm->sad, sa_index0);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, node->node_index,
					   AH_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      to_next[0] = bi0;
	      to_next += 1;
	      goto trace;
	    }


	  sa0->total_data_size += b0->current_length;

	  ssize_t adv;
	  ih4 = vlib_buffer_get_current (b0);

	  if (PREDICT_TRUE (sa0->is_tunnel))
	    {
	      if (!is_ip6)
		adv = -sizeof (ip4_and_ah_header_t);
	      else
		adv = -sizeof (ip6_and_ah_header_t);
	    }
	  else
	    {
	      adv = -sizeof (ah_header_t);
	    }

	  const u8 padding_len = ah_calc_icv_padding_len (icv_size, is_ip6);
	  adv -= padding_len;

	  icv_size =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	  /* transport mode save the eth header before it is overwritten */
	  if (PREDICT_FALSE (!sa0->is_tunnel))
	    {
	      ethernet_header_t *ieh0 = (ethernet_header_t *)
		((u8 *) vlib_buffer_get_current (b0) -
		 sizeof (ethernet_header_t));
	      ethernet_header_t *oeh0 =
		(ethernet_header_t *) ((u8 *) ieh0 + (adv - icv_size));
	      clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	    }

	  vlib_buffer_advance (b0, adv - icv_size);

	  if (is_ip6)
	    {
	      ih6 = (ip6_header_t *) ih4;
	      oh6 = vlib_buffer_get_current (b0);
	      ah = (ah_header_t *) (oh6 + 1);
	      vnet_buffer (b0)->ipsec.ttl_or_hop_limit = ih6->hop_limit;
	      vnet_buffer (b0)->
		ipsec.ip_version_traffic_class_and_flow_label =
		ih6->ip_version_traffic_class_and_flow_label;

	      if (PREDICT_TRUE (sa0->is_tunnel))
		{
		  next_hdr_type = IP_PROTOCOL_IPV6;
		}
	      else
		{
		  next_hdr_type = ih6->protocol;
		  memmove (oh6, ih6, sizeof (ip6_header_t));
		}

	      oh6->protocol = IP_PROTOCOL_IPSEC_AH;
	      oh6->ip_version_traffic_class_and_flow_label = 0x60;
	      oh6->hop_limit = 0;
	      ah->reserved = 0;
	      ah->nexthdr = next_hdr_type;
	      ah->spi = clib_net_to_host_u32 (sa0->spi);
	      ah->seq_no = clib_net_to_host_u32 (sa0->seq);
	      ah->hdrlen =
		(sizeof (ah_header_t) + icv_size + padding_len) / 4 - 2;
	      oh6->payload_length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
				      sizeof (ip6_header_t));
	    }
	  else
	    {
	      oh4 = vlib_buffer_get_current (b0);
	      memset (oh4, 0, sizeof (*oh4));
	      ah = (ah_header_t *) (oh4 + 1);
	      memset (ah, 0, sizeof (*ah));
	      vnet_buffer (b0)->ipsec.ttl_or_hop_limit = ih4->ttl;
	      vnet_buffer (b0)->ipsec.tos = ih4->tos;

	      if (PREDICT_TRUE (sa0->is_tunnel))
		{
		  next_hdr_type = IP_PROTOCOL_IP_IN_IP;
		}
	      else
		{
		  next_hdr_type = ih4->protocol;
		  memmove (oh4, ih4, sizeof (ip4_header_t));
		}

	      oh4->length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	      oh4->ip_version_and_header_length = 0x45;
	      oh4->fragment_id = 0;
	      oh4->flags_and_fragment_offset = 0;
	      oh4->ttl = 0;
	      oh4->tos = 0;
	      oh4->protocol = IP_PROTOCOL_IPSEC_AH;
	      ah->spi = clib_net_to_host_u32 (sa0->spi);
	      ah->seq_no = clib_net_to_host_u32 (sa0->seq);
	      oh4->checksum = 0;
	      ah->nexthdr = next_hdr_type;
	      ah->hdrlen =
		(sizeof (ah_header_t) + icv_size + padding_len) / 4 - 2;
	    }

	  if (PREDICT_TRUE (!is_ip6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      oh4->src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	      oh4->dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	      next0 = AH_ENCRYPT_NEXT_IP4_LOOKUP;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else if (is_ip6 && sa0->is_tunnel && sa0->is_tunnel_ip6)
	    {
	      oh6->src_address.as_u64[0] = sa0->tunnel_src_addr.ip6.as_u64[0];
	      oh6->src_address.as_u64[1] = sa0->tunnel_src_addr.ip6.as_u64[1];
	      oh6->dst_address.as_u64[0] = sa0->tunnel_dst_addr.ip6.as_u64[0];
	      oh6->dst_address.as_u64[1] = sa0->tunnel_dst_addr.ip6.as_u64[1];
	      next0 = AH_ENCRYPT_NEXT_IP6_LOOKUP;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else
	    {
	      transport_mode = 1;
	    }

	  memset (ah + 1, 0, icv_size);

	  JOB_AES_HMAC *job = IPSECMB_FUNC (get_next_job) (mgr);
	  job->src = vlib_buffer_get_current (b0);
	  job->hash_start_src_offset_in_bytes = 0;
	  job->cipher_mode = NULL_CIPHER;
	  job->hash_alg = imbm->integ_algs[sa0->integ_alg].hash_alg;
	  job->auth_tag_output_len_in_bytes =
	    imbm->integ_algs[sa0->integ_alg].hash_output_length;
	  job->auth_tag_output = (u8 *) (ah + 1);
	  if (PREDICT_TRUE (sa0->use_esn))
	    {
	      *(u32 *) (vlib_buffer_get_current (b0) + b0->current_length) =
		sa0->seq_hi;
	      b0->current_length += sizeof (u32);
	    }
	  job->msg_len_to_hash_in_bytes = b0->current_length;
	  job->cipher_direction = ENCRYPT;
	  job->chain_order = HASH_CIPHER;
	  job->u.HMAC._hashed_auth_key_xor_ipad = samb0->ipad_hash;
	  job->u.HMAC._hashed_auth_key_xor_opad = samb0->opad_hash;


	  job->user_data = (void *) (uintptr_t) bi0;
	  job->user_data2 = (void *) (uintptr_t) next0;
	  vnet_buffer (b0)->ipsec.sad_index = sa_index0;

	  job = IPSECMB_FUNC (submit_job) (mgr);
	  ++packets_in_flight;

	  if (!job)
	    {
	      continue;
	    }

	  --packets_in_flight;
	  ASSERT (STS_COMPLETED == job->status);
	  bi0 = (uintptr_t) job->user_data;
	  next0 = (uintptr_t) job->user_data2;
	  b0 = vlib_get_buffer (vm, bi0);
	  sa0 =
	    pool_elt_at_index (im->sad, vnet_buffer (b0)->ipsec.sad_index);
	  ah_finish_encrypt (vm, b0, sa0, is_ip6);
	  if (!sa0->is_tunnel && !sa0->is_tunnel_ip6)
	    {
	      next0 = AH_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	      vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
	    }

	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ah_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq - 1;
	      tr->integ_alg = sa0->integ_alg;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}

      if (PREDICT_FALSE (n_left_from == 0))
	{
	  JOB_AES_HMAC *job = NULL;
	  while (n_left_to_next > 0 && (job = IPSECMB_FUNC (flush_job) (mgr)))
	    {
	      --packets_in_flight;
	      u32 bi0, next0;
	      vlib_buffer_t *b0;
	      ipsec_sa_t *sa0;

	      ASSERT (STS_COMPLETED == job->status);
	      bi0 = (uintptr_t) job->user_data;
	      next0 = (uintptr_t) job->user_data2;
	      b0 = vlib_get_buffer (vm, bi0);
	      sa0 =
		pool_elt_at_index (im->sad,
				   vnet_buffer (b0)->ipsec.sad_index);
	      ah_finish_encrypt (vm, b0, sa0, is_ip6);
	      if (!sa0->is_tunnel && !sa0->is_tunnel_ip6)
		{
		  next0 = AH_ENCRYPT_NEXT_INTERFACE_OUTPUT;
		  vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
		}

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ah_encrypt_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->spi = sa0->spi;
		  tr->seq = sa0->seq - 1;
		  tr->integ_alg = sa0->integ_alg;
		}

	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next, bi0,
					       next0);
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index, AH_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (ah4_encrypt_ipsecmb_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return ah_encrypt_ipsecmb_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

VLIB_NODE_FN (ah6_encrypt_ipsecmb_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return ah_encrypt_ipsecmb_inline (vm, node, from_frame, 1 /*is_ip6 */ );
}

#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah4_encrypt_ipsecmb_node) = {
  .name = "ah4-encrypt-ipsecmb",
  .vector_size = sizeof (u32),
  .format_trace = format_ah_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ah_encrypt_error_strings),
  .error_strings = ah_encrypt_error_strings,

  .n_next_nodes = AH_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [AH_ENCRYPT_NEXT_##s] = n,
    foreach_ah_encrypt_next
#undef _
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah6_encrypt_ipsecmb_node) = {
  .name = "ah6-encrypt-ipsecmb",
  .vector_size = sizeof (u32),
  .format_trace = format_ah_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ah_encrypt_error_strings),
  .error_strings = ah_encrypt_error_strings,

  .n_next_nodes = AH_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [AH_ENCRYPT_NEXT_##s] = n,
    foreach_ah_encrypt_next
#undef _
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
