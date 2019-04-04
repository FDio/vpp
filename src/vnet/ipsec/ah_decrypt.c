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

#define foreach_ah_decrypt_next \
  _ (DROP, "error-drop")        \
  _ (IP4_INPUT, "ip4-input")    \
  _ (IP6_INPUT, "ip6-input")    \
  _ (IPSEC_GRE_INPUT, "ipsec-gre-input")

#define _(v, s) AH_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_ah_decrypt_next
#undef _
    AH_DECRYPT_N_NEXT,
} ah_decrypt_next_t;

#define foreach_ah_decrypt_error                \
  _ (RX_PKTS, "AH pkts received")               \
  _ (DECRYPTION_FAILED, "AH decryption failed") \
  _ (INTEG_ERROR, "Integrity check failed")     \
  _ (REPLAY, "SA replayed packet")

typedef enum
{
#define _(sym,str) AH_DECRYPT_ERROR_##sym,
  foreach_ah_decrypt_error
#undef _
    AH_DECRYPT_N_ERROR,
} ah_decrypt_error_t;

static char *ah_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_ah_decrypt_error
#undef _
};

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

always_inline uword
ah_decrypt_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		   int is_ip6)
{
  u32 n_left_from, *from, next_index, *to_next, thread_index;
  ipsec_main_t *im = &ipsec_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  int icv_size;

  next_index = node->cached_next_index;
  thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 i_bi0;
	  u32 next0;
	  vlib_buffer_t *i_b0;
	  ah_header_t *ah0;
	  ipsec_sa_t *sa0;
	  u32 sa_index0 = ~0;
	  u32 seq;
	  ip4_header_t *ih4 = 0, *oh4 = 0;
	  ip6_header_t *ih6 = 0, *oh6 = 0;
	  u8 ip_hdr_size = 0;
	  u8 tos = 0;
	  u8 ttl = 0;
	  u32 ip_version_traffic_class_and_flow_label = 0;
	  u8 hop_limit = 0;
	  u8 nexthdr = 0;
	  u8 icv_padding_len = 0;


	  i_bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = AH_DECRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, i_bi0);
	  to_next[0] = i_bi0;
	  to_next += 1;
	  ih4 = vlib_buffer_get_current (i_b0);
	  ih6 = vlib_buffer_get_current (i_b0);
	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  vlib_prefetch_combined_counter (&ipsec_sa_counters,
					  thread_index, sa_index0);

	  if (is_ip6)
	    {
	      ip6_ext_header_t *prev = NULL;
	      ip6_ext_header_find_t (ih6, prev, ah0, IP_PROTOCOL_IPSEC_AH);
	      ip_hdr_size = sizeof (ip6_header_t);
	      ASSERT ((u8 *) ah0 - (u8 *) ih6 == ip_hdr_size);
	    }
	  else
	    {
	      ip_hdr_size = ip4_header_bytes (ih4);
	      ah0 = (ah_header_t *) ((u8 *) ih4 + ip_hdr_size);
	    }

	  seq = clib_host_to_net_u32 (ah0->seq_no);

	  /* anti-replay check */
	  if (ipsec_sa_anti_replay_check (sa0, &ah0->seq_no))
	    {
	      i_b0->error = node->errors[AH_DECRYPT_ERROR_REPLAY];
	      goto trace;
	    }

	  vlib_increment_combined_counter
	    (&ipsec_sa_counters, thread_index, sa_index0,
	     1, i_b0->current_length);

	  icv_size = sa0->integ_icv_size;
	  if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	    {
	      u8 sig[64];
	      u8 digest[icv_size];
	      u8 *icv = ah0->auth_data;
	      memcpy (digest, icv, icv_size);
	      clib_memset (icv, 0, icv_size);

	      if (is_ip6)
		{
		  ip_version_traffic_class_and_flow_label =
		    ih6->ip_version_traffic_class_and_flow_label;
		  hop_limit = ih6->hop_limit;
		  ih6->ip_version_traffic_class_and_flow_label = 0x60;
		  ih6->hop_limit = 0;
		  nexthdr = ah0->nexthdr;
		  icv_padding_len =
		    ah_calc_icv_padding_len (icv_size, 1 /* is_ipv6 */ );
		}
	      else
		{
		  tos = ih4->tos;
		  ttl = ih4->ttl;
		  ih4->tos = 0;
		  ih4->ttl = 0;
		  ih4->checksum = 0;
		  ih4->flags_and_fragment_offset = 0;
		  icv_padding_len =
		    ah_calc_icv_padding_len (icv_size, 0 /* is_ipv6 */ );
		}
	      hmac_calc (vm, sa0, (u8 *) ih4, i_b0->current_length, sig);

	      if (PREDICT_FALSE (memcmp (digest, sig, icv_size)))
		{
		  i_b0->error = node->errors[AH_DECRYPT_ERROR_INTEG_ERROR];
		  goto trace;
		}

	      ipsec_sa_anti_replay_advance (sa0, &ah0->seq_no);
	    }

	  vlib_buffer_advance (i_b0,
			       ip_hdr_size + sizeof (ah_header_t) + icv_size +
			       icv_padding_len);
	  i_b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  if (PREDICT_TRUE (ipsec_sa_is_set_IS_TUNNEL (sa0)))
	    {			/* tunnel mode */
	      if (PREDICT_TRUE (ah0->nexthdr == IP_PROTOCOL_IP_IN_IP))
		next0 = AH_DECRYPT_NEXT_IP4_INPUT;
	      else if (ah0->nexthdr == IP_PROTOCOL_IPV6)
		next0 = AH_DECRYPT_NEXT_IP6_INPUT;
	      else
		{
		  i_b0->error =
		    node->errors[AH_DECRYPT_ERROR_DECRYPTION_FAILED];
		  goto trace;
		}
	    }
	  else
	    {			/* transport mode */
	      if (is_ip6)
		{
		  vlib_buffer_advance (i_b0, -sizeof (ip6_header_t));
		  oh6 = vlib_buffer_get_current (i_b0);
		  memmove (oh6, ih6, sizeof (ip6_header_t));

		  next0 = AH_DECRYPT_NEXT_IP6_INPUT;
		  oh6->protocol = nexthdr;
		  oh6->hop_limit = hop_limit;
		  oh6->ip_version_traffic_class_and_flow_label =
		    ip_version_traffic_class_and_flow_label;
		  oh6->payload_length =
		    clib_host_to_net_u16 (vlib_buffer_length_in_chain
					  (vm, i_b0) - sizeof (ip6_header_t));
		}
	      else
		{
		  vlib_buffer_advance (i_b0, -sizeof (ip4_header_t));
		  oh4 = vlib_buffer_get_current (i_b0);
		  memmove (oh4, ih4, sizeof (ip4_header_t));

		  next0 = AH_DECRYPT_NEXT_IP4_INPUT;
		  oh4->ip_version_and_header_length = 0x45;
		  oh4->fragment_id = 0;
		  oh4->flags_and_fragment_offset = 0;
		  oh4->protocol = ah0->nexthdr;
		  oh4->length =
		    clib_host_to_net_u16 (vlib_buffer_length_in_chain
					  (vm, i_b0));
		  oh4->ttl = ttl;
		  oh4->tos = tos;
		  oh4->checksum = ip4_header_checksum (oh4);
		}
	    }

	  /* for IPSec-GRE tunnel next node is ipsec-gre-input */
	  if (PREDICT_FALSE (ipsec_sa_is_set_IS_GRE (sa0)))
	    next0 = AH_DECRYPT_NEXT_IPSEC_GRE_INPUT;

	  vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      i_b0->flags |= VLIB_BUFFER_IS_TRACED;
	      ah_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, i_b0, sizeof (*tr));
	      tr->integ_alg = sa0->integ_alg;
	      tr->seq_num = seq;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, i_bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index, AH_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (ah4_decrypt_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ah_decrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah4_decrypt_node) = {
  .name = "ah4-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ah_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ah_decrypt_error_strings),
  .error_strings = ah_decrypt_error_strings,

  .n_next_nodes = AH_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [AH_DECRYPT_NEXT_##s] = n,
    foreach_ah_decrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (ah6_decrypt_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ah_decrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah6_decrypt_node) = {
  .name = "ah6-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ah_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ah_decrypt_error_strings),
  .error_strings = ah_decrypt_error_strings,

  .n_next_nodes = AH_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [AH_DECRYPT_NEXT_##s] = n,
    foreach_ah_decrypt_next
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
