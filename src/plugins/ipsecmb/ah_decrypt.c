/*
 * ah_decrypt.c : ipsecmb AH decrypt node
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
  _ (REPLAY, "SA replayed packet")              \
  _ (NOT_IP, "Not IP packet (dropped)")

typedef enum
{
#define _(sym, str) AH_DECRYPT_ERROR_##sym,
  foreach_ah_decrypt_error
#undef _
    AH_DECRYPT_N_ERROR,
} ah_decrypt_error_t;

static char *ah_decrypt_error_strings[] = {
#define _(sym, string) string,
  foreach_ah_decrypt_error
#undef _
};

typedef struct
{
  ipsec_integ_alg_t integ_alg;
} ah_decrypt_trace_t;

/* packet trace format function */
static u8 *
format_ah_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ah_decrypt_trace_t *t = va_arg (*args, ah_decrypt_trace_t *);

  s = format (s, "ah: integrity %U", format_ipsec_integ_alg, t->integ_alg);
  return s;
}

typedef struct
{
  u8 tos;
  u8 ttl;
  u32 ip_version_traffic_class_and_flow_label;
  u8 hop_limit;
} ip_mutable_data_t;

#ifdef CLIB_MARCH_VARIANT
always_inline void
remove_ah (vlib_main_t * vm, vlib_node_runtime_t * node, u32 * bi0,
	   u32 * next0, ipsec_sa_t * sa0, u32 ip_hdr_size, u32 icv_size,
	   u8 icv_padding_len, ah_header_t * ah0, int is_ip6)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, *bi0);

  if (sa0->is_tunnel)
    {				/* tunnel mode */
      vlib_buffer_advance (b0, ip_hdr_size + sizeof (ah_header_t) + icv_size +
			   icv_padding_len);
      if (ah0->nexthdr == IP_PROTOCOL_IP_IN_IP)
	*next0 = AH_DECRYPT_NEXT_IP4_INPUT;
      else if (ah0->nexthdr == IP_PROTOCOL_IPV6)
	*next0 = AH_DECRYPT_NEXT_IP6_INPUT;
      else
	{
	  clib_warning ("next header: 0x%x", ah0->nexthdr);
	  vlib_node_increment_counter (vm, node->node_index,
				       AH_DECRYPT_ERROR_DECRYPTION_FAILED, 1);
	  *next0 = AH_DECRYPT_NEXT_DROP;
	  return;
	}
    }
  else
    {				/* transport mode */
      const size_t ip_hdr_offset =
	sizeof (ah_header_t) + icv_size + icv_padding_len;
      if (is_ip6)
	{			/* ipv6 */
	  ip6_header_t *ih6 =
	    (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      ip_hdr_offset);
	  u8 nexthdr = ah0->nexthdr;
	  memmove (ih6, vlib_buffer_get_current (b0), sizeof (ip6_header_t));
	  vlib_buffer_advance (b0, ip_hdr_offset);

	  *next0 = AH_DECRYPT_NEXT_IP6_INPUT;
	  ih6->protocol = nexthdr;
	  ih6->payload_length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
				  sizeof (ip6_header_t));
	}
      else
	{			/* ipv4 */
	  ip4_header_t *ih4 =
	    (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      ip_hdr_offset);
	  u8 nexthdr = ah0->nexthdr;
	  memmove (ih4, vlib_buffer_get_current (b0), sizeof (ip4_header_t));
	  vlib_buffer_advance (b0, ip_hdr_offset);

	  *next0 = AH_DECRYPT_NEXT_IP4_INPUT;
	  ih4->ip_version_and_header_length = 0x45;
	  ih4->fragment_id = 0;
	  ih4->flags_and_fragment_offset = 0;
	  ih4->protocol = nexthdr;
	  ih4->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	  ih4->checksum = ip4_header_checksum (ih4);
	}
    }

  /* for IPSec-GRE tunnel next node is ipsec-gre-input */
  if (PREDICT_FALSE
      ((vnet_buffer (b0)->ipsec.flags & IPSEC_FLAG_IPSEC_GRE_TUNNEL)))
    {
      *next0 = AH_DECRYPT_NEXT_IPSEC_GRE_INPUT;
    }
}

always_inline void
ah_finish_decrypt (vlib_main_t * vm, vlib_node_runtime_t * node,
		   JOB_AES_HMAC * job, u32 * bi0, u32 * next0, int is_ip6)
{
  ipsec_main_t *im = &ipsec_main;
  *bi0 = (uintptr_t) job->user_data;
  vlib_buffer_t *b0 = vlib_get_buffer (vm, *bi0);
  ipsec_sa_t *sa0 =
    pool_elt_at_index (im->sad, vnet_buffer (b0)->ipsec.sad_index);
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 icv_size = em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
  u32 ip_hdr_size = 0;
  ip4_header_t *ih4 = vlib_buffer_get_current (b0);
  size_t seq_size = 0;
  if (PREDICT_TRUE (sa0->use_esn))
    {
      seq_size = sizeof (u32);
    }
  ip_mutable_data_t *md =
    (ip_mutable_data_t *) ((u8 *) vlib_buffer_get_current (b0) +
			   b0->current_length + seq_size + icv_size);
  if (is_ip6)
    {
      ip_hdr_size = sizeof (ip6_header_t);
      ip6_header_t *ih6 = vlib_buffer_get_current (b0);
      ih6->ip_version_traffic_class_and_flow_label =
	md->ip_version_traffic_class_and_flow_label;
      ih6->hop_limit = md->hop_limit;
    }
  else
    {
      ip_hdr_size = ip4_header_bytes (ih4);
      ih4->ttl = md->ttl;
      ih4->tos = md->tos;
    }

  u8 icv_padding_len = ah_calc_icv_padding_len (icv_size, is_ip6);
  ah_header_t *ah0 =
    (ah_header_t *) ((u8 *) vlib_buffer_get_current (b0) + ip_hdr_size);
  void *digest = ah0 + 1;
  void *sig = vlib_buffer_get_current (b0) + b0->current_length + seq_size;

  if (PREDICT_FALSE (memcmp (digest, sig, icv_size)))
    {
      vlib_node_increment_counter (vm, node->node_index,
				   AH_DECRYPT_ERROR_INTEG_ERROR, 1);
      *next0 = AH_DECRYPT_NEXT_DROP;
      return;
    }

  if (PREDICT_TRUE (sa0->use_anti_replay))
    {
      if (PREDICT_TRUE (sa0->use_esn))
	esp_replay_advance_esn (sa0, clib_host_to_net_u32 (ah0->seq_no));
      else
	esp_replay_advance (sa0, clib_host_to_net_u32 (ah0->seq_no));
    }
  remove_ah (vm, node, bi0, next0, sa0, ip_hdr_size, icv_size,
	     icv_padding_len, ah0, is_ip6);
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
}

always_inline uword
ah_decrypt_ipsecmb_inline (vlib_main_t * vm,
			   vlib_node_runtime_t * node,
			   vlib_frame_t * from_frame, int is_ip6)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  int icv_size = 0;
  u32 thread_index = vlib_get_thread_index ();
  MB_MGR *mgr = imbm->mb_mgr[thread_index];
  u32 packets_in_flight = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0 || packets_in_flight > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  u32 next0;
	  vlib_buffer_t *b0;
	  ah_header_t *ah0;
	  ipsec_sa_t *sa0;
	  ipsecmb_sa_t *samb0;
	  u32 sa_index0 = ~0;
	  u32 seq;
	  ip4_header_t *ih4 = 0;
	  ip6_header_t *ih6 = 0;
	  u8 ip_hdr_size = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = AH_DECRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  ih4 = vlib_buffer_get_current (b0);
	  ih6 = vlib_buffer_get_current (b0);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);
	  samb0 = pool_elt_at_index (imbm->sad, sa_index0);

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
	      ah0 = (ah_header_t *) (ih4 + 1);
	    }

	  seq = clib_host_to_net_u32 (ah0->seq_no);
	  /* anti-replay check */
	  // TODO UT remaining
	  if (sa0->use_anti_replay)
	    {
	      int rv = 0;

	      if (PREDICT_TRUE (sa0->use_esn))
		rv = esp_replay_check_esn (sa0, seq);
	      else
		rv = esp_replay_check (sa0, seq);

	      if (PREDICT_FALSE (rv))
		{
		  clib_warning ("anti-replay SPI %u seq %u", sa0->spi, seq);
		  vlib_node_increment_counter (vm, node->node_index,
					       AH_DECRYPT_ERROR_REPLAY, 1);
		  goto trace;
		}
	    }

	  sa0->total_data_size += b0->current_length;
	  icv_size =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	  if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	    {
	      u8 *icv = (u8 *) vlib_buffer_get_current (b0) + ip_hdr_size +
		sizeof (ah_header_t);
	      size_t seq_size = 0;
	      if (PREDICT_TRUE (sa0->use_esn))
		{
		  *(u32 *) (vlib_buffer_get_current (b0) +
			    b0->current_length) = sa0->seq_hi;
		  seq_size = sizeof (u32);
		}
	      clib_memcpy (vlib_buffer_get_current (b0) + b0->current_length +
			   seq_size, icv, icv_size);
	      memset (icv, 0, icv_size);

	      ip_mutable_data_t *md =
		(ip_mutable_data_t *) ((u8 *) vlib_buffer_get_current (b0) +
				       b0->current_length + seq_size +
				       icv_size);
	      if (is_ip6)
		{
		  md->ip_version_traffic_class_and_flow_label =
		    ih6->ip_version_traffic_class_and_flow_label;
		  md->hop_limit = ih6->hop_limit;
		  ih6->ip_version_traffic_class_and_flow_label = 0x60;
		  ih6->hop_limit = 0;
		}
	      else
		{
		  md->tos = ih4->tos;
		  md->ttl = ih4->ttl;
		  ih4->tos = 0;
		  ih4->ttl = 0;
		  ih4->checksum = 0;
		  ih4->flags_and_fragment_offset = 0;
		}

	      JOB_AES_HMAC *job = IPSECMB_FUNC (get_next_job) (mgr);
	      job->src = vlib_buffer_get_current (b0);
	      job->hash_start_src_offset_in_bytes = 0;
	      job->cipher_mode = NULL_CIPHER;
	      job->hash_alg = imbm->integ_algs[sa0->integ_alg].hash_alg;
	      job->auth_tag_output_len_in_bytes =
		imbm->integ_algs[sa0->integ_alg].hash_output_length;
	      job->auth_tag_output = icv;
	      job->msg_len_to_hash_in_bytes = b0->current_length + seq_size;
	      job->cipher_direction = DECRYPT;
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
	      ah_finish_decrypt (vm, node, job, &bi0, &next0, is_ip6);
	    }
	  else
	    {
	      remove_ah (vm, node, &bi0, &next0, sa0, ip_hdr_size, icv_size,
			 0, ah0, is_ip6);
	    }
	trace:
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      b0->flags |= VLIB_BUFFER_IS_TRACED;
	      ah_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->integ_alg = sa0->integ_alg;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      if (0 == n_left_from)
	{
	  JOB_AES_HMAC *job = NULL;
	  while (n_left_to_next > 0 && (job = IPSECMB_FUNC (flush_job) (mgr)))
	    {
	      --packets_in_flight;
	      ASSERT (STS_COMPLETED == job->status);
	      u32 bi0, next0;
	      ah_finish_decrypt (vm, node, job, &bi0, &next0, is_ip6);
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ipsec_sa_t *sa0 = pool_elt_at_index (im->sad,
						       vnet_buffer
						       (b0)->ipsec.sad_index);
		  b0->flags |= VLIB_BUFFER_IS_TRACED;
		  ah_decrypt_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->integ_alg = sa0->integ_alg;
		}
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index, AH_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (ah4_decrypt_ipsecmb_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return ah_decrypt_ipsecmb_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

VLIB_NODE_FN (ah6_decrypt_ipsecmb_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return ah_decrypt_ipsecmb_inline (vm, node, from_frame, 1 /*is_ip6 */ );
}
#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah4_decrypt_ipsecmb_node) = {
    .name = "ah4-decrypt-ipsecmb",
    .vector_size = sizeof (u32),
    .format_trace = format_ah_decrypt_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN (ah_decrypt_error_strings),
    .error_strings = ah_decrypt_error_strings,

    .n_next_nodes = AH_DECRYPT_N_NEXT,
    .next_nodes =
        {
#define _(s, n) [AH_DECRYPT_NEXT_##s] = n,
            foreach_ah_decrypt_next
#undef _
        },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah6_decrypt_ipsecmb_node) = {
    .name = "ah6-decrypt-ipsecmb",
    .vector_size = sizeof (u32),
    .format_trace = format_ah_decrypt_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN (ah_decrypt_error_strings),
    .error_strings = ah_decrypt_error_strings,

    .n_next_nodes = AH_DECRYPT_N_NEXT,
    .next_nodes =
        {
#define _(s, n) [AH_DECRYPT_NEXT_##s] = n,
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
