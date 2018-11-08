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
  ipsecmb_error_e error;
  JOB_STS sts;
  ipsec_integ_alg_t integ_alg;
} ipsecmb_ah_decrypt_trace_t;

/* packet trace format function */
static u8 *
format_ipsecmb_ah_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsecmb_ah_decrypt_trace_t *t =
    va_arg (*args, ipsecmb_ah_decrypt_trace_t *);

  s =
    format (s, "ah: integrity: %U err: %U status: %U", format_ipsec_integ_alg,
	    t->integ_alg, format_ipsecmb_error, t->error, format_ipsecmb_sts,
	    t->sts);
  return s;
}

#ifdef CLIB_MARCH_VARIANT
always_inline void
ipsecmb_remove_ah (vlib_main_t * vm, vlib_node_runtime_t * node,
		   ipsecmb_job_desc_t * job, ipsec_sa_t * sa0,
		   u32 ip_hdr_size, u32 icv_size, u8 icv_padding_len,
		   ah_header_t * ah0, int is_ip6)
{
  vlib_buffer_t *b0 = job->b;
  if (sa0->is_tunnel)
    {				/* tunnel mode */
      vlib_buffer_advance (b0, ip_hdr_size + sizeof (ah_header_t) + icv_size +
			   icv_padding_len);
      if (ah0->nexthdr == IP_PROTOCOL_IP_IN_IP)
	job->next = AH_DECRYPT_NEXT_IP4_INPUT;
      else if (ah0->nexthdr == IP_PROTOCOL_IPV6)
	job->next = AH_DECRYPT_NEXT_IP6_INPUT;
      else
	{
	  clib_warning ("next header: 0x%x", ah0->nexthdr);
	  vlib_node_increment_counter (vm, node->node_index,
				       AH_DECRYPT_ERROR_DECRYPTION_FAILED, 1);
	  job->next = AH_DECRYPT_NEXT_DROP;
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

	  job->next = AH_DECRYPT_NEXT_IP6_INPUT;
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

	  job->next = AH_DECRYPT_NEXT_IP4_INPUT;
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
      job->next = AH_DECRYPT_NEXT_IPSEC_GRE_INPUT;
    }
}

always_inline void
ipsecmb_ah_finish_decrypt (vlib_main_t * vm, vlib_node_runtime_t * node,
			   ipsecmb_job_desc_t * job, int is_ip6)
{
  vlib_buffer_t *b0 = job->b;
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa0 =
    pool_elt_at_index (im->sad, vnet_buffer (b0)->ipsec.sad_index);
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 icv_size = em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
  u32 ip_hdr_size = 0;
  ip4_header_t *ih4 = vlib_buffer_get_current (b0);
  if (is_ip6)
    {
      ip_hdr_size = sizeof (ip6_header_t);
      ip6_header_t *ih6 = vlib_buffer_get_current (b0);
      ih6->ip_version_traffic_class_and_flow_label =
	job->ip_version_traffic_class_and_flow_label;
      ih6->hop_limit = job->hop_limit;
    }
  else
    {
      ip_hdr_size = ip4_header_bytes (ih4);
      ih4->ttl = job->ttl;
      ih4->tos = job->tos;
    }

  u8 icv_padding_len = ah_calc_icv_padding_len (icv_size, is_ip6);
  ah_header_t *ah0 =
    (ah_header_t *) ((u8 *) vlib_buffer_get_current (b0) + ip_hdr_size);
  void *digest = ah0 + 1;
  if (PREDICT_FALSE (memcmp (digest, job->icv, icv_size)))
    {
      vlib_node_increment_counter (vm, node->node_index,
				   AH_DECRYPT_ERROR_INTEG_ERROR, 1);
      job->next = AH_DECRYPT_NEXT_DROP;
      return;
    }

  if (PREDICT_TRUE (sa0->use_anti_replay))
    {
      if (PREDICT_TRUE (sa0->use_esn))
	esp_replay_advance_esn (sa0, clib_host_to_net_u32 (ah0->seq_no));
      else
	esp_replay_advance (sa0, clib_host_to_net_u32 (ah0->seq_no));
    }
  ipsecmb_remove_ah (vm, node, job, sa0, ip_hdr_size, icv_size,
		     icv_padding_len, ah0, is_ip6);
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
}

always_inline uword
ipsecmb_ah_decrypt_inline (vlib_main_t * vm,
			   vlib_node_runtime_t * node,
			   vlib_frame_t * from_frame, int is_ip6)
{
  ipsec_main_t *im = &ipsec_main;
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 thread_index = vlib_get_thread_index ();
  ipsecmb_per_thread_data_t *t = &imbm->per_thread_data[thread_index];;

  u32 n_left_from = from_frame->n_vectors;
  u32 *from = vlib_frame_vector_args (from_frame);
  ipsecmb_job_desc_t *job = t->jobs;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_get_buffers (vm, from, bufs, from_frame->n_vectors);

  while (n_left_from > 0)
    {
      int icv_size = 0;
      ah_header_t *ah0;
      u32 seq;
      ip4_header_t *ih4 = 0;
      ip6_header_t *ih6 = 0;
      u8 ip_hdr_size = 0;

      job->src = NULL;
      job->next = AH_DECRYPT_NEXT_DROP;

      vlib_buffer_t *b0 = job->b = *b;
      u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
      ipsec_sa_t *sa0 = job->sa = pool_elt_at_index (im->sad, sa_index0);
      job->samb = pool_elt_at_index (imbm->sad, sa_index0);

      ih4 = vlib_buffer_get_current (b0);
      ih6 = vlib_buffer_get_current (b0);

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
	      job->error = IMB_ERR_DECRYPTION_FAILED;
	      vlib_node_increment_counter (vm, node->node_index,
					   AH_DECRYPT_ERROR_REPLAY, 1);
	      goto next;
	    }
	}

      sa0->total_data_size += vlib_buffer_length_in_chain (vm, b0);
      icv_size = em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
      if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	{
	  u8 *icv =
	    (u8 *) vlib_buffer_get_current (b0) + ip_hdr_size +
	    sizeof (ah_header_t);
	  vec_validate (job->icv, icv_size);
	  clib_memcpy_fast (job->icv, icv, icv_size);
	  memset (icv, 0, icv_size);

	  if (is_ip6)
	    {
	      job->ip_version_traffic_class_and_flow_label =
		ih6->ip_version_traffic_class_and_flow_label;
	      job->hop_limit = ih6->hop_limit;
	      ih6->ip_version_traffic_class_and_flow_label = 0x60;
	      ih6->hop_limit = 0;
	    }
	  else
	    {
	      job->tos = ih4->tos;
	      job->ttl = ih4->ttl;
	      ih4->tos = 0;
	      ih4->ttl = 0;
	      ih4->checksum = 0;
	      ih4->flags_and_fragment_offset = 0;
	    }

	  if (sa0->use_esn)
	    {
	      u32 *esn;
	      void *tmp;
	      ipsecmb_merge_chain_to_job_data (vm, job, 0, sizeof (u32),
					       &tmp);
	      esn = tmp;
	      *esn = sa0->seq_hi;
	      b0->current_length += sizeof (u32);
	      b0->total_length_not_including_first_buffer += sizeof (u32);
	    }
	  else
	    {
	      ipsecmb_merge_chain_to_job_data (vm, job, 0, 0, 0);
	    }

	  job->msg_len_to_hash_in_bytes = job->data_len;
	  job->cipher_mode = NULL_CIPHER;
	  job->hash_alg = imbm->integ_algs[sa0->integ_alg].hash_alg;
	  job->icv_output_len_in_bytes =
	    imbm->integ_algs[sa0->integ_alg].hash_output_length;
	  job->icv_dst = icv;
	}
      job->error = IMB_ERR_OK;
    next:
      --n_left_from;
      ++b;
      ++job;
    }

  //submit all the jobs for processing to ipsec library
  ipsecmb_process_jobs (vm, t->mb_mgr, t->jobs, from_frame->n_vectors,
			DECRYPT, HASH_CIPHER, IPSECMB_FUNC (get_next_job),
			IPSECMB_FUNC (submit_job),
			IPSECMB_FUNC (flush_job), is_ip6);
  // wrap things up
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  int i;
  for (i = 0; i < from_frame->n_vectors; ++i)
    {
      job = &t->jobs[i];
      if (IMB_ERR_OK == job->error)
	{
	  if (job->sts != STS_COMPLETED)
	    {
	      vlib_node_increment_counter (vm, node->node_index,
					   AH_DECRYPT_ERROR_DECRYPTION_FAILED,
					   1);
	    }
	  else
	    {
	      ipsecmb_ah_finish_decrypt (vm, node, job, is_ip6);
	    }
	}
      if (PREDICT_FALSE (job->b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsecmb_ah_decrypt_trace_t *tr =
	    vlib_add_trace (vm, node, job->b, sizeof (*tr));
	  u32 sa_index0 = vnet_buffer (job->b)->ipsec.sad_index;
	  ipsec_sa_t *sa0 = pool_elt_at_index (im->sad, sa_index0);
	  tr->integ_alg = sa0->integ_alg;
	  tr->error = job->error;
	  tr->sts = job->sts;
	}
      next[0] = job->next;
      next += 1;
    };

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index, AH_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);
  return from_frame->n_vectors;
}

VLIB_NODE_FN (ipsecmb_ah4_decrypt_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return ipsecmb_ah_decrypt_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

VLIB_NODE_FN (ipsecmb_ah6_decrypt_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return ipsecmb_ah_decrypt_inline (vm, node, from_frame, 1 /*is_ip6 */ );
}
#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsecmb_ah4_decrypt_node) = {
    .name = "ah4-decrypt-ipsecmb",
    .vector_size = sizeof (u32),
    .format_trace = format_ipsecmb_ah_decrypt_trace,
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
VLIB_REGISTER_NODE (ipsecmb_ah6_decrypt_node) = {
    .name = "ah6-decrypt-ipsecmb",
    .vector_size = sizeof (u32),
    .format_trace = format_ipsecmb_ah_decrypt_trace,
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
