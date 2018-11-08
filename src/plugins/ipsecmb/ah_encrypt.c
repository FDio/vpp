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
 _(ENCRYPT_FAILED, "AH encryption failed")         \
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
  ipsecmb_error_e error;
  JOB_STS sts;
  ipsec_integ_alg_t integ_alg;
} ipsecmb_ah_encrypt_trace_t;

/* packet trace format function */
static u8 *
format_ipsecmb_ah_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsecmb_ah_encrypt_trace_t *t =
    va_arg (*args, ipsecmb_ah_encrypt_trace_t *);

  s = format (s, "ah: spi: %u seq: %u integrity: %U error: %U sts: %U",
	      t->spi, t->seq, format_ipsec_integ_alg, t->integ_alg,
	      format_ipsecmb_error, t->error, format_ipsecmb_sts, t->sts);
  return s;
}

#ifdef CLIB_MARCH_VARIANT
always_inline void
ipsecmb_ah_finish_encrypt (vlib_main_t * vm, vlib_buffer_t * b0, int is_ip6)
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
ipsecmb_ah_encrypt_inline (vlib_main_t * vm,
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
      ip4_header_t *ih4, *oh4 = 0;
      ip6_header_t *ih6, *oh6 = 0;
      ah_header_t *ah = 0;
      u8 next_hdr_type;

      job->next = AH_ENCRYPT_NEXT_DROP;
      vlib_buffer_t *b0 = job->b = *b;
      u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
      ipsec_sa_t *sa0 = job->sa = pool_elt_at_index (im->sad, sa_index0);
      job->samb = pool_elt_at_index (imbm->sad, sa_index0);

      if (PREDICT_FALSE (esp_seq_advance (job->sa)))
	{
	  vlib_node_increment_counter (vm, node->node_index,
				       AH_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	  job->error = IMB_ERR_SEQ_CYCLED;
	  job->src = NULL;
	  goto next;
	}


      sa0->total_data_size += vlib_buffer_length_in_chain (vm, b0);

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

      icv_size = em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
      /* transport mode save the eth header before it is overwritten */
      if (PREDICT_FALSE (!sa0->is_tunnel))
	{
	  ethernet_header_t *ieh0 = (ethernet_header_t *)
	    ((u8 *) vlib_buffer_get_current (b0) -
	     sizeof (ethernet_header_t));
	  ethernet_header_t *oeh0 =
	    (ethernet_header_t *) ((u8 *) ieh0 + (adv - icv_size));
	  clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	  job->next = AH_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	}

      vlib_buffer_advance (b0, adv - icv_size);

      if (is_ip6)
	{
	  ih6 = (ip6_header_t *) ih4;
	  oh6 = vlib_buffer_get_current (b0);
	  ah = (ah_header_t *) (oh6 + 1);
	  vnet_buffer (b0)->ipsec.ttl_or_hop_limit = ih6->hop_limit;
	  vnet_buffer (b0)->ipsec.ip_version_traffic_class_and_flow_label =
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

	  job->next = AH_ENCRYPT_NEXT_IP4_LOOKUP;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	}
      else if (is_ip6 && sa0->is_tunnel && sa0->is_tunnel_ip6)
	{
	  oh6->src_address.as_u64[0] = sa0->tunnel_src_addr.ip6.as_u64[0];
	  oh6->src_address.as_u64[1] = sa0->tunnel_src_addr.ip6.as_u64[1];
	  oh6->dst_address.as_u64[0] = sa0->tunnel_dst_addr.ip6.as_u64[0];
	  oh6->dst_address.as_u64[1] = sa0->tunnel_dst_addr.ip6.as_u64[1];
	  job->next = AH_ENCRYPT_NEXT_IP6_LOOKUP;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	}

      memset (ah + 1, 0, icv_size);

      if (sa0->use_esn)
	{
	  u32 *esn;
	  void *tmp;
	  ipsecmb_merge_chain_to_job_data (vm, job, 0, sizeof (u32), &tmp);
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
      job->icv_dst = ah + 1;
      job->error = IMB_ERR_OK;
    next:
      --n_left_from;
      ++b;
      ++job;
    }

  //submit all the jobs for processing to ipsec library
  ipsecmb_process_jobs (vm, t->mb_mgr, t->jobs, from_frame->n_vectors,
			ENCRYPT, HASH_CIPHER, IPSECMB_FUNC (get_next_job),
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
					   AH_ENCRYPT_ERROR_ENCRYPT_FAILED,
					   1);
	      job->error = IMB_ERR_ENCRYPTION_FAILED;
	    }
	  else
	    {
	      vlib_buffer_t *b0 = job->b;
	      ipsecmb_ah_finish_encrypt (vm, b0, is_ip6);
	      if (!job->sa->is_tunnel && !job->sa->is_tunnel_ip6)
		{
		  vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
		}
	    }
	}
      if (PREDICT_FALSE (job->b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsecmb_ah_encrypt_trace_t *tr =
	    vlib_add_trace (vm, node, job->b, sizeof (*tr));
	  u32 sa_index0 = vnet_buffer (job->b)->ipsec.sad_index;
	  ipsec_sa_t *sa0 = pool_elt_at_index (im->sad, sa_index0);
	  tr->spi = sa0->spi;
	  tr->seq = sa0->seq - 1;
	  tr->integ_alg = sa0->integ_alg;
	  tr->error = job->error;
	  tr->sts = job->sts;
	}
      next[0] = job->next;
      next += 1;
    };

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index, AH_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);
  return from_frame->n_vectors;
}

VLIB_NODE_FN (ipsecmb_ah4_encrypt_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return ipsecmb_ah_encrypt_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

VLIB_NODE_FN (ipsecmb_ah6_encrypt_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return ipsecmb_ah_encrypt_inline (vm, node, from_frame, 1 /*is_ip6 */ );
}

#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsecmb_ah4_encrypt_node) = {
  .name = "ah4-encrypt-ipsecmb",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsecmb_ah_encrypt_trace,
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
VLIB_REGISTER_NODE (ipsecmb_ah6_encrypt_node) = {
  .name = "ah6-encrypt-ipsecmb",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsecmb_ah_encrypt_trace,
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
