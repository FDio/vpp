/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/ipsec/ah.h>
#include <vnet/ipsec/ipsec_io.h>

always_inline void
ah_encrypt_finish_one (vlib_buffer_t * b0, int is_ip6)
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

always_inline void
ah_encrypt_finish_inline (vlib_main_t * vm, ipsec_main_t * im, u16 * next,
			  ipsec_job_desc_t * job, int n_jobs, int is_ip6)
{
  while (n_jobs)
    {
      if (IPSEC_ERR_OK == job->error)
	{
	  vlib_buffer_t *b0 = job->b;
	  ah_encrypt_finish_one (b0, is_ip6);
	  if (!job->sa->is_tunnel && !job->sa->is_tunnel_ip6)
	    {
	      vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
	    }
	}
      next[0] = job->next;
      ++next;
      ++job;
      --n_jobs;
    }
}

void
ah_encrypt_finish (vlib_main_t * vm, ipsec_main_t * im, u16 * next,
		   ipsec_job_desc_t * job, int n_jobs, int is_ip6)
{
  if (is_ip6)
    ah_encrypt_finish_inline (vm, im, next, job, n_jobs, 1 /*is_ip6 */ );
  else
    ah_encrypt_finish_inline (vm, im, next, job, n_jobs, 0 /*is_ip6 */ );
}

always_inline void
ah_encrypt_prepare_jobs_inline (vlib_main_t * vm, u32 thread_index,
				ipsec_main_t * im, ipsec_proto_main_t * em,
				vlib_buffer_t ** b, ipsec_job_desc_t * job,
				int n_jobs, int is_ip6, u32 next_index_drop,
				u32 next_index_interface_output)
{
  while (n_jobs > 0)
    {
      int icv_size = 0;
      ip4_header_t *ih4, *oh4 = 0;
      ip6_header_t *ih6, *oh6 = 0;
      ah_header_t *ah = 0;
      u8 next_hdr_type;
      ssize_t adv;

      job->next = next_index_drop;
      vlib_buffer_t *b0 = job->b = *b;
      u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
      ipsec_sa_t *sa0 = job->sa = pool_elt_at_index (im->sad, sa_index0);

      if (PREDICT_FALSE (sa_seq_advance (job->sa)))
	{
	  job->error = IPSEC_ERR_SEQ_CYCLED;
	  goto next;
	}

      vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				       sa_index0, 1,
				       vlib_buffer_length_in_chain (vm, b0));

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

      icv_size = em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
      const u8 padding_len = ah_calc_icv_padding_len (icv_size, is_ip6);
      adv -= padding_len;
      /* transport mode save the eth header before it is overwritten */
      if (PREDICT_FALSE (!sa0->is_tunnel))
	{
	  ethernet_header_t *ieh0 = (ethernet_header_t *)
	    ((u8 *) vlib_buffer_get_current (b0) -
	     sizeof (ethernet_header_t));
	  ethernet_header_t *oeh0 =
	    (ethernet_header_t *) ((u8 *) ieh0 + (adv - icv_size));
	  clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	  job->next = next_index_interface_output;
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
	  job->next = sa0->dpo[IPSEC_PROTOCOL_AH].dpoi_next_node;
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
	    sa0->dpo[IPSEC_PROTOCOL_AH].dpoi_index;
	}
      else if (is_ip6 && sa0->is_tunnel && sa0->is_tunnel_ip6)
	{
	  oh6->src_address.as_u64[0] = sa0->tunnel_src_addr.ip6.as_u64[0];
	  oh6->src_address.as_u64[1] = sa0->tunnel_src_addr.ip6.as_u64[1];
	  oh6->dst_address.as_u64[0] = sa0->tunnel_dst_addr.ip6.as_u64[0];
	  oh6->dst_address.as_u64[1] = sa0->tunnel_dst_addr.ip6.as_u64[1];
	  job->next = sa0->dpo[IPSEC_PROTOCOL_AH].dpoi_next_node;
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
	    sa0->dpo[IPSEC_PROTOCOL_AH].dpoi_index;
	}

      memset (ah + 1, 0, icv_size);

      if (sa0->use_esn)
	{
	  u32 *esn;
	  void *tmp;
	  ipsec_merge_chain_to_job_data (vm, job, 0, sizeof (u32), &tmp);
	  esn = tmp;
	  *esn = sa0->seq_hi;
	  b0->current_length += sizeof (u32);
	  b0->total_length_not_including_first_buffer += sizeof (u32);
	}
      else
	{
	  ipsec_merge_chain_to_job_data (vm, job, 0, 0, 0);
	}

      job->msg_len_to_hash_in_bytes = job->data_len;
      job->icv_output_len_in_bytes =
	em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
      job->icv_dst = ah + 1;
      job->error = IPSEC_ERR_OK;
    next:
      --n_jobs;
      ++b;
      ++job;
    }
}

void
ah_encrypt_prepare_jobs (vlib_main_t * vm, u32 thread_index,
			 ipsec_main_t * im, ipsec_proto_main_t * em,
			 vlib_buffer_t ** b, ipsec_job_desc_t * job,
			 int n_jobs, int is_ip6, u32 next_index_drop,
			 u32 next_index_interface_output)
{
  if (is_ip6)
    return ah_encrypt_prepare_jobs_inline (vm, thread_index, im, em, b, job,
					   n_jobs, 1 /*is_ip6 */ ,
					   next_index_drop,
					   next_index_interface_output);
  else
    return ah_encrypt_prepare_jobs_inline (vm, thread_index, im, em, b, job,
					   n_jobs, 0 /*is_ip6 */ ,
					   next_index_drop,
					   next_index_interface_output);
}

always_inline void
ah_decrypt_prepare_jobs_inline (vlib_main_t * vm, u32 thread_index,
				ipsec_main_t * im, ipsec_proto_main_t * em,
				vlib_buffer_t ** b, ipsec_job_desc_t * job,
				int n_jobs, int is_ip6, u32 next_index_drop)
{
  while (n_jobs > 0)
    {
      int icv_size = 0;
      ah_header_t *ah0;
      u32 seq;
      ip4_header_t *ih4 = 0;
      ip6_header_t *ih6 = 0;
      u8 ip_hdr_size = 0;

      job->src = NULL;
      job->next = next_index_drop;

      vlib_buffer_t *b0 = job->b = *b;
      u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
      ipsec_sa_t *sa0 = job->sa = pool_elt_at_index (im->sad, sa_index0);

      ih4 = vlib_buffer_get_current (b0);
      ih6 = vlib_buffer_get_current (b0);

      vlib_prefetch_combined_counter (&ipsec_sa_counters, thread_index,
				      sa_index0);

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
      if (sa0->use_anti_replay)
	{
	  int rv = 0;

	  if (PREDICT_TRUE (sa0->use_esn))
	    rv = sa_replay_check_esn (sa0, seq);
	  else
	    rv = sa_replay_check (sa0, seq);

	  if (PREDICT_FALSE (rv))
	    {
	      job->error = IPSEC_ERR_REPLAY;
	      goto next;
	    }
	}

      vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				       sa_index0, 1,
				       vlib_buffer_length_in_chain (vm, b0));
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
	      vnet_buffer (b0)->
		ipsec.ip_version_traffic_class_and_flow_label =
		ih6->ip_version_traffic_class_and_flow_label;
	      vnet_buffer (b0)->ipsec.ttl_or_hop_limit = ih6->hop_limit;
	      ih6->ip_version_traffic_class_and_flow_label = 0x60;
	      ih6->hop_limit = 0;
	    }
	  else
	    {
	      vnet_buffer (b0)->ipsec.tos = ih4->tos;
	      vnet_buffer (b0)->ipsec.ttl_or_hop_limit = ih4->ttl;
	      ih4->tos = 0;
	      ih4->ttl = 0;
	      ih4->checksum = 0;
	      ih4->flags_and_fragment_offset = 0;
	    }

	  if (sa0->use_esn)
	    {
	      u32 *esn;
	      void *tmp;
	      ipsec_merge_chain_to_job_data (vm, job, 0, sizeof (u32), &tmp);
	      esn = tmp;
	      *esn = sa0->seq_hi;
	      b0->current_length += sizeof (u32);
	      b0->total_length_not_including_first_buffer += sizeof (u32);
	    }
	  else
	    {
	      ipsec_merge_chain_to_job_data (vm, job, 0, 0, 0);
	    }

	  job->msg_len_to_hash_in_bytes = job->data_len;
	  job->icv_output_len_in_bytes =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	  job->icv_dst = icv;
	}
      else
	{
	  job->msg_len_to_hash_in_bytes = 0;
	}
      job->error = IPSEC_ERR_OK;
    next:
      --n_jobs;;
      ++b;
      ++job;
    }
}

void
ah_decrypt_prepare_jobs (vlib_main_t * vm, u32 thread_index,
			 ipsec_main_t * im, ipsec_proto_main_t * em,
			 vlib_buffer_t ** b, ipsec_job_desc_t * job,
			 int n_jobs, int is_ip6, u32 next_index_drop)
{
  if (is_ip6)
    return ah_decrypt_prepare_jobs_inline (vm, thread_index, im, em, b, job,
					   n_jobs, 1 /*is_ip6 */ ,
					   next_index_drop);
  else
    return ah_decrypt_prepare_jobs_inline (vm, thread_index, im, em, b, job,
					   n_jobs, 0 /*is_ip6 */ ,
					   next_index_drop);
}

always_inline void
ipsec_remove_ah (vlib_main_t * vm, ipsec_job_desc_t * job, u32 ip_hdr_size,
		 u32 icv_size, u8 icv_padding_len, ah_header_t * ah0,
		 int is_ip6, u32 next_index_drop, u32 next_index_ip4_input,
		 u32 next_index_ip6_input, u32 next_index_gre_input)
{
  vlib_buffer_t *b0 = job->b;
  if (job->sa->is_tunnel)
    {				/* tunnel mode */
      vlib_buffer_advance (b0, ip_hdr_size + sizeof (ah_header_t) + icv_size +
			   icv_padding_len);
      if (ah0->nexthdr == IP_PROTOCOL_IP_IN_IP)
	job->next = next_index_ip4_input;
      else if (ah0->nexthdr == IP_PROTOCOL_IPV6)
	job->next = next_index_ip6_input;
      else
	{
	  job->next = next_index_drop;
	  job->error = IPSEC_ERR_NOT_IP;
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

	  job->next = next_index_ip6_input;
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

	  job->next = next_index_ip4_input;
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
      job->next = next_index_gre_input;
    }
}

always_inline void
ah_decrypt_finish_one (vlib_main_t * vm, ipsec_job_desc_t * job, int is_ip6,
		       u32 next_index_drop, u32 next_index_ip4_input,
		       u32 next_index_ip6_input, u32 next_index_gre_input)
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
	vnet_buffer (job->b)->ipsec.ip_version_traffic_class_and_flow_label;
      ih6->hop_limit = vnet_buffer (job->b)->ipsec.ttl_or_hop_limit;
    }
  else
    {
      ip_hdr_size = ip4_header_bytes (ih4);
      ih4->ttl = vnet_buffer (job->b)->ipsec.ttl_or_hop_limit;
      ih4->tos = vnet_buffer (job->b)->ipsec.tos;
    }

  u8 icv_padding_len = ah_calc_icv_padding_len (icv_size, is_ip6);
  ah_header_t *ah0 =
    (ah_header_t *) ((u8 *) vlib_buffer_get_current (b0) + ip_hdr_size);
  void *digest = ah0 + 1;
  if (PREDICT_FALSE (memcmp (digest, job->icv, icv_size)))
    {
      job->next = next_index_drop;
      job->error = IPSEC_ERR_INTEG_ERROR;
      return;
    }

  if (PREDICT_TRUE (sa0->use_anti_replay))
    {
      if (PREDICT_TRUE (sa0->use_esn))
	sa_replay_advance_esn (sa0, clib_host_to_net_u32 (ah0->seq_no));
      else
	sa_replay_advance (sa0, clib_host_to_net_u32 (ah0->seq_no));
    }
  ipsec_remove_ah (vm, job, ip_hdr_size, icv_size, icv_padding_len, ah0,
		   is_ip6, next_index_drop, next_index_ip4_input,
		   next_index_ip6_input, next_index_gre_input);
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
}

always_inline void
ah_decrypt_finish_inline (vlib_main_t * vm, u16 * next,
			  ipsec_job_desc_t * job, int n_jobs, int is_ip6,
			  u32 next_index_drop, u32 next_index_ip4_input,
			  u32 next_index_ip6_input, u32 next_index_gre_input)
{
  while (n_jobs)
    {
      if (IPSEC_ERR_OK == job->error)
	{
	  ah_decrypt_finish_one (vm, job, is_ip6, next_index_drop,
				 next_index_ip4_input, next_index_ip6_input,
				 next_index_gre_input);
	}
      next[0] = job->next;
      ++next;
      ++job;
      --n_jobs;
    }
}

void
ah_decrypt_finish (vlib_main_t * vm, u16 * next, ipsec_job_desc_t * job,
		   int n_jobs, int is_ip6, u32 next_index_drop,
		   u32 next_index_ip4_input, u32 next_index_ip6_input,
		   u32 next_index_gre_input)
{
  if (is_ip6)
    return ah_decrypt_finish_inline (vm, next, job, n_jobs, 1 /*is_ip6 */ ,
				     next_index_drop, next_index_ip4_input,
				     next_index_ip6_input,
				     next_index_gre_input);
  else
    return ah_decrypt_finish_inline (vm, next, job, n_jobs, 0 /*is_ip6 */ ,
				     next_index_drop, next_index_ip4_input,
				     next_index_ip6_input,
				     next_index_gre_input);
}
