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

#include <vnet/ipsec/ipsec_io.h>
#include <vnet/ipsec/esp.h>

u8 *
format_ipsec_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_trace_t *t = va_arg (*args, ipsec_trace_t *);

  s =
    format (s,
	    "spi: %u seq: %u crypto: %U integrity: %U error: %U\n",
	    t->spi, t->seq, format_ipsec_crypto_alg, t->crypto_alg,
	    format_ipsec_integ_alg, t->integ_alg, format_ipsec_error,
	    t->error, t->udp_encap ? " udp-encap-enabled" : "");
  s = format (s, "  data_len: %d crypto_len: %d hash_len: %d",
	      t->data_len, t->crypto_len, t->hash_len);
  return s;
}

always_inline void
ipsec_ip4_fill_comon_values (ip4_header_t * oh4, u8 tos)
{
  oh4->ip_version_and_header_length = 0x45;
  oh4->tos = tos;
  oh4->fragment_id = 0;
  oh4->flags_and_fragment_offset = 0;
  oh4->ttl = 254;
}

always_inline void
ipsec_handle_udp_encap (ipsec_sa_t * sa0, esp_header_t ** esp,
			ip4_header_t * oh4)
{
  if (sa0->udp_encap)
    {
      *esp = (esp_header_t *) ((u8 *) * esp + sizeof (udp_header_t));
      udp_header_t *udp = (udp_header_t *) (oh4 + 1);
      udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      udp->checksum = 0;
      oh4->protocol = IP_PROTOCOL_UDP;
    }
  else
    {
      oh4->protocol = IP_PROTOCOL_IPSEC_ESP;
    }
}

always_inline void
esp_encrypt_prepare_tunnel_headers (ipsec_job_desc_t * job,
				    u8 * next_hdr_type, esp_header_t ** esp,
				    u32 iv_size, int is_ip6,
				    u32 next_ip4_lookup, u32 next_ip6_lookup)
{
  vlib_buffer_t *b0 = job->b;
  ipsec_sa_t *sa0 = job->sa;
  if (is_ip6)
    {
      ip6_header_t *ih6 = vlib_buffer_get_current (b0);
      job->next = next_ip6_lookup;
      *next_hdr_type = IP_PROTOCOL_IPV6;
      ip6_header_t *oh6 =
	(ip6_header_t *) ((u8 *) ih6 - sizeof (esp_header_t) -
			  sizeof (ip6_header_t) - iv_size);
      oh6->src_address.as_u64[0] = sa0->tunnel_src_addr.ip6.as_u64[0];
      oh6->src_address.as_u64[1] = sa0->tunnel_src_addr.ip6.as_u64[1];
      oh6->dst_address.as_u64[0] = sa0->tunnel_dst_addr.ip6.as_u64[0];
      oh6->dst_address.as_u64[1] = sa0->tunnel_dst_addr.ip6.as_u64[1];

      vlib_buffer_advance (b0, -(sizeof (esp_header_t) +
				 sizeof (ip6_header_t) + iv_size));
      oh6->ip_version_traffic_class_and_flow_label =
	ih6->ip_version_traffic_class_and_flow_label;
      oh6->protocol = IP_PROTOCOL_IPSEC_ESP;
      oh6->hop_limit = 254;
      *esp = (esp_header_t *) (oh6 + 1);
    }
  else
    {				/* is ipv4 */
      ip4_header_t *ih4 = vlib_buffer_get_current (b0);

      job->next = next_ip4_lookup;
      u32 udp_hdr_size = 0;
      if (sa0->udp_encap)
	{
	  udp_hdr_size = sizeof (udp_header_t);
	}
      *next_hdr_type = IP_PROTOCOL_IP_IN_IP;
      ip4_header_t *oh4 =
	(ip4_header_t *) (((u8 *) ih4) - sizeof (ip4_header_t) -
			  sizeof (esp_header_t) - udp_hdr_size - iv_size);
      oh4->src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
      oh4->dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;
      vlib_buffer_advance (b0,
			   -(sizeof (ip4_header_t) + sizeof (esp_header_t) +
			     udp_hdr_size + iv_size));
      *esp = (esp_header_t *) (oh4 + 1);

      ipsec_ip4_fill_comon_values (oh4, ih4->tos);
      ipsec_handle_udp_encap (sa0, esp, oh4);
    }
  job->next = sa0->dpo[IPSEC_PROTOCOL_ESP].dpoi_next_node;
  vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
    sa0->dpo[IPSEC_PROTOCOL_ESP].dpoi_index;
}

always_inline void
esp_encrypt_prepare_transport_headers (ipsec_job_desc_t * job,
				       u8 * next_hdr_type,
				       esp_header_t ** esp, u32 iv_size,
				       int is_ip6, u32 next_ip4_lookup,
				       u32 next_ip6_lookup)
{
  vlib_buffer_t *b0 = job->b;
  ipsec_sa_t *sa0 = job->sa;
  if (is_ip6)
    {
      ip6_header_t *ih6 = vlib_buffer_get_current (b0);
      ip6_header_t *oh6 =
	(ip6_header_t *) ((u8 *) ih6 - sizeof (esp_header_t) - iv_size);
      job->next = next_ip6_lookup;
      *next_hdr_type = ih6->protocol;
      if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
	{
	  ethernet_header_t *ieh0, *oeh0;
	  ieh0 = (ethernet_header_t *) vlib_buffer_get_current (b0) - 1;
	  oeh0 = (ethernet_header_t *) oh6 - 1;
	  clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	}
      oh6->src_address.as_u64[0] = ih6->src_address.as_u64[0];
      oh6->src_address.as_u64[1] = ih6->src_address.as_u64[1];
      oh6->dst_address.as_u64[0] = ih6->dst_address.as_u64[0];
      oh6->dst_address.as_u64[1] = ih6->dst_address.as_u64[1];
      oh6->ip_version_traffic_class_and_flow_label =
	ih6->ip_version_traffic_class_and_flow_label;
      oh6->protocol = IP_PROTOCOL_IPSEC_ESP;
      oh6->hop_limit = 254;
      vlib_buffer_advance (b0, -(sizeof (esp_header_t) + iv_size));
      *esp = (esp_header_t *) (oh6 + 1);
    }
  else
    {				/* is ipv4 */
      ip4_header_t *ih4 = vlib_buffer_get_current (b0);
      job->next = next_ip4_lookup;
      u32 udp_hdr_size = 0;
      if (sa0->udp_encap)
	{
	  udp_hdr_size = sizeof (udp_header_t);
	}
      *next_hdr_type = ih4->protocol;
      ip4_header_t *oh4 =
	(ip4_header_t *) (((u8 *) ih4) - sizeof (esp_header_t) -
			  udp_hdr_size - iv_size);
      if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
	{
	  ethernet_header_t *ieh0, *oeh0;
	  ieh0 = (ethernet_header_t *) vlib_buffer_get_current (b0) - 1;
	  oeh0 = (ethernet_header_t *) oh4 - 1;
	  clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	}
      oh4->src_address.as_u32 = ih4->src_address.as_u32;
      oh4->dst_address.as_u32 = ih4->dst_address.as_u32;
      vlib_buffer_advance (b0,
			   -(sizeof (esp_header_t) + udp_hdr_size + iv_size));
      *esp = (esp_header_t *) (oh4 + 1);

      ipsec_ip4_fill_comon_values (oh4, ih4->tos);
      ipsec_handle_udp_encap (sa0, esp, oh4);
    }
}

always_inline void
esp_encrypt_finish_one (vlib_main_t * vm, ipsec_job_desc_t * job,
			int thread_index, int is_ip6,
			u32 next_index_drop, u32 next_index_interface_output)
{
  ip4_header_t *oh4 = 0;
  udp_header_t *udp = 0;
  ip6_header_t *oh6 = 0;
  vlib_buffer_t *b0 = job->b;
  oh4 = vlib_buffer_get_current (b0);
  oh6 = vlib_buffer_get_current (b0);
  if (job->src == job->data)
    {
      ipsec_split_job_data_to_chain (vm, next_index_drop, job, job->data_len);
    }
  else
    {
      job->b->current_length += job->data_len;
    }
  if (is_ip6)
    {
      oh6->payload_length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			      sizeof (ip6_header_t));
    }
  else
    {
      oh4->length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
      oh4->checksum = ip4_header_checksum (oh4);
      if (job->sa->udp_encap)
	{
	  udp = (udp_header_t *) (oh4 + 1);
	  udp->length =
	    clib_host_to_net_u16 (clib_net_to_host_u16 (oh4->length) -
				  ip4_header_bytes (oh4));
	}
    }

  if (!job->sa->is_tunnel)
    {
      job->next = next_index_interface_output;
      vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
    }
}

always_inline void
esp_encrypt_finish_inline (vlib_main_t * vm, ipsec_main_t * im,
			   u16 * next, ipsec_job_desc_t * job,
			   u32 n_jobs, int thread_index, int is_ip6,
			   u32 next_index_drop,
			   u32 next_index_interface_output)
{
  while (n_jobs)
    {
      if (IPSEC_ERR_OK == job->error)
	{
	  esp_encrypt_finish_one (vm, job, thread_index, is_ip6,
				  next_index_drop,
				  next_index_interface_output);
	}

      next[0] = job->next;
      ++next;
      ++job;
      --n_jobs;
    }
}

void
esp_encrypt_finish (vlib_main_t * vm, ipsec_main_t * im, u16 * next,
		    ipsec_job_desc_t * job, u32 n_jobs,
		    int thread_index, int is_ip6, u32 next_index_drop,
		    u32 next_index_interface_output)
{
  if (is_ip6)
    return esp_encrypt_finish_inline (vm, im, next, job, n_jobs,
				      thread_index, 1 /*is_ip6 */ ,
				      next_index_drop,
				      next_index_interface_output);
  else
    return esp_encrypt_finish_inline (vm, im, next, job, n_jobs,
				      thread_index, 0 /*is_ip6 */ ,
				      next_index_drop,
				      next_index_interface_output);
}

always_inline void
esp_encrypt_prepare_jobs_inline (vlib_main_t * vm, u32 thread_index,
				 ipsec_main_t * im, ipsec_proto_main_t * em,
				 vlib_buffer_t ** b, ipsec_job_desc_t * job,
				 u32 n_jobs, int is_ip6,
				 int (*random_bytes) (u8 * dest, int len),
				 u32 next_index_drop,
				 u32 next_index_ip4_lookup,
				 u32 next_index_ip6_lookup)
{
  while (n_jobs > 0)
    {
      esp_header_t *esp = 0;
      u8 next_hdr_type;

      job->next = next_index_drop;
      vlib_buffer_t *b0 = job->b = *b;
      u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
      ipsec_sa_t *sa0 = job->sa = pool_elt_at_index (im->sad, sa_index0);

      vlib_prefetch_combined_counter (&ipsec_sa_counters, thread_index,
				      sa_index0);

      if (sa_seq_advance (sa0))
	{
	  job->error = IPSEC_ERR_SEQ_CYCLED;
	  goto next;
	}

      vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				       sa_index0, 1,
				       vlib_buffer_length_in_chain (vm, b0));

      const int iv_size =
	em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;
      if (sa0->is_tunnel)
	esp_encrypt_prepare_tunnel_headers (job, &next_hdr_type, &esp,
					    iv_size, is_ip6,
					    next_index_ip4_lookup,
					    next_index_ip6_lookup);
      else
	esp_encrypt_prepare_transport_headers (job, &next_hdr_type, &esp,
					       iv_size, is_ip6,
					       next_index_ip4_lookup,
					       next_index_ip6_lookup);

      esp->spi = clib_net_to_host_u32 (sa0->spi);
      esp->seq = clib_net_to_host_u32 (sa0->seq);
      ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);

      if (PREDICT_TRUE (IPSEC_INTEG_ALG_NONE != sa0->integ_alg))
	{
	  job->icv_output_len_in_bytes =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	}
      else
	{
	  job->icv_output_len_in_bytes = 0;
	}

      esp_footer_t *f0;
      u32 *esn = 0;
      const int hash_payload_offset =
	(u8 *) (esp) - (u8 *) vlib_buffer_get_current (b0);
      const int cipher_headers_len = sizeof (esp_header_t) + iv_size;
      const int cipher_payload_offset =
	hash_payload_offset + cipher_headers_len;
      if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
	{
	  const int block_size =
	    em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;
	  const int cipher_payload_length =
	    vlib_buffer_length_in_chain (vm, b0) - cipher_payload_offset;
	  const int blocks = 1 + (cipher_payload_length + 1) / block_size;

	  /* pad packet in input buffer */
	  u8 pad_bytes =
	    block_size * blocks - sizeof (esp_footer_t) -
	    cipher_payload_length;

	  if (1 != random_bytes ((u8 *) (esp + 1), iv_size))
	    {
	      job->error = IPSEC_ERR_RND_GEN_FAILED;
	      job->next = next_index_drop;
	      goto next;
	    }
	  job->iv = (u8 *) (esp + 1);
	  job->iv_len_in_bytes = iv_size;

	  void *tmp;
	  u8 *padding;
	  if (sa0->use_esn)
	    {
	      ipsec_merge_chain_to_job_data (vm, job, hash_payload_offset,
					     job->icv_output_len_in_bytes
					     + pad_bytes +
					     sizeof (esp_footer_t) +
					     sizeof (u32), &tmp);
	      padding = tmp;
	      esn = (u32 *) (padding + pad_bytes + sizeof (esp_footer_t));
	    }
	  else
	    {
	      ipsec_merge_chain_to_job_data (vm, job, hash_payload_offset,
					     job->icv_output_len_in_bytes
					     + pad_bytes +
					     sizeof (esp_footer_t), &tmp);
	      padding = tmp;
	    }

	  u8 i;
	  for (i = 0; i < pad_bytes; ++i)
	    {
	      padding[i] = i + 1;
	    }
	  f0 = (esp_footer_t *) (padding + pad_bytes);
	  f0->pad_length = pad_bytes;
	  f0->next_header = next_hdr_type;
	}
      else
	{
	  if (sa0->use_esn)
	    {
	      void *tmp;
	      ipsec_merge_chain_to_job_data (vm, job, hash_payload_offset,
					     job->icv_output_len_in_bytes
					     + sizeof (u32), &tmp);
	      esn = tmp;
	    }
	  else
	    {
	      ipsec_merge_chain_to_job_data (vm, job, hash_payload_offset,
					     job->icv_output_len_in_bytes,
					     NULL);
	    }
	}

      job->cipher_dst = job->src + cipher_headers_len;
      job->cipher_start_src_offset_in_bytes = cipher_headers_len;
      job->msg_len_to_cipher_in_bytes =
	job->data_len - cipher_headers_len - job->icv_output_len_in_bytes;

      job->msg_len_to_hash_in_bytes =
	job->data_len - job->icv_output_len_in_bytes;
      if (PREDICT_TRUE (IPSEC_INTEG_ALG_NONE != sa0->integ_alg))
	{
	  if (sa0->use_esn)
	    {
	      *esn = sa0->seq_hi;
	    }
	  job->icv_dst = job->cipher_dst + job->msg_len_to_cipher_in_bytes;
	}
      job->b->current_length = hash_payload_offset;
      job->error = IPSEC_ERR_OK;
    next:
      ++job;
      ++b;
      --n_jobs;
    }
}

void
esp_encrypt_prepare_jobs (vlib_main_t * vm, u32 thread_index,
			  ipsec_main_t * im, ipsec_proto_main_t * em,
			  vlib_buffer_t ** b, ipsec_job_desc_t * job,
			  u32 n_jobs, int is_ip6,
			  int (*random_bytes) (u8 * dest, int len),
			  u32 next_index_drop, u32 next_index_ip4_lookup,
			  u32 next_index_ip6_lookup)
{
  if (is_ip6)
    return esp_encrypt_prepare_jobs_inline (vm, thread_index, im, em, b, job,
					    n_jobs, 1 /*is_ip6 */ ,
					    random_bytes, next_index_drop,
					    next_index_ip4_lookup,
					    next_index_ip6_lookup);
  else
    return esp_encrypt_prepare_jobs_inline (vm, thread_index, im, em, b, job,
					    n_jobs, 0 /*is_ip6 */ ,
					    random_bytes, next_index_drop,
					    next_index_ip4_lookup,
					    next_index_ip6_lookup);
}

always_inline void
esp_decrypt_prepare_jobs_inline (vlib_main_t * vm, u32 thread_index,
				 ipsec_main_t * im, ipsec_proto_main_t * em,
				 vlib_buffer_t ** b, ipsec_job_desc_t * job,
				 u32 n_jobs, int is_ip6, u32 next_index_drop)
{
  while (n_jobs > 0)
    {
      esp_header_t *esp = 0;
      job->next = next_index_drop;
      vlib_buffer_t *b0 = job->b = *b;
      u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
      ipsec_sa_t *sa0 = job->sa = pool_elt_at_index (im->sad, sa_index0);

      esp = vlib_buffer_get_current (b0);

      u32 seq = vnet_buffer (b0)->ipsec.seq = clib_host_to_net_u32 (esp->seq);

      /* anti-replay check */
      if (sa0->use_anti_replay)
	{
	  int rv = 0;

	  if (sa0->use_esn)
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

      int trunc_size = 0;
      if (sa0->integ_alg != IPSEC_INTEG_ALG_NONE)
	{
	  trunc_size =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	  vec_validate (job->icv, trunc_size);
	  job->icv_dst = job->icv;
	  job->msg_len_to_hash_in_bytes =
	    vlib_buffer_length_in_chain (vm, b0) - trunc_size;
	  job->icv_output_len_in_bytes = trunc_size;
	}

      u8 ip_hdr_size = 0;

      if ((sa0->crypto_alg >= IPSEC_CRYPTO_ALG_AES_CBC_128 &&
	   sa0->crypto_alg <= IPSEC_CRYPTO_ALG_AES_CBC_256) ||
	  (sa0->crypto_alg >= IPSEC_CRYPTO_ALG_DES_CBC &&
	   sa0->crypto_alg <= IPSEC_CRYPTO_ALG_3DES_CBC))
	{
	  const int block_size =
	    em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;
	  const int iv_size =
	    em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;

	  int blocks =
	    (vlib_buffer_length_in_chain (vm, b0) -
	     job->icv_output_len_in_bytes - sizeof (esp_header_t) -
	     iv_size) / block_size;
	  if (vlib_buffer_length_in_chain (vm, b0) - sizeof (esp_header_t) -
	      iv_size < block_size || blocks <= 0)
	    {
	      job->next = next_index_drop;
	      job->error = IPSEC_ERR_INTEG_ERROR;
	      goto next;
	    }

	  /* transport mode */
	  if (!sa0->is_tunnel)
	    {
	      if (b0->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
		{
		  if (is_ip6)
		    {
		      ip_hdr_size = sizeof (ip6_header_t);
		    }
		  else
		    {
		      ip_hdr_size = sizeof (ip4_header_t);
		    }
		}
	      else
		{
		  job->error = IPSEC_ERR_NOT_IP;
		  goto next;
		}
	    }
	  job->iv = esp->data;
	  job->iv_len_in_bytes = iv_size;
	  job->msg_len_to_cipher_in_bytes = blocks * block_size;
	  job->cipher_start_src_offset_in_bytes =
	    sizeof (esp_header_t) + iv_size;
	}
      else
	{
	  job->iv = 0;
	  job->msg_len_to_cipher_in_bytes = 0;
	}

      ipsec_merge_chain_to_job_data (vm, job, 0, 0, 0);

      job->cipher_dst = job->src;
      job->hash_start_src_offset_in_bytes = 0;
      job->error = IPSEC_ERR_OK;

      if (sa0->is_tunnel)
	{
	  b0->current_data -= ip_hdr_size;
	}
      b0->current_length = 0;
    next:
      ++job;
      ++b;
      --n_jobs;
    }
}

void
esp_decrypt_prepare_jobs (vlib_main_t * vm, u32 thread_index,
			  ipsec_main_t * im, ipsec_proto_main_t * em,
			  vlib_buffer_t ** b, ipsec_job_desc_t * job,
			  u32 n_jobs, int is_ip6, u32 next_index_drop)
{
  if (is_ip6)
    esp_decrypt_prepare_jobs_inline (vm, thread_index, im, em, b, job, n_jobs,
				     1 /*is_ip6 */ , next_index_drop);
  else
    esp_decrypt_prepare_jobs_inline (vm, thread_index, im, em, b, job, n_jobs,
				     0 /*is_ip6 */ , next_index_drop);
}

always_inline void
esp_decrypt_finish_one (vlib_main_t * vm, ipsec_job_desc_t * job, int is_ip6,
			u32 next_index_drop, u32 next_index_ip4_input,
			u32 next_index_ip6_input, u32 next_index_gre_input)
{
  esp_footer_t *f0;
  if (IPSEC_INTEG_ALG_NONE != job->sa->integ_alg)
    {
      const u8 *in_packet_icv =
	job->src + job->data_len - job->icv_output_len_in_bytes;
      if (0 !=
	  memcmp (job->icv_dst, in_packet_icv, job->icv_output_len_in_bytes))
	{
	  job->next = next_index_drop;
	  job->error = IPSEC_ERR_INTEG_ERROR;
	  return;
	}
    }

  if (IPSEC_CRYPTO_ALG_NONE != job->sa->crypto_alg)
    {
      f0 =
	(esp_footer_t *) ((u8 *) job->src + job->msg_len_to_cipher_in_bytes -
			  sizeof (esp_footer_t));
    }
  else
    {
      f0 =
	(esp_footer_t *) ((u8 *) job->src + job->data_len -
			  job->icv_output_len_in_bytes -
			  sizeof (esp_footer_t));
    }

  if (job->src == job->data)
    {
      if (ipsec_split_job_data_to_chain
	  (vm, next_index_drop, job,
	   ((u8 *) f0 - job->src) - f0->pad_length) < 0)
	{
	  return;
	}
    }
  else
    {
      job->b->current_length += ((u8 *) f0 - job->src) - f0->pad_length;
    }

  /* tunnel mode */
  if (job->sa->is_tunnel)
    {
      if (f0->next_header == IP_PROTOCOL_IP_IN_IP)
	{
	  job->next = next_index_ip4_input;
	}
      else if (f0->next_header == IP_PROTOCOL_IPV6)
	{
	  job->next = next_index_ip6_input;
	}
      else
	{
	  job->next = next_index_drop;
	  job->error = IPSEC_ERR_CIPHERING_FAILED;
	  return;
	}
    }
  /* transport mode */
  else
    {
      if (is_ip6)
	{
	  vlib_buffer_advance (job->b, -sizeof (ip6_header_t));
	  ip6_header_t *ih6 = vlib_buffer_get_current (job->b);
	  job->next = next_index_ip6_input;
	  ih6->protocol = f0->next_header;
	  ih6->payload_length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, job->b) -
				  sizeof (ip6_header_t));
	}
      else
	{
	  vlib_buffer_advance (job->b, -sizeof (ip4_header_t));
	  ip4_header_t *ih4 = vlib_buffer_get_current (job->b);
	  job->next = next_index_ip4_input;
	  ih4->fragment_id = 0;
	  ih4->flags_and_fragment_offset = 0;
	  ih4->protocol = f0->next_header;
	  ih4->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, job->b));
	  ih4->checksum = ip4_header_checksum (ih4);
	}
    }

  /* for IPSec-GRE tunnel next node is ipsec-gre-input */
  if ((vnet_buffer (job->b)->ipsec.flags & IPSEC_FLAG_IPSEC_GRE_TUNNEL))
    {
      job->next = next_index_gre_input;
    }

  vnet_buffer (job->b)->sw_if_index[VLIB_TX] = (u32) ~ 0;
  if (job->sa->use_anti_replay)
    {
      if (job->sa->use_esn)
	sa_replay_advance_esn (job->sa, vnet_buffer (job->b)->ipsec.seq);
      else
	sa_replay_advance (job->sa, vnet_buffer (job->b)->ipsec.seq);
    }
}

void
esp_decrypt_finish (vlib_main_t * vm, u16 * next, ipsec_job_desc_t * job,
		    u32 n_jobs, int is_ip6, u32 next_index_drop,
		    u32 next_index_ip4_input, u32 next_index_ip6_input,
		    u32 next_index_gre_input)
{
  while (n_jobs)
    {
      if (IPSEC_ERR_OK == job->error)
	{
	  esp_decrypt_finish_one (vm, job, is_ip6, next_index_drop,
				  next_index_ip4_input, next_index_ip6_input,
				  next_index_gre_input);
	}

      next[0] = job->next;
      ++next;
      ++job;
      --n_jobs;
    }
}
