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

vlib_node_registration_t ah_encrypt_node;

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

#if WITH_IPSEC_MB
always_inline void
ah_finish_encrypt (vlib_main_t * vm, JOB_AES_HMAC * job, u32 * bi, u32 * next0)
{
  *bi = (uintptr_t) job->user_data;
  *next0 = (uintptr_t) job->user_data2;
  vlib_buffer_t *b0 = vlib_get_buffer (vm, *bi);
  u8 is_ipv6 = vnet_buffer (b0)->ipsec.is_ipv6;
  u8 transport_mode = vnet_buffer (b0)->ipsec.transport_mode;
  u8 ttl = vnet_buffer (b0)->ipsec.ttl;
  u8 tos = vnet_buffer (b0)->ipsec.tos;

  if (PREDICT_FALSE (is_ipv6))
    {
    }
  else
    {
      ip4_header_t *oh4 = 0;
      if (PREDICT_FALSE (transport_mode))
	{
	  oh4 =
	    (void *) ((ethernet_header_t *) vlib_buffer_get_current (b0) + 1);
	}
      else
	{
	  oh4 = vlib_buffer_get_current (b0);
	}

      oh4->ttl = ttl;
      oh4->tos = tos;
      oh4->checksum = ip4_header_checksum (oh4);
    }
}

always_inline uword
ah_encrypt_node_ipsec_mb_fn (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  int icv_size = 0;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  next_index = node->cached_next_index;
  u32 thread_index = vlib_get_thread_index ();
  MB_MGR *mgr = im->mb_mgr[thread_index];
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
	  ip4_header_t *ih4, *oh4 = 0;
	  ip6_header_t *ih6, *oh6 = 0;
	  ah_header_t *ah = 0;
	  u8 is_ipv6;
	  u8 next_hdr_type;
	  u8 transport_mode = 0;
	  u8 tos = 0;
	  u8 ttl = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = AH_ENCRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, ah_encrypt_node.index,
					   AH_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      to_next[0] = bi0;
	      to_next += 1;
	      goto trace;
	    }


	  sa0->total_data_size += b0->current_length;

	  ssize_t adv;
	  ih4 = vlib_buffer_get_current (b0);
	  ttl = ih4->ttl;
	  tos = ih4->tos;

	  is_ipv6 = (ih4->ip_version_and_header_length & 0xF0) == 0x60;
	  /* is ipv6 */
	  if (PREDICT_TRUE (sa0->is_tunnel))
	    {
	      if (PREDICT_TRUE (!is_ipv6))
		adv = -sizeof (ip4_and_ah_header_t);
	      else
		adv = -sizeof (ip6_and_ah_header_t);
	    }
	  else
	    {
	      adv = -sizeof (ah_header_t);
	    }

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

	  /* is ipv6 */
	  if (PREDICT_FALSE (is_ipv6))
	    {
	      ih6 = (ip6_header_t *) ih4;
	      oh6 = vlib_buffer_get_current (b0);
	      ah = (ah_header_t *) (oh6 + 1);
	      memset (ah, 0, sizeof (*ah));

	      if (PREDICT_TRUE (sa0->is_tunnel))
		{
		  next_hdr_type = IP_PROTOCOL_IPV6;
		  oh6->ip_version_traffic_class_and_flow_label =
		    ih6->ip_version_traffic_class_and_flow_label;
		}
	      else
		{
		  next_hdr_type = ih6->protocol;
		  memmove (oh6, ih6, sizeof (ip6_header_t));
		}

	      oh6->protocol = IP_PROTOCOL_IPSEC_AH;
	      oh6->hop_limit = 254;
	      ah->spi = clib_net_to_host_u32 (sa0->spi);
	      ah->seq_no = clib_net_to_host_u32 (sa0->seq);
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
	      ah->hdrlen = 4;
	    }

	  if (PREDICT_TRUE
	      (!is_ipv6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      oh4->src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	      oh4->dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	      next0 = AH_ENCRYPT_NEXT_IP4_LOOKUP;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else if (is_ipv6 && sa0->is_tunnel && sa0->is_tunnel_ip6)
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
	      next0 = AH_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	    }

	  memset (ah + 1, 0, icv_size);

	  JOB_AES_HMAC *job = im->funcs.get_next_job (mgr);
	  job->src = vlib_buffer_get_current (b0);
	  job->hash_start_src_offset_in_bytes = 0;
	  job->cipher_mode = NULL_CIPHER;
	  job->hash_alg =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].hash_alg;
	  job->auth_tag_output_len_in_bytes =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
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
	  job->u.HMAC._hashed_auth_key_xor_ipad = sa0->ipad_hash;
	  job->u.HMAC._hashed_auth_key_xor_opad = sa0->opad_hash;

	  if (transport_mode)
	    {
	      vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
	    }

	  job->user_data = (void *) (uintptr_t) bi0;
	  job->user_data2 = (void *) (uintptr_t) next0;
	  vnet_buffer (b0)->ipsec.is_ipv6 = is_ipv6;
	  vnet_buffer (b0)->ipsec.transport_mode = transport_mode;
	  vnet_buffer (b0)->ipsec.ttl = ttl;
	  vnet_buffer (b0)->ipsec.tos = tos;
	  vnet_buffer (b0)->ipsec.sad_index = sa_index0;

	  job = im->funcs.submit_job (mgr);
	  ++packets_in_flight;

	  if (!job)
	    {
	      continue;
	    }

	  --packets_in_flight;
	  ASSERT (STS_COMPLETED == job->status);
	  ah_finish_encrypt (vm, job, &bi0, &next0);
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sa0 =
		pool_elt_at_index (im->sad,
				   vnet_buffer (b0)->ipsec.sad_index);
	    }

	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      b0->flags |= VLIB_BUFFER_IS_TRACED;
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
	  while (n_left_to_next > 0 && (job = im->funcs.flush_job (mgr)))
	    {
	      --packets_in_flight;
	      u32 bi0, next0;
	      vlib_buffer_t *b0;
	      ipsec_sa_t *sa0;

	      ASSERT (STS_COMPLETED == job->status);
	      ah_finish_encrypt (vm, job, &bi0, &next0);
	      b0 = vlib_get_buffer (vm, bi0);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ah_encrypt_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  sa0 =
		    pool_elt_at_index (im->sad,
				       vnet_buffer (b0)->ipsec.sad_index);
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
  vlib_node_increment_counter (vm, ah_encrypt_node.index,
			       AH_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}
#else
always_inline uword
ah_encrypt_node_openssl_fn (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  int icv_size = 0;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 i_bi0, next0;
	  vlib_buffer_t *i_b0 = 0;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ip4_and_ah_header_t *ih0, *oh0 = 0;
	  ip6_and_ah_header_t *ih6_0, *oh6_0 = 0;
	  u8 is_ipv6;
	  u8 ip_hdr_size;
	  u8 next_hdr_type;
	  u8 transport_mode = 0;
	  u8 tos = 0;
	  u8 ttl = 0;

	  i_bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = AH_ENCRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, i_bi0);
	  to_next[0] = i_bi0;
	  to_next += 1;
	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, ah_encrypt_node.index,
					   AH_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      //TODO need to confirm if below is needed
	      to_next[0] = i_bi0;
	      to_next += 1;
	      goto trace;
	    }


	  sa0->total_data_size += i_b0->current_length;

	  ssize_t adv;
	  ih0 = vlib_buffer_get_current (i_b0);
	  ttl = ih0->ip4.ttl;
	  tos = ih0->ip4.tos;

	  is_ipv6 = (ih0->ip4.ip_version_and_header_length & 0xF0) == 0x60;
	  /* is ipv6 */
	  if (PREDICT_TRUE (sa0->is_tunnel))
	    {
	      if (PREDICT_TRUE (!is_ipv6))
		adv = -sizeof (ip4_and_ah_header_t);
	      else
		adv = -sizeof (ip6_and_ah_header_t);
	    }
	  else
	    {
	      adv = -sizeof (ah_header_t);
	    }

	  icv_size =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	  /*transport mode save the eth header before it is overwritten */
	  if (PREDICT_FALSE (!sa0->is_tunnel))
	    {
	      ethernet_header_t *ieh0 = (ethernet_header_t *)
		((u8 *) vlib_buffer_get_current (i_b0) -
		 sizeof (ethernet_header_t));
	      ethernet_header_t *oeh0 =
		(ethernet_header_t *) ((u8 *) ieh0 + (adv - icv_size));
	      clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	    }

	  vlib_buffer_advance (i_b0, adv - icv_size);

	  /* is ipv6 */
	  if (PREDICT_FALSE (is_ipv6))
	    {
	      ih6_0 = (ip6_and_ah_header_t *) ih0;
	      ip_hdr_size = sizeof (ip6_header_t);
	      oh6_0 = vlib_buffer_get_current (i_b0);

	      if (PREDICT_TRUE (sa0->is_tunnel))
		{
		  next_hdr_type = IP_PROTOCOL_IPV6;
		  oh6_0->ip6.ip_version_traffic_class_and_flow_label =
		    ih6_0->ip6.ip_version_traffic_class_and_flow_label;
		}
	      else
		{
		  next_hdr_type = ih6_0->ip6.protocol;
		  memmove (oh6_0, ih6_0, sizeof (ip6_header_t));
		}

	      oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_AH;
	      oh6_0->ip6.hop_limit = 254;
	      oh6_0->ah.spi = clib_net_to_host_u32 (sa0->spi);
	      oh6_0->ah.seq_no = clib_net_to_host_u32 (sa0->seq);
	      oh6_0->ip6.payload_length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, i_b0) -
				      sizeof (ip6_header_t));
	    }
	  else
	    {
	      ip_hdr_size = sizeof (ip4_header_t);
	      oh0 = vlib_buffer_get_current (i_b0);
	      memset (oh0, 0, sizeof (ip4_and_ah_header_t));

	      if (PREDICT_TRUE (sa0->is_tunnel))
		{
		  next_hdr_type = IP_PROTOCOL_IP_IN_IP;
		}
	      else
		{
		  next_hdr_type = ih0->ip4.protocol;
		  memmove (oh0, ih0, sizeof (ip4_header_t));
		}

	      oh0->ip4.length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, i_b0));
	      oh0->ip4.ip_version_and_header_length = 0x45;
	      oh0->ip4.fragment_id = 0;
	      oh0->ip4.flags_and_fragment_offset = 0;
	      oh0->ip4.ttl = 0;
	      oh0->ip4.tos = 0;
	      oh0->ip4.protocol = IP_PROTOCOL_IPSEC_AH;
	      oh0->ah.spi = clib_net_to_host_u32 (sa0->spi);
	      oh0->ah.seq_no = clib_net_to_host_u32 (sa0->seq);
	      oh0->ip4.checksum = 0;
	      oh0->ah.nexthdr = next_hdr_type;
	      oh0->ah.hdrlen = 4;
	    }



	  if (PREDICT_TRUE
	      (!is_ipv6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      oh0->ip4.src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	      oh0->ip4.dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	      next0 = AH_ENCRYPT_NEXT_IP4_LOOKUP;
	      vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else if (is_ipv6 && sa0->is_tunnel && sa0->is_tunnel_ip6)
	    {
	      oh6_0->ip6.src_address.as_u64[0] =
		sa0->tunnel_src_addr.ip6.as_u64[0];
	      oh6_0->ip6.src_address.as_u64[1] =
		sa0->tunnel_src_addr.ip6.as_u64[1];
	      oh6_0->ip6.dst_address.as_u64[0] =
		sa0->tunnel_dst_addr.ip6.as_u64[0];
	      oh6_0->ip6.dst_address.as_u64[1] =
		sa0->tunnel_dst_addr.ip6.as_u64[1];

	      next0 = AH_ENCRYPT_NEXT_IP6_LOOKUP;
	      vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else
	    {
	      transport_mode = 1;
	      next0 = AH_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	    }

	  u8 sig[64];
	  memset (sig, 0, sizeof (sig));
	  u8 *digest =
	    vlib_buffer_get_current (i_b0) + ip_hdr_size + icv_size;
	  memset (digest, 0, icv_size);

	  unsigned size = hmac_calc (sa0->integ_alg, sa0->integ_key,
				     sa0->integ_key_len,
				     vlib_buffer_get_current (i_b0),
				     i_b0->current_length, sig, sa0->use_esn,
				     sa0->seq_hi);

	  memcpy (digest, sig, size);
	  if (PREDICT_FALSE (is_ipv6))
	    {
	    }
	  else
	    {
	      oh0->ip4.ttl = ttl;
	      oh0->ip4.tos = tos;
	      oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
	    }

	  if (transport_mode)
	    vlib_buffer_advance (i_b0, -sizeof (ethernet_header_t));

	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      i_b0->flags |= VLIB_BUFFER_IS_TRACED;
	      ah_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, i_b0, sizeof (*tr));
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq - 1;
	      tr->integ_alg = sa0->integ_alg;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, i_bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, ah_encrypt_node.index,
			       AH_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}
#endif

static uword
ah_encrypt_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
#if WITH_IPSEC_MB
  return ah_encrypt_node_ipsec_mb_fn (vm, node, from_frame);
#else
  return ah_encrypt_node_openssl_fn (vm, node, from_frame);
#endif
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah_encrypt_node) = {
  .function = ah_encrypt_node_fn,
  .name = "ah-encrypt",
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

VLIB_NODE_FUNCTION_MULTIARCH (ah_encrypt_node, ah_encrypt_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
