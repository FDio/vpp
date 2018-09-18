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

#define foreach_ah_decrypt_next                \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(IPSEC_GRE_INPUT, "ipsec-gre-input")

#define _(v, s) AH_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_ah_decrypt_next
#undef _
    AH_DECRYPT_N_NEXT,
} ah_decrypt_next_t;


#define foreach_ah_decrypt_error                   \
 _(RX_PKTS, "AH pkts received")                    \
 _(DECRYPTION_FAILED, "AH decryption failed")      \
 _(INTEG_ERROR, "Integrity check failed")           \
 _(REPLAY, "SA replayed packet")                    \
 _(NOT_IP, "Not IP packet (dropped)")


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

#if WITH_IPSEC_MB

always_inline void
remove_ah (vlib_main_t * vm, u32 * bi0, u32 * next0, ipsec_sa_t * sa0,
	   u32 ip_hdr_size, u32 icv_size, ip4_header_t * ih4,
	   ah_header_t * ah0)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, *bi0);

  int tunnel_mode = 1;
  int transport_ip6 = 0;

  if (PREDICT_FALSE (!sa0->is_tunnel && !sa0->is_tunnel_ip6))
    {				/* transport mode */
      tunnel_mode = 0;

      if (PREDICT_TRUE ((ih4->ip_version_and_header_length & 0xF0) != 0x40))
	{
	  if (PREDICT_TRUE
	      ((ih4->ip_version_and_header_length & 0xF0) == 0x60))
	    transport_ip6 = 1;
	  else
	    {
	      clib_warning ("next header: 0x%x", ah0->nexthdr);
	      vlib_node_increment_counter (vm, ah_decrypt_node.index,
					   AH_DECRYPT_ERROR_NOT_IP, 1);
	      *next0 = AH_DECRYPT_NEXT_DROP;
	      return;
	    }
	}
    }

  if (PREDICT_TRUE (tunnel_mode))
    {
      vlib_buffer_advance (b0, ip_hdr_size + sizeof (ah_header_t) + icv_size);
      if (PREDICT_TRUE (ah0->nexthdr == IP_PROTOCOL_IP_IN_IP))
	*next0 = AH_DECRYPT_NEXT_IP4_INPUT;
      else if (ah0->nexthdr == IP_PROTOCOL_IPV6)
	*next0 = AH_DECRYPT_NEXT_IP6_INPUT;
      else
	{
	  clib_warning ("next header: 0x%x", ah0->nexthdr);
	  vlib_node_increment_counter (vm, ah_decrypt_node.index,
				       AH_DECRYPT_ERROR_DECRYPTION_FAILED, 1);
	  *next0 = AH_DECRYPT_NEXT_DROP;
	  return;
	}
    }
  else
    {				/* transport mode */
      const size_t ip_hdr_offset = sizeof (ah_header_t) + icv_size;
      if (PREDICT_FALSE (transport_ip6))
	{
	  ip6_header_t *ih6 =
	    (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      ip_hdr_offset);
	  memmove (ih6, vlib_buffer_get_current (b0), sizeof (ip6_header_t));
	  vlib_buffer_advance (b0, ip_hdr_offset);

	  *next0 = AH_DECRYPT_NEXT_IP6_INPUT;
	  ih6->protocol = ah0->nexthdr;
	  ih6->payload_length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain
				  (vm, b0) - sizeof (ip6_header_t));
	}
      else
	{
	  ih4 =
	    (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      ip_hdr_offset);
	  memmove (ih4, vlib_buffer_get_current (b0), sizeof (ip4_header_t));
	  vlib_buffer_advance (b0, ip_hdr_offset);

	  *next0 = AH_DECRYPT_NEXT_IP4_INPUT;
	  ih4->ip_version_and_header_length = 0x45;
	  ih4->fragment_id = 0;
	  ih4->flags_and_fragment_offset = 0;
	  ih4->protocol = ah0->nexthdr;
	  ih4->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	  ih4->ttl = vnet_buffer (b0)->ipsec.ttl;
	  ih4->tos = vnet_buffer (b0)->ipsec.tos;
	  ih4->checksum = ip4_header_checksum (ih4);
	}
    }

  /* for IPSec-GRE tunnel next node is ipsec-gre-input */
  if (PREDICT_FALSE
      ((vnet_buffer (b0)->ipsec.flags) & IPSEC_FLAG_IPSEC_GRE_TUNNEL))
    {
      *next0 = AH_DECRYPT_NEXT_IPSEC_GRE_INPUT;
    }

  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
}

always_inline void
ah_finish_decrypt (vlib_main_t * vm, JOB_AES_HMAC * job, u32 * bi0, u32 * next0)
{
  ipsec_main_t *im = &ipsec_main;
  *bi0 = (uintptr_t) job->user_data;
  vlib_buffer_t *b0 = vlib_get_buffer (vm, *bi0);
  ipsec_sa_t *sa0 =
    pool_elt_at_index (im->sad, vnet_buffer (b0)->ipsec.sad_index);
  ip4_header_t *ih4 = vlib_buffer_get_current (b0);
  u32 ip_hdr_size = ip4_header_bytes (ih4);
  ah_header_t *ah0 = (ah_header_t *) ((u8 *) ih4 + ip_hdr_size);
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 icv_size = em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
  void *digest = ah0 + 1;
  size_t seq_size = 0;
  if (PREDICT_TRUE (sa0->use_esn))
    {
      seq_size = sizeof (u32);
    }
  void *sig = vlib_buffer_get_current (b0) + b0->current_length + seq_size;

  if (PREDICT_FALSE (memcmp (digest, sig, icv_size)))
    {
      vlib_node_increment_counter (vm, ah_decrypt_node.index,
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
  remove_ah (vm, bi0, next0, sa0, ip_hdr_size, icv_size, ih4, ah0);
}


always_inline uword
ah_decrypt_node_ipsec_mb_fn (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  int icv_size = 0;
  u32 thread_index = vlib_get_thread_index ();
  MB_MGR *mgr = im->mb_mgr[thread_index];
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
	  u32 sa_index0 = ~0;
	  u32 seq;
	  ip4_header_t *ih4 = 0;
	  u8 ip_hdr_size = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = AH_DECRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  ih4 = vlib_buffer_get_current (b0);
	  ip_hdr_size = ip4_header_bytes (ih4);
	  ah0 = (ah_header_t *) ((u8 *) ih4 + ip_hdr_size);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  seq = clib_host_to_net_u32 (ah0->seq_no);
	  /* anti-replay check */
	  //TODO UT remaining
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
		  vlib_node_increment_counter (vm, ah_decrypt_node.index,
					       AH_DECRYPT_ERROR_REPLAY, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  goto trace;
		}
	    }


	  sa0->total_data_size += b0->current_length;
	  icv_size =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	  if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	    {
	      u8 *icv =
		(u8 *) vlib_buffer_get_current (b0) + ip_hdr_size +
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

	      if ((ih4->ip_version_and_header_length & 0xF0) == 0x40)
		{
		  vnet_buffer (b0)->ipsec.tos = ih4->tos;
		  vnet_buffer (b0)->ipsec.ttl = ih4->ttl;
		  ih4->tos = 0;
		  ih4->ttl = 0;
		  ih4->checksum = 0;
		  ih4->flags_and_fragment_offset = 0;
		}		//TODO else part for IPv6

	      JOB_AES_HMAC *job = im->funcs.get_next_job (mgr);
	      job->src = vlib_buffer_get_current (b0);
	      job->hash_start_src_offset_in_bytes = 0;
	      job->cipher_mode = NULL_CIPHER;
	      job->hash_alg =
		em->ipsec_proto_main_integ_algs[sa0->integ_alg].hash_alg;
	      job->auth_tag_output_len_in_bytes =
		em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	      job->auth_tag_output = icv;
	      job->msg_len_to_hash_in_bytes = b0->current_length + seq_size;
	      job->cipher_direction = DECRYPT;
	      job->chain_order = HASH_CIPHER;
	      job->u.HMAC._hashed_auth_key_xor_ipad = sa0->ipad_hash;
	      job->u.HMAC._hashed_auth_key_xor_opad = sa0->opad_hash;

	      job->user_data = (void *) (uintptr_t) bi0;
	      job->user_data2 = (void *) (uintptr_t) next0;
	      vnet_buffer (b0)->ipsec.sad_index = sa_index0;
	      job = im->funcs.submit_job (mgr);
	      ++packets_in_flight;

	      if (!job)
		{
		  continue;
		}
	      --packets_in_flight;
	      ASSERT (STS_COMPLETED == job->status);
	      ah_finish_decrypt (vm, job, &bi0, &next0);
	    }
	  else
	    {
	      remove_ah (vm, &bi0, &next0, sa0, ip_hdr_size, icv_size, ih4,
			 ah0);
	    }
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;
	trace:
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
	  while (n_left_to_next > 0 && (job = im->funcs.flush_job (mgr)))
	    {
	      --packets_in_flight;
	      ASSERT (STS_COMPLETED == job->status);
	      u32 bi0, next0;
	      ah_finish_decrypt (vm, job, &bi0, &next0);
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
  vlib_node_increment_counter (vm, ah_decrypt_node.index,
			       AH_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

#else
always_inline uword
ah_decrypt_node_openssl_fn (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  int icv_size = 0;

  next_index = node->cached_next_index;

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
	  u8 tunnel_mode = 1;
	  u8 transport_ip6 = 0;
	  u8 ip_hdr_size = 0;
	  u8 tos = 0;
	  u8 ttl = 0;


	  i_bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = AH_DECRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, i_bi0);
	  to_next[0] = i_bi0;
	  to_next += 1;
	  ih4 = vlib_buffer_get_current (i_b0);
	  ip_hdr_size = ip4_header_bytes (ih4);
	  ah0 = (ah_header_t *) ((u8 *) ih4 + ip_hdr_size);

	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  seq = clib_host_to_net_u32 (ah0->seq_no);
	  /* anti-replay check */
	  //TODO UT remaining
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
		  vlib_node_increment_counter (vm, ah_decrypt_node.index,
					       AH_DECRYPT_ERROR_REPLAY, 1);
		  to_next[0] = i_bi0;
		  to_next += 1;
		  goto trace;
		}
	    }


	  sa0->total_data_size += i_b0->current_length;
	  icv_size =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	  if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	    {
	      u8 sig[64];
	      u8 digest[64];
	      memset (sig, 0, sizeof (sig));
	      memset (digest, 0, sizeof (digest));
	      u8 *icv =
		vlib_buffer_get_current (i_b0) + ip_hdr_size +
		sizeof (ah_header_t);
	      memcpy (digest, icv, icv_size);
	      memset (icv, 0, icv_size);

	      if ((ih4->ip_version_and_header_length & 0xF0) == 0x40)
		{
		  tos = ih4->tos;
		  ttl = ih4->ttl;
		  ih4->tos = 0;
		  ih4->ttl = 0;
		  ih4->checksum = 0;
		  ih4->flags_and_fragment_offset = 0;
		}		//TODO else part for IPv6

	      hmac_calc (sa0->integ_alg, sa0->integ_key, sa0->integ_key_len,
			 (u8 *) ih4, i_b0->current_length, sig, sa0->use_esn,
			 sa0->seq_hi);

	      if (PREDICT_FALSE (memcmp (digest, sig, icv_size)))
		{
		  vlib_node_increment_counter (vm, ah_decrypt_node.index,
					       AH_DECRYPT_ERROR_INTEG_ERROR,
					       1);
		  to_next[0] = i_bi0;
		  to_next += 1;
		  goto trace;
		}

	      //TODO UT remaining
	      if (PREDICT_TRUE (sa0->use_anti_replay))
		{
		  if (PREDICT_TRUE (sa0->use_esn))
		    esp_replay_advance_esn (sa0, seq);
		  else
		    esp_replay_advance (sa0, seq);
		}

	    }


	  vlib_buffer_advance (i_b0,
			       ip_hdr_size + sizeof (ah_header_t) + icv_size);
	  i_b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  /* transport mode */
	  if (PREDICT_FALSE (!sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      tunnel_mode = 0;

	      if (PREDICT_TRUE
		  ((ih4->ip_version_and_header_length & 0xF0) != 0x40))
		{
		  if (PREDICT_TRUE
		      ((ih4->ip_version_and_header_length & 0xF0) == 0x60))
		    transport_ip6 = 1;
		  else
		    {
		      clib_warning ("next header: 0x%x", ah0->nexthdr);
		      vlib_node_increment_counter (vm, ah_decrypt_node.index,
						   AH_DECRYPT_ERROR_NOT_IP,
						   1);
		      goto trace;
		    }
		}
	    }

	  if (PREDICT_TRUE (tunnel_mode))
	    {
	      if (PREDICT_TRUE (ah0->nexthdr == IP_PROTOCOL_IP_IN_IP))
		next0 = AH_DECRYPT_NEXT_IP4_INPUT;
	      else if (ah0->nexthdr == IP_PROTOCOL_IPV6)
		next0 = AH_DECRYPT_NEXT_IP6_INPUT;
	      else
		{
		  clib_warning ("next header: 0x%x", ah0->nexthdr);
		  vlib_node_increment_counter (vm, ah_decrypt_node.index,
					       AH_DECRYPT_ERROR_DECRYPTION_FAILED,
					       1);
		  goto trace;
		}
	    }
	  /* transport mode */
	  else
	    {
	      if (PREDICT_FALSE (transport_ip6))
		{
		  ih6 =
		    (ip6_header_t *) (i_b0->data +
				      sizeof (ethernet_header_t));
		  vlib_buffer_advance (i_b0, -sizeof (ip6_header_t));
		  oh6 = vlib_buffer_get_current (i_b0);
		  memmove (oh6, ih6, sizeof (ip6_header_t));

		  next0 = AH_DECRYPT_NEXT_IP6_INPUT;
		  oh6->protocol = ah0->nexthdr;
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
	  if (PREDICT_FALSE
	      ((vnet_buffer (i_b0)->ipsec.flags) &
	       IPSEC_FLAG_IPSEC_GRE_TUNNEL))
	    next0 = AH_DECRYPT_NEXT_IPSEC_GRE_INPUT;


	  vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      i_b0->flags |= VLIB_BUFFER_IS_TRACED;
	      ah_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, i_b0, sizeof (*tr));
	      tr->integ_alg = sa0->integ_alg;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, i_bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, ah_decrypt_node.index,
			       AH_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}
#endif

static uword
ah_decrypt_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
#if WITH_IPSEC_MB
  return ah_decrypt_node_ipsec_mb_fn (vm, node, from_frame);
#else
  return ah_decrypt_node_openssl_fn (vm, node, from_frame);
#endif
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah_decrypt_node) = {
  .function = ah_decrypt_node_fn,
  .name = "ah-decrypt",
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

VLIB_NODE_FUNCTION_MULTIARCH (ah_decrypt_node, ah_decrypt_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
