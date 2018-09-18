/*
 * esp_encrypt.c : IPSec ESP encrypt node
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
#include <vnet/udp/udp.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>

ipsec_proto_main_t ipsec_proto_main;

#define foreach_esp_encrypt_next                   \
_(DROP, "error-drop")                              \
_(IP4_LOOKUP, "ip4-lookup")                        \
_(IP6_LOOKUP, "ip6-lookup")                        \
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ESP_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_encrypt_next
#undef _
    ESP_ENCRYPT_N_NEXT,
} esp_encrypt_next_t;

#define foreach_esp_encrypt_error                   \
 _(RX_PKTS, "ESP pkts received")                    \
 _(NO_BUFFER, "No buffer (packet dropped)")         \
 _(DECRYPTION_FAILED, "ESP encryption failed")      \
 _(SEQ_CYCLED, "sequence number cycled")


typedef enum
{
#define _(sym,str) ESP_ENCRYPT_ERROR_##sym,
  foreach_esp_encrypt_error
#undef _
    ESP_ENCRYPT_N_ERROR,
} esp_encrypt_error_t;

vlib_node_registration_t esp_encrypt_node;

typedef struct
{
  u32 spi;
  u32 seq;
  u8 udp_encap;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_encrypt_trace_t;

#ifdef WITH_IPSEC_MB
static inline void
random_bytes (u8 * buffer, u32 len)
{
  static u32 seed = 0;
  //TODO FIXME
  for (u32 i = 0; i < len; ++i)
    {
      buffer[i] = random_u32 (&seed) % 256;
    }
}

static inline void
esp_finish_encrypt (vlib_main_t * vm, JOB_AES_HMAC * job, u32 * bi0, u32 * next0,
		ipsec_sa_t ** sa0)
{
  ip4_header_t *oh4 = 0;
  udp_header_t *udp = 0;
  ip6_header_t *oh6 = 0;
  ipsec_main_t *im = &ipsec_main;
  *bi0 = (uintptr_t) job->user_data;
  vlib_buffer_t *b0 = vlib_get_buffer (vm, *bi0);
  u8 is_ipv6 = vnet_buffer (b0)->ipsec.is_ipv6;
  u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
  *sa0 = pool_elt_at_index (im->sad, sa_index0);
  if (vnet_buffer (b0)->ipsec.tunnel_mode)
    {
      oh4 = vlib_buffer_get_current (b0);
      oh6 = vlib_buffer_get_current (b0);
    }
  else
    {
      oh4 =
	(ip4_header_t *) ((u8 *)
			  vlib_buffer_get_current (b0) +
			  sizeof (ethernet_header_t));
      oh6 =
	(ip6_header_t *) ((u8 *)
			  vlib_buffer_get_current (b0) +
			  sizeof (ethernet_header_t));
    }
  if (PREDICT_FALSE (is_ipv6))
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
      if ((*sa0)->udp_encap)
	{
	  udp = (udp_header_t *) (oh4 + 1);
	  udp->length =
	    clib_host_to_net_u16 (oh4->length - ip4_header_bytes (oh4));
	}
    }

  *next0 = (uintptr_t) job->user_data2;
}

static uword
esp_encrypt_node_ipsec_mb_fn (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  u32 packets_in_flight = 0;
  ipsec_proto_main_t *em = &ipsec_proto_main;

  next_index = node->cached_next_index;

  u32 thread_index = vlib_get_thread_index ();
  MB_MGR *mgr = im->mb_mgr[thread_index];

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
	  udp_header_t *udp;
	  esp_header_t *esp;
	  u8 is_ipv6;
	  u8 next_hdr_type;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = ESP_ENCRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, esp_encrypt_node.index,
					   ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      //TODO: rekey SA
	      to_next[0] = bi0;
	      to_next += 1;
	      goto trace;
	    }

	  sa0->total_data_size += b0->current_length;
	  ih4 = vlib_buffer_get_current (b0);
	  ih6 = vlib_buffer_get_current (b0);
	  const int iv_size =
	    em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;
	  if (PREDICT_FALSE
	      ((ih4->ip_version_and_header_length & 0xF0) == 0x60))
	    {			/* is ipv6 */
	      is_ipv6 = 1;
	      next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
	      ih6 = vlib_buffer_get_current (b0);
	      if (sa0->is_tunnel && sa0->is_tunnel_ip6)
		{		/* tunnel mode */
		  next_hdr_type = IP_PROTOCOL_IPV6;
		  oh6 =
		    (ip6_header_t *) ((u8 *) ih6 -
				      sizeof (esp_header_t) -
				      sizeof (ip6_header_t) - iv_size);
		  oh6->src_address.as_u64[0] =
		    sa0->tunnel_src_addr.ip6.as_u64[0];
		  oh6->src_address.as_u64[1] =
		    sa0->tunnel_src_addr.ip6.as_u64[1];
		  oh6->dst_address.as_u64[0] =
		    sa0->tunnel_dst_addr.ip6.as_u64[0];
		  oh6->dst_address.as_u64[1] =
		    sa0->tunnel_dst_addr.ip6.as_u64[1];

		  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  vlib_buffer_advance (b0,
				       -(sizeof (esp_header_t) +
					 sizeof (ip6_header_t) + iv_size));
		}
	      else
		{		/* transport mode */
		  next_hdr_type = ih6->protocol;
		  oh6 =
		    (ip6_header_t *) ((u8 *) ih6 - sizeof (esp_header_t) -
				      iv_size);
		  if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
		    {
		      ethernet_header_t *ieh0, *oeh0;
		      ieh0 =
			(ethernet_header_t *) vlib_buffer_get_current (b0) -
			1;
		      oeh0 = (ethernet_header_t *) oh6 - 1;
		      clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
		      next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
		      vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
		    }
		  oh6->src_address.as_u64[0] = ih6->src_address.as_u64[0];
		  oh6->src_address.as_u64[1] = ih6->src_address.as_u64[1];
		  oh6->dst_address.as_u64[0] = ih6->dst_address.as_u64[0];
		  oh6->dst_address.as_u64[1] = ih6->dst_address.as_u64[1];
		  vlib_buffer_advance (b0,
				       -(sizeof (esp_header_t) + iv_size));
		}
	      oh6->ip_version_traffic_class_and_flow_label =
		ih6->ip_version_traffic_class_and_flow_label;
	      oh6->protocol = IP_PROTOCOL_IPSEC_ESP;
	      oh6->hop_limit = 254;
	      esp = (esp_header_t *) (oh6 + 1);
	    }
	  else
	    {			/* is ipv4 */
	      next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
	      u32 udp_hdr_size = 0;
	      if (sa0->udp_encap)
		{
		  udp_hdr_size = sizeof (udp_header_t);
		}
	      if (sa0->is_tunnel && !sa0->is_tunnel_ip6)
		{		/* tunnel mode */
		  next_hdr_type = IP_PROTOCOL_IP_IN_IP;
		  oh4 = (ip4_header_t *) (((u8 *) ih4) -
					  sizeof (ip4_header_t) -
					  sizeof (esp_header_t) -
					  udp_hdr_size - iv_size);
		  oh4->src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
		  oh4->dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;
		  vlib_buffer_advance (b0,
				       -(sizeof (ip4_header_t) +
					 sizeof (esp_header_t) +
					 udp_hdr_size + iv_size));
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		}
	      else
		{		/* transport mode */
		  next_hdr_type = ih4->protocol;
		  oh4 =
		    (void *) (((u8 *) ih4) - sizeof (esp_header_t) -
			      udp_hdr_size - iv_size);
		  if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
		    {
		      ethernet_header_t *ieh0, *oeh0;
		      ieh0 =
			(ethernet_header_t *) ((u8 *)
					       vlib_buffer_get_current (b0) -
					       sizeof (ethernet_header_t));
		      oeh0 = (ethernet_header_t *) oh4 - 1;
		      clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
		      next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
		      vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
		    }
		  oh4->src_address.as_u32 = ih4->src_address.as_u32;
		  oh4->dst_address.as_u32 = ih4->dst_address.as_u32;
		  vlib_buffer_advance (b0,
				       -(sizeof (esp_header_t) +
					 udp_hdr_size + iv_size));
		}
	      is_ipv6 = 0;
	      esp = (esp_header_t *) (oh4 + 1);

	      oh4->ip_version_and_header_length = 0x45;
	      oh4->tos = ih4->tos;
	      oh4->fragment_id = 0;
	      oh4->flags_and_fragment_offset = 0;
	      oh4->ttl = 254;
	      if (sa0->udp_encap)
		{
		  esp = (esp_header_t *) ((u8 *) esp + sizeof (udp_header_t));
		  udp = (udp_header_t *) (oh4 + 1);
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

	  esp->spi = clib_net_to_host_u32 (sa0->spi);
	  esp->seq = clib_net_to_host_u32 (sa0->seq);
	  ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);

	  esp_footer_t *f0;
	  const u32 payload_offset =
	    (u8 *) (esp + 1) + iv_size - (u8 *) vlib_buffer_get_current (b0);
	  JOB_AES_HMAC *job = im->funcs.get_next_job (mgr);
	  if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
	    {
	      const int block_size =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;
	      u32 payload_length = b0->current_length - payload_offset;
	      int blocks = 1 + (payload_length + 1) / block_size;

	      /* pad packet in input buffer */
	      u8 pad_bytes =
		block_size * blocks - sizeof (esp_footer_t) - payload_length;
	      u8 i;
	      u8 *padding = vlib_buffer_get_current (b0) + b0->current_length;
	      b0->current_length = payload_offset + block_size * blocks;
	      for (i = 0; i < pad_bytes; ++i)
		{
		  padding[i] = i + 1;
		}
	      f0 = vlib_buffer_get_current (b0) + b0->current_length -
		sizeof (esp_footer_t);
	      f0->pad_length = pad_bytes;
	      f0->next_header = next_hdr_type;

	      random_bytes ((u8 *) (esp + 1), iv_size);
	      job->iv = (u8 *) (esp + 1);
	      job->iv_len_in_bytes = iv_size;
	    }

	  job->chain_order = CIPHER_HASH;
	  job->cipher_direction = ENCRYPT;
	  job->src =
	    (u8 *) vlib_buffer_get_current (b0) + payload_offset -
	    (sizeof (esp_header_t) + iv_size);
	  job->dst = (u8 *) vlib_buffer_get_current (b0) + payload_offset;
	  job->cipher_mode =
	    em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].cipher_mode;
	  job->aes_enc_key_expanded = sa0->aes_enc_key_expanded;
	  job->aes_dec_key_expanded = sa0->aes_dec_key_expanded;
	  job->aes_key_len_in_bytes = sa0->crypto_key_len;
	  job->cipher_start_src_offset_in_bytes =
	    sizeof (esp_header_t) + iv_size;
	  job->hash_start_src_offset_in_bytes = 0;
	  job->msg_len_to_cipher_in_bytes =
	    b0->current_length - payload_offset;
	  if (PREDICT_TRUE (IPSEC_INTEG_ALG_NONE != sa0->integ_alg))
	    {
	      if (PREDICT_TRUE (sa0->use_esn))
		{
		  *(u32 *) (vlib_buffer_get_current (b0) +
			    b0->current_length) = sa0->seq_hi;
		  b0->current_length += sizeof (u32);
		}
	      job->msg_len_to_hash_in_bytes =
		b0->current_length - payload_offset + sizeof (esp_header_t) +
		iv_size;
	      job->u.HMAC._hashed_auth_key_xor_ipad = sa0->ipad_hash;
	      job->u.HMAC._hashed_auth_key_xor_opad = sa0->opad_hash;
	      job->auth_tag_output =
		vlib_buffer_get_current (b0) + b0->current_length;
	      job->auth_tag_output_len_in_bytes =
		em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	      b0->current_length +=
		em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	    }
	  job->hash_alg =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].hash_alg;
	  job->user_data = (void *) (uintptr_t) bi0;
	  job->user_data2 = (void *) (uintptr_t) next0;
	  vnet_buffer (b0)->ipsec.is_ipv6 = is_ipv6;
	  vnet_buffer (b0)->ipsec.tunnel_mode = sa0->is_tunnel;
	  job = im->funcs.submit_job (mgr);
	  ++packets_in_flight;

	  if (!job)
	    {
	      continue;
	    }

	  --packets_in_flight;
	  ASSERT (STS_COMPLETED == job->status);
	  esp_finish_encrypt (vm, job, &bi0, &next0, &sa0);

	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq - 1;
	      tr->udp_encap = sa0->udp_encap;
	      tr->crypto_alg = sa0->crypto_alg;
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
	      esp_finish_encrypt (vm, job, &bi0, &next0, &sa0);
	      b0 = vlib_get_buffer (vm, bi0);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  esp_encrypt_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->spi = sa0->spi;
		  tr->seq = sa0->seq - 1;
		  tr->udp_encap = sa0->udp_encap;
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
		}

	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next, bi0,
					       next0);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, esp_encrypt_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}
#else
always_inline void
esp_encrypt_cbc (vlib_main_t * vm, ipsec_crypto_alg_t alg,
		 u8 * in, u8 * out, size_t in_len, u8 * key, u8 * iv)
{
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 thread_index = vm->thread_index;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = em->per_thread_data[thread_index].encrypt_ctx;
#else
  EVP_CIPHER_CTX *ctx = &(em->per_thread_data[thread_index].encrypt_ctx);
#endif
  const EVP_CIPHER *cipher = NULL;
  int out_len;

  ASSERT (alg < IPSEC_CRYPTO_N_ALG);

  if (PREDICT_FALSE
      (em->ipsec_proto_main_crypto_algs[alg].type == IPSEC_CRYPTO_ALG_NONE))
    return;

  if (PREDICT_FALSE
      (alg != em->per_thread_data[thread_index].last_encrypt_alg))
    {
      cipher = em->ipsec_proto_main_crypto_algs[alg].type;
      em->per_thread_data[thread_index].last_encrypt_alg = alg;
    }

  EVP_EncryptInit_ex (ctx, cipher, NULL, key, iv);

  EVP_EncryptUpdate (ctx, out, &out_len, in, in_len);
  EVP_EncryptFinal_ex (ctx, out + out_len, &out_len);
}

static uword
esp_encrypt_node_openssl_fn (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 *recycle = 0;
  u32 thread_index = vm->thread_index;

  ipsec_alloc_empty_buffers (vm, im);

  u32 *empty_buffers = im->empty_buffers[thread_index];

  if (PREDICT_FALSE (vec_len (empty_buffers) < n_left_from))
    {
      vlib_node_increment_counter (vm, esp_encrypt_node.index,
				   ESP_ENCRYPT_ERROR_NO_BUFFER, n_left_from);
      clib_warning ("no enough empty buffers. discarding frame");
      goto free_buffers_and_exit;
    }

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 i_bi0, o_bi0, next0;
	  vlib_buffer_t *i_b0, *o_b0 = 0;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ip4_and_esp_header_t *oh0 = 0;
	  ip6_and_esp_header_t *ih6_0, *oh6_0 = 0;
	  ip4_and_udp_and_esp_header_t *iuh0, *ouh0 = 0;
	  uword last_empty_buffer;
	  esp_header_t *o_esp0;
	  esp_footer_t *f0;
	  u8 is_ipv6;
	  u8 ip_udp_hdr_size;
	  u8 next_hdr_type;
	  u32 ip_proto = 0;
	  u8 transport_mode = 0;

	  i_bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_ENCRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, i_bi0);
	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, esp_encrypt_node.index,
					   ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      //TODO: rekey SA
	      o_bi0 = i_bi0;
	      to_next[0] = o_bi0;
	      to_next += 1;
	      goto trace;
	    }

	  sa0->total_data_size += i_b0->current_length;

	  /* grab free buffer */
	  last_empty_buffer = vec_len (empty_buffers) - 1;
	  o_bi0 = empty_buffers[last_empty_buffer];
	  o_b0 = vlib_get_buffer (vm, o_bi0);
	  o_b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  o_b0->current_data = sizeof (ethernet_header_t);
	  iuh0 = vlib_buffer_get_current (i_b0);
	  vlib_prefetch_buffer_with_index (vm,
					   empty_buffers[last_empty_buffer -
							 1], STORE);
	  _vec_len (empty_buffers) = last_empty_buffer;
	  to_next[0] = o_bi0;
	  to_next += 1;

	  /* add old buffer to the recycle list */
	  vec_add1 (recycle, i_bi0);

	  /* is ipv6 */
	  if (PREDICT_FALSE
	      ((iuh0->ip4.ip_version_and_header_length & 0xF0) == 0x60))
	    {
	      is_ipv6 = 1;
	      ih6_0 = vlib_buffer_get_current (i_b0);
	      next_hdr_type = IP_PROTOCOL_IPV6;
	      oh6_0 = vlib_buffer_get_current (o_b0);

	      oh6_0->ip6.ip_version_traffic_class_and_flow_label =
		ih6_0->ip6.ip_version_traffic_class_and_flow_label;
	      oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
	      ip_udp_hdr_size = sizeof (ip6_header_t);
	      o_esp0 = vlib_buffer_get_current (o_b0) + ip_udp_hdr_size;
	      oh6_0->ip6.hop_limit = 254;
	      oh6_0->ip6.src_address.as_u64[0] =
		ih6_0->ip6.src_address.as_u64[0];
	      oh6_0->ip6.src_address.as_u64[1] =
		ih6_0->ip6.src_address.as_u64[1];
	      oh6_0->ip6.dst_address.as_u64[0] =
		ih6_0->ip6.dst_address.as_u64[0];
	      oh6_0->ip6.dst_address.as_u64[1] =
		ih6_0->ip6.dst_address.as_u64[1];
	      o_esp0->spi = clib_net_to_host_u32 (sa0->spi);
	      o_esp0->seq = clib_net_to_host_u32 (sa0->seq);

	      next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
	    }
	  else
	    {
	      is_ipv6 = 0;
	      next_hdr_type = IP_PROTOCOL_IP_IN_IP;
	      ip_proto = ih6_0->ip6.protocol;
	      oh0 = vlib_buffer_get_current (o_b0);
	      ouh0 = vlib_buffer_get_current (o_b0);

	      oh0->ip4.ip_version_and_header_length = 0x45;
	      oh0->ip4.tos = iuh0->ip4.tos;
	      oh0->ip4.fragment_id = 0;
	      oh0->ip4.flags_and_fragment_offset = 0;
	      oh0->ip4.ttl = 254;
	      if (sa0->udp_encap)
		{
		  ouh0->udp.src_port =
		    clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
		  ouh0->udp.dst_port =
		    clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
		  ouh0->udp.checksum = 0;
		  ouh0->ip4.protocol = IP_PROTOCOL_UDP;
		  ip_udp_hdr_size =
		    sizeof (udp_header_t) + sizeof (ip4_header_t);
		}
	      else
		{
		  oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
		  ip_udp_hdr_size = sizeof (ip4_header_t);
		}
	      o_esp0 = vlib_buffer_get_current (o_b0) + ip_udp_hdr_size;
	      oh0->ip4.src_address.as_u32 = iuh0->ip4.src_address.as_u32;
	      oh0->ip4.dst_address.as_u32 = iuh0->ip4.dst_address.as_u32;
	      o_esp0->spi = clib_net_to_host_u32 (sa0->spi);
	      o_esp0->seq = clib_net_to_host_u32 (sa0->seq);
	      ip_proto = iuh0->ip4.protocol;

	      next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
	    }

	  if (PREDICT_TRUE
	      (!is_ipv6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      oh0->ip4.src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	      oh0->ip4.dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	      vnet_buffer (o_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
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

	      vnet_buffer (o_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else
	    {
	      next_hdr_type = ip_proto;
	      if (vnet_buffer (i_b0)->sw_if_index[VLIB_TX] != ~0)
		{
		  transport_mode = 1;
		  ethernet_header_t *ieh0, *oeh0;
		  ieh0 =
		    (ethernet_header_t *) ((u8 *)
					   vlib_buffer_get_current (i_b0) -
					   sizeof (ethernet_header_t));
		  oeh0 = (ethernet_header_t *) o_b0->data;
		  clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
		  next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
		  vnet_buffer (o_b0)->sw_if_index[VLIB_TX] =
		    vnet_buffer (i_b0)->sw_if_index[VLIB_TX];
		}
	      vlib_buffer_advance (i_b0, ip_udp_hdr_size);
	    }

	  ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);

	  if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
	    {

	      const int BLOCK_SIZE =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;
	      const int IV_SIZE =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;
	      int blocks = 1 + (i_b0->current_length + 1) / BLOCK_SIZE;

	      /* pad packet in input buffer */
	      u8 pad_bytes = BLOCK_SIZE * blocks - 2 - i_b0->current_length;
	      u8 i;
	      u8 *padding =
		vlib_buffer_get_current (i_b0) + i_b0->current_length;
	      i_b0->current_length = BLOCK_SIZE * blocks;
	      for (i = 0; i < pad_bytes; ++i)
		{
		  padding[i] = i + 1;
		}
	      f0 = vlib_buffer_get_current (i_b0) + i_b0->current_length - 2;
	      f0->pad_length = pad_bytes;
	      f0->next_header = next_hdr_type;

	      o_b0->current_length = ip_udp_hdr_size + sizeof (esp_header_t) +
		BLOCK_SIZE * blocks + IV_SIZE;

	      vnet_buffer (o_b0)->sw_if_index[VLIB_RX] =
		vnet_buffer (i_b0)->sw_if_index[VLIB_RX];

	      u8 iv[em->
		    ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size];
	      RAND_bytes (iv, sizeof (iv));

	      clib_memcpy ((u8 *) vlib_buffer_get_current (o_b0) +
			   ip_udp_hdr_size + sizeof (esp_header_t), iv,
			   em->ipsec_proto_main_crypto_algs[sa0->
							    crypto_alg].iv_size);

	      esp_encrypt_cbc (vm, sa0->crypto_alg,
			       (u8 *) vlib_buffer_get_current (i_b0),
			       (u8 *) vlib_buffer_get_current (o_b0) +
			       ip_udp_hdr_size + sizeof (esp_header_t) +
			       IV_SIZE, BLOCK_SIZE * blocks,
			       sa0->crypto_key, iv);
	    }

	  o_b0->current_length += hmac_calc (sa0->integ_alg, sa0->integ_key,
					     sa0->integ_key_len,
					     (u8 *) o_esp0,
					     o_b0->current_length -
					     ip_udp_hdr_size,
					     vlib_buffer_get_current (o_b0) +
					     o_b0->current_length,
					     sa0->use_esn, sa0->seq_hi);


	  if (PREDICT_FALSE (is_ipv6))
	    {
	      oh6_0->ip6.payload_length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, o_b0) -
				      sizeof (ip6_header_t));
	    }
	  else
	    {
	      oh0->ip4.length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, o_b0));
	      oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
	      if (sa0->udp_encap)
		{
		  ouh0->udp.length =
		    clib_host_to_net_u16 (clib_net_to_host_u16
					  (oh0->ip4.length) -
					  ip4_header_bytes (&oh0->ip4));
		}
	    }

	  if (transport_mode)
	    vlib_buffer_reset (o_b0);

	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      if (o_b0)
		{
		  o_b0->flags |= VLIB_BUFFER_IS_TRACED;
		  o_b0->trace_index = i_b0->trace_index;
		  esp_encrypt_trace_t *tr =
		    vlib_add_trace (vm, node, o_b0, sizeof (*tr));
		  tr->spi = sa0->spi;
		  tr->seq = sa0->seq - 1;
		  tr->udp_encap = sa0->udp_encap;
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, o_bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, esp_encrypt_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

free_buffers_and_exit:
  if (recycle)
    vlib_buffer_free (vm, recycle, vec_len (recycle));
  vec_free (recycle);
  return from_frame->n_vectors;
}
#endif

static uword
esp_encrypt_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
#ifdef WITH_IPSEC_MB
  return esp_encrypt_node_ipsec_mb_fn (vm, node, from_frame);
#else
  return esp_encrypt_node_openssl_fn (vm, node, from_frame);
#endif
}

static char *esp_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_encrypt_error
#undef _
};

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);

  s = format (s, "esp: spi %u seq %u crypto %U integrity %U%s",
	      t->spi, t->seq,
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg,
	      t->udp_encap ? " udp-encap-enabled" : "");
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp_encrypt_node) = {
  .name = "esp-encrypt",
  .function = esp_encrypt_node_fn,
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_ENCRYPT_NEXT_##s] = n,
    foreach_esp_encrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (esp_encrypt_node, esp_encrypt_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
