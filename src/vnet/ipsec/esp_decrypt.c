/*
 * esp_decrypt.c : IPSec ESP decrypt node
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

#define foreach_esp_decrypt_next                \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(IPSEC_GRE_INPUT, "ipsec-gre-input")

#define _(v, s) ESP_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_decrypt_next
#undef _
    ESP_DECRYPT_N_NEXT,
} esp_decrypt_next_t;


#define foreach_esp_decrypt_error                   \
 _(RX_PKTS, "ESP pkts received")                    \
 _(NO_BUFFER, "No buffer (packed dropped)")         \
 _(DECRYPTION_FAILED, "ESP decryption failed")      \
 _(INTEG_ERROR, "Integrity check failed")           \
 _(REPLAY, "SA replayed packet")                    \
 _(NOT_IP, "Not IP packet (dropped)")

typedef enum
{
#define _(sym,str) ESP_DECRYPT_ERROR_##sym,
  foreach_esp_decrypt_error
#undef _
    ESP_DECRYPT_N_ERROR,
} esp_decrypt_error_t;

static char *esp_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_decrypt_error
#undef _
};

typedef struct
{
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_decrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_decrypt_trace_t *t = va_arg (*args, esp_decrypt_trace_t *);

  s = format (s, "esp: crypto %U integrity %U",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);
  return s;
}

#ifdef WITH_IPSEC_MB

always_inline void
esp_finish_decrypt (vlib_main_t * vm, JOB_AES_HMAC * job, u32 * next0)
{
  u32 bi0 = (uintptr_t) job->user_data;
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  u8 tunnel_mode = vnet_buffer (b0)->ipsec.tunnel_mode;
  u8 transport_ip6 = vnet_buffer (b0)->ipsec.is_ipv6;
  esp_footer_t *f0;
  ip4_header_t *ih4 = vlib_buffer_get_current (b0);
  ip6_header_t *ih6 = vlib_buffer_get_current (b0);

  if (PREDICT_FALSE (NULL_HASH != job->hash_alg))
    {
      if (PREDICT_FALSE
	  (0 !=
	   memcmp (job->auth_tag_output,
		   job->auth_tag_output - job->auth_tag_output_len_in_bytes,
		   job->auth_tag_output_len_in_bytes)))
	{
	  vlib_node_increment_counter (vm, esp_decrypt_node.index,
				       ESP_DECRYPT_ERROR_INTEG_ERROR, 1);
	  *next0 = ESP_DECRYPT_NEXT_DROP;
	  return;
	}
    }

  f0 = (esp_footer_t *) ((u8 *) vlib_buffer_get_current (b0) +
			 b0->current_length);
  b0->current_length -= f0->pad_length;

  /* tunnel mode */
  if (PREDICT_TRUE (tunnel_mode))
    {
      if (PREDICT_TRUE (f0->next_header == IP_PROTOCOL_IP_IN_IP))
	{
	  *next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
	}
      else if (f0->next_header == IP_PROTOCOL_IPV6)
	{
	  *next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
	}
      else
	{
	  clib_warning ("next header: 0x%x", f0->next_header);
	  vlib_node_increment_counter (vm, esp_decrypt_node.index,
				       ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
				       1);
	  *next0 = ESP_DECRYPT_NEXT_DROP;
	  return;
	}
    }
  /* transport mode */
  else
    {
      if (PREDICT_FALSE (transport_ip6))
	{
	  *next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
	  ih6->protocol = f0->next_header;
	  ih6->payload_length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
				  sizeof (ip6_header_t));
	}
      else
	{
	  *next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
	  ih4->fragment_id = 0;
	  ih4->flags_and_fragment_offset = 0;
	  ih4->protocol = f0->next_header;
	  ih4->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	  ih4->checksum = ip4_header_checksum (ih4);
	}
    }

  /* for IPSec-GRE tunnel next node is ipsec-gre-input */
  if (PREDICT_FALSE ((vnet_buffer (b0)->ipsec.flags) &
		     IPSEC_FLAG_IPSEC_GRE_TUNNEL))
    {
      *next0 = ESP_DECRYPT_NEXT_IPSEC_GRE_INPUT;
    }

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
}

always_inline uword
esp_decrypt_node_ipsec_mb_fn (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  u32 packets_in_flight = 0;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  u32 thread_index = vlib_get_thread_index ();
  MB_MGR *mgr = im->mb_mgr[thread_index];

  next_index = node->cached_next_index;

  while (n_left_from > 0 || packets_in_flight > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0;
	  esp_header_t *esp0;
	  ipsec_sa_t *sa0;
	  u32 sa_index0 = ~0;
	  u32 seq;
	  ip4_header_t *ih4 = 0;
	  u8 tunnel_mode = 1;
	  u8 transport_ip6 = 0;


	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = ESP_DECRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  esp0 = vlib_buffer_get_current (b0);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  seq = clib_host_to_net_u32 (esp0->seq);

	  /* anti-replay check */
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
		  vlib_node_increment_counter (vm, esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_REPLAY, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  sa0->total_data_size += b0->current_length;

	  if (PREDICT_TRUE (sa0->use_anti_replay))
	    {
	      if (PREDICT_TRUE (sa0->use_esn))
		esp_replay_advance_esn (sa0, seq);
	      else
		esp_replay_advance (sa0, seq);
	    }

	  JOB_AES_HMAC *job = im->funcs.get_next_job (mgr);
	  int trunc_size = 0;
	  if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	    {
	      trunc_size =
		em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	      // put calculated auth tag after in-packet auth tag
	      job->auth_tag_output =
		vlib_buffer_get_current (b0) + b0->current_length;
	      b0->current_length -= trunc_size;
	      job->msg_len_to_hash_in_bytes = b0->current_length;
	      job->auth_tag_output_len_in_bytes = trunc_size;
	      job->u.HMAC._hashed_auth_key_xor_ipad = sa0->ipad_hash;
	      job->u.HMAC._hashed_auth_key_xor_opad = sa0->opad_hash;
	    }

	  job->hash_alg =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].hash_alg;
	  u8 ip_hdr_size = 0;

	  if ((sa0->crypto_alg >= IPSEC_CRYPTO_ALG_AES_CBC_128 &&
	       sa0->crypto_alg <= IPSEC_CRYPTO_ALG_AES_CBC_256) ||
	      (sa0->crypto_alg >= IPSEC_CRYPTO_ALG_DES_CBC &&
	       sa0->crypto_alg <= IPSEC_CRYPTO_ALG_3DES_CBC))
	    {
	      const int block_size =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;;
	      const int iv_size =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;

	      int blocks =
		(b0->current_length - sizeof (esp_header_t) -
		 iv_size) / block_size;

	      /* transport mode */
	      if (PREDICT_FALSE (!sa0->is_tunnel && !sa0->is_tunnel_ip6))
		{
		  tunnel_mode = 0;

		  if (b0->flags & VNET_BUFFER_F_IS_IP4)
		    ih4 =
		      (ip4_header_t *) ((u8 *) esp0 - sizeof (ip4_header_t));
		  else
		    ih4 =
		      (ip4_header_t *) ((u8 *) esp0 - sizeof (ip6_header_t));

		  if (PREDICT_TRUE
		      ((ih4->ip_version_and_header_length & 0xF0) != 0x40))
		    {
		      if (PREDICT_TRUE
			  ((ih4->ip_version_and_header_length & 0xF0) ==
			   0x60))
			{
			  transport_ip6 = 1;
			  ip_hdr_size = sizeof (ip6_header_t);
			}
		      else
			{
			  vlib_node_increment_counter (vm,
						       esp_decrypt_node.index,
						       ESP_DECRYPT_ERROR_NOT_IP,
						       1);
			  goto trace;
			}
		    }
		  else
		    {
		      ip_hdr_size = sizeof (ip4_header_t);
		    }
		}


	      job->chain_order = HASH_CIPHER;
	      job->cipher_direction = DECRYPT;
	      job->src = (u8 *) esp0;
	      job->dst = (u8 *) esp0;
	      vlib_buffer_advance (b0, -ip_hdr_size);
	      job->cipher_mode =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].cipher_mode;
	      job->aes_enc_key_expanded = sa0->aes_enc_key_expanded;
	      job->aes_dec_key_expanded = sa0->aes_dec_key_expanded;
	      job->aes_key_len_in_bytes = sa0->crypto_key_len;
	      job->iv = esp0->data;
	      job->iv_len_in_bytes = iv_size;
	      job->msg_len_to_cipher_in_bytes = blocks * block_size;
	      job->cipher_start_src_offset_in_bytes =
		sizeof (esp_header_t) + iv_size;
	      job->hash_start_src_offset_in_bytes = 0;

	      job->user_data = (void *) (uintptr_t) bi0;
	      job->user_data2 = sa0;
	      vnet_buffer_opaque_t *vnb = vnet_buffer (b0);
	      vnb->ipsec.tunnel_mode = tunnel_mode;
	      vnb->ipsec.is_ipv6 = transport_ip6;

	      b0->current_length =
		(blocks * block_size) - sizeof (esp_footer_t) + ip_hdr_size;
	      ASSERT ((u8 *) vlib_buffer_get_current (b0) +
		      b0->current_length < job->auth_tag_output);
	      b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	      job = im->funcs.submit_job (mgr);
	      ++packets_in_flight;

	      if (!job)
		{
		  continue;
		}

	      --packets_in_flight;
	      ASSERT (job->status == STS_COMPLETED);

	      esp_finish_decrypt (vm, job, &next0);
	      bi0 = (uintptr_t) job->user_data;
	      b0 = vlib_get_buffer (vm, bi0);
	      sa0 = job->user_data2;

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	    trace:
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  esp_decrypt_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
		}

	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }
	}

      if (PREDICT_FALSE (n_left_from == 0))
	{
	  JOB_AES_HMAC *job = NULL;
	  while (n_left_to_next > 0 && (job = im->funcs.flush_job (mgr)))
	    {
	      --packets_in_flight;
	      u32 bi0, next0;
	      bi0 = (uintptr_t) job->user_data;
	      vlib_buffer_t *i_b0 = vlib_get_buffer (vm, bi0);

	      ASSERT (job->status == STS_COMPLETED);

	      esp_finish_decrypt (vm, job, &next0);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  esp_decrypt_trace_t *tr =
		    vlib_add_trace (vm, node, i_b0, sizeof (*tr));
		  ipsec_sa_t *sa0 = job->user_data2;
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
		}

	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, esp_decrypt_node.index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

#else

always_inline void
esp_decrypt_cbc (ipsec_crypto_alg_t alg,
		 u8 * in, u8 * out, size_t in_len, u8 * key, u8 * iv)
{
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 thread_index = vlib_get_thread_index ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = em->per_thread_data[thread_index].decrypt_ctx;
#else
  EVP_CIPHER_CTX *ctx = &(em->per_thread_data[thread_index].decrypt_ctx);
#endif
  const EVP_CIPHER *cipher = NULL;
  int out_len;

  ASSERT (alg < IPSEC_CRYPTO_N_ALG);

  if (PREDICT_FALSE (em->ipsec_proto_main_crypto_algs[alg].type == 0))
    return;

  if (PREDICT_FALSE
      (alg != em->per_thread_data[thread_index].last_decrypt_alg))
    {
      cipher = em->ipsec_proto_main_crypto_algs[alg].type;
      em->per_thread_data[thread_index].last_decrypt_alg = alg;
    }

  EVP_DecryptInit_ex (ctx, cipher, NULL, key, iv);

  EVP_DecryptUpdate (ctx, out, &out_len, in, in_len);
  EVP_DecryptFinal_ex (ctx, out + out_len, &out_len);
}

static uword
esp_decrypt_node_openssl_fn (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 *recycle = 0;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  u32 thread_index = vlib_get_thread_index ();

  ipsec_alloc_empty_buffers (vm, im);

  u32 *empty_buffers = im->empty_buffers[thread_index];

  if (PREDICT_FALSE (vec_len (empty_buffers) < n_left_from))
    {
      vlib_node_increment_counter (vm, esp_decrypt_node.index,
				   ESP_DECRYPT_ERROR_NO_BUFFER, n_left_from);
      goto free_buffers_and_exit;
    }

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 i_bi0, o_bi0 = (u32) ~ 0, next0;
	  vlib_buffer_t *i_b0;
	  vlib_buffer_t *o_b0 = 0;
	  esp_header_t *esp0;
	  ipsec_sa_t *sa0;
	  u32 sa_index0 = ~0;
	  u32 seq;
	  ip4_header_t *ih4 = 0, *oh4 = 0;
	  ip6_header_t *ih6 = 0, *oh6 = 0;
	  u8 tunnel_mode = 1;
	  u8 transport_ip6 = 0;


	  i_bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_DECRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, i_bi0);
	  esp0 = vlib_buffer_get_current (i_b0);

	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  seq = clib_host_to_net_u32 (esp0->seq);

	  /* anti-replay check */
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
		  vlib_node_increment_counter (vm, esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_REPLAY, 1);
		  o_bi0 = i_bi0;
		  to_next[0] = o_bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  sa0->total_data_size += i_b0->current_length;

	  if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	    {
	      u8 sig[64];
	      int icv_size =
		em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	      memset (sig, 0, sizeof (sig));
	      u8 *icv =
		vlib_buffer_get_current (i_b0) + i_b0->current_length -
		icv_size;
	      i_b0->current_length -= icv_size;

	      hmac_calc (sa0->integ_alg, sa0->integ_key, sa0->integ_key_len,
			 (u8 *) esp0, i_b0->current_length, sig, sa0->use_esn,
			 sa0->seq_hi);

	      if (PREDICT_FALSE (memcmp (icv, sig, icv_size)))
		{
		  vlib_node_increment_counter (vm, esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_INTEG_ERROR,
					       1);
		  o_bi0 = i_bi0;
		  to_next[0] = o_bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  if (PREDICT_TRUE (sa0->use_anti_replay))
	    {
	      if (PREDICT_TRUE (sa0->use_esn))
		esp_replay_advance_esn (sa0, seq);
	      else
		esp_replay_advance (sa0, seq);
	    }

	  /* grab free buffer */
	  uword last_empty_buffer = vec_len (empty_buffers) - 1;
	  o_bi0 = empty_buffers[last_empty_buffer];
	  to_next[0] = o_bi0;
	  to_next += 1;
	  o_b0 = vlib_get_buffer (vm, o_bi0);
	  vlib_prefetch_buffer_with_index (vm,
					   empty_buffers[last_empty_buffer -
							 1], STORE);
	  _vec_len (empty_buffers) = last_empty_buffer;

	  /* add old buffer to the recycle list */
	  vec_add1 (recycle, i_bi0);

	  if ((sa0->crypto_alg >= IPSEC_CRYPTO_ALG_AES_CBC_128 &&
	       sa0->crypto_alg <= IPSEC_CRYPTO_ALG_AES_CBC_256) ||
	      (sa0->crypto_alg >= IPSEC_CRYPTO_ALG_DES_CBC &&
	       sa0->crypto_alg <= IPSEC_CRYPTO_ALG_3DES_CBC))
	    {
	      const int BLOCK_SIZE =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;;
	      const int IV_SIZE =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;
	      esp_footer_t *f0;
	      u8 ip_hdr_size = 0;

	      int blocks =
		(i_b0->current_length - sizeof (esp_header_t) -
		 IV_SIZE) / BLOCK_SIZE;

	      o_b0->current_data = sizeof (ethernet_header_t);

	      /* transport mode */
	      if (PREDICT_FALSE (!sa0->is_tunnel && !sa0->is_tunnel_ip6))
		{
		  tunnel_mode = 0;

		  if (i_b0->flags & VNET_BUFFER_F_IS_IP4)
		    ih4 =
		      (ip4_header_t *) ((u8 *) esp0 - sizeof (ip4_header_t));
		  else
		    ih4 =
		      (ip4_header_t *) ((u8 *) esp0 - sizeof (ip6_header_t));

		  if (PREDICT_TRUE
		      ((ih4->ip_version_and_header_length & 0xF0) != 0x40))
		    {
		      if (PREDICT_TRUE
			  ((ih4->ip_version_and_header_length & 0xF0) ==
			   0x60))
			{
			  transport_ip6 = 1;
			  ip_hdr_size = sizeof (ip6_header_t);
			  ih6 = (ip6_header_t *) ih4;
			  oh6 = vlib_buffer_get_current (o_b0);
			}
		      else
			{
			  vlib_node_increment_counter (vm,
						       esp_decrypt_node.index,
						       ESP_DECRYPT_ERROR_NOT_IP,
						       1);
			  o_b0 = 0;
			  goto trace;
			}
		    }
		  else
		    {
		      oh4 = vlib_buffer_get_current (o_b0);
		      ip_hdr_size = sizeof (ip4_header_t);
		    }
		}

	      esp_decrypt_cbc (sa0->crypto_alg,
			       esp0->data + IV_SIZE,
			       (u8 *) vlib_buffer_get_current (o_b0) +
			       ip_hdr_size, BLOCK_SIZE * blocks,
			       sa0->crypto_key, esp0->data);

	      o_b0->current_length = (blocks * BLOCK_SIZE) - 2 + ip_hdr_size;
	      o_b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      f0 =
		(esp_footer_t *) ((u8 *) vlib_buffer_get_current (o_b0) +
				  o_b0->current_length);
	      o_b0->current_length -= f0->pad_length;

	      /* tunnel mode */
	      if (PREDICT_TRUE (tunnel_mode))
		{
		  if (PREDICT_TRUE (f0->next_header == IP_PROTOCOL_IP_IN_IP))
		    {
		      next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
		      oh4 = vlib_buffer_get_current (o_b0);
		    }
		  else if (f0->next_header == IP_PROTOCOL_IPV6)
		    next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
		  else
		    {
		      clib_warning ("next header: 0x%x", f0->next_header);
		      vlib_node_increment_counter (vm, esp_decrypt_node.index,
						   ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						   1);
		      o_b0 = 0;
		      goto trace;
		    }
		}
	      /* transport mode */
	      else
		{
		  if (PREDICT_FALSE (transport_ip6))
		    {
		      next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
		      oh6->ip_version_traffic_class_and_flow_label =
			ih6->ip_version_traffic_class_and_flow_label;
		      oh6->protocol = f0->next_header;
		      oh6->hop_limit = ih6->hop_limit;
		      oh6->src_address.as_u64[0] = ih6->src_address.as_u64[0];
		      oh6->src_address.as_u64[1] = ih6->src_address.as_u64[1];
		      oh6->dst_address.as_u64[0] = ih6->dst_address.as_u64[0];
		      oh6->dst_address.as_u64[1] = ih6->dst_address.as_u64[1];
		      oh6->payload_length =
			clib_host_to_net_u16 (vlib_buffer_length_in_chain
					      (vm,
					       o_b0) - sizeof (ip6_header_t));
		    }
		  else
		    {
		      next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
		      oh4->ip_version_and_header_length = 0x45;
		      oh4->tos = ih4->tos;
		      oh4->fragment_id = 0;
		      oh4->flags_and_fragment_offset = 0;
		      oh4->ttl = ih4->ttl;
		      oh4->protocol = f0->next_header;
		      oh4->src_address.as_u32 = ih4->src_address.as_u32;
		      oh4->dst_address.as_u32 = ih4->dst_address.as_u32;
		      oh4->length =
			clib_host_to_net_u16 (vlib_buffer_length_in_chain
					      (vm, o_b0));
		      oh4->checksum = ip4_header_checksum (oh4);
		    }
		}

	      /* for IPSec-GRE tunnel next node is ipsec-gre-input */
	      if (PREDICT_FALSE
		  ((vnet_buffer (i_b0)->ipsec.flags) &
		   IPSEC_FLAG_IPSEC_GRE_TUNNEL))
		next0 = ESP_DECRYPT_NEXT_IPSEC_GRE_INPUT;

	      vnet_buffer (o_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      vnet_buffer (o_b0)->sw_if_index[VLIB_RX] =
		vnet_buffer (i_b0)->sw_if_index[VLIB_RX];
	    }

	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      if (o_b0)
		{
		  o_b0->flags |= VLIB_BUFFER_IS_TRACED;
		  o_b0->trace_index = i_b0->trace_index;
		  esp_decrypt_trace_t *tr =
		    vlib_add_trace (vm, node, o_b0, sizeof (*tr));
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, o_bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, esp_decrypt_node.index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

free_buffers_and_exit:
  if (recycle)
    vlib_buffer_free (vm, recycle, vec_len (recycle));
  vec_free (recycle);
  return from_frame->n_vectors;
}
#endif

static uword
esp_decrypt_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
#ifdef WITH_IPSEC_MB
  return esp_decrypt_node_ipsec_mb_fn (vm, node, from_frame);
#else
  return esp_decrypt_node_openssl_fn (vm, node, from_frame);
#endif
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp_decrypt_node) = {
  .function = esp_decrypt_node_fn,
  .name = "esp-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_DECRYPT_NEXT_##s] = n,
    foreach_esp_decrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (esp_decrypt_node, esp_decrypt_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
