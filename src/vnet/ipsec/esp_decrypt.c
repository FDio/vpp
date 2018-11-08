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

always_inline uword
esp_decrypt_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		    int is_ip6)
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
      if (is_ip6)
	vlib_node_increment_counter (vm, esp6_decrypt_node.index,
				     ESP_DECRYPT_ERROR_NO_BUFFER,
				     n_left_from);
      else
	vlib_node_increment_counter (vm, esp4_decrypt_node.index,
				     ESP_DECRYPT_ERROR_NO_BUFFER,
				     n_left_from);
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
		  if (is_ip6)
		    vlib_node_increment_counter (vm,
						 esp6_decrypt_node.index,
						 ESP_DECRYPT_ERROR_REPLAY, 1);
		  else
		    vlib_node_increment_counter (vm,
						 esp4_decrypt_node.index,
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
	      clib_memset (sig, 0, sizeof (sig));
	      u8 *icv =
		vlib_buffer_get_current (i_b0) + i_b0->current_length -
		icv_size;
	      i_b0->current_length -= icv_size;

	      hmac_calc (sa0->integ_alg, sa0->integ_key, sa0->integ_key_len,
			 (u8 *) esp0, i_b0->current_length, sig, sa0->use_esn,
			 sa0->seq_hi);

	      if (PREDICT_FALSE (memcmp (icv, sig, icv_size)))
		{
		  if (is_ip6)
		    vlib_node_increment_counter (vm,
						 esp6_decrypt_node.index,
						 ESP_DECRYPT_ERROR_INTEG_ERROR,
						 1);
		  else
		    vlib_node_increment_counter (vm,
						 esp4_decrypt_node.index,
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

		  if (is_ip6)
		    {
		      ih6 =
			(ip6_header_t *) ((u8 *) esp0 -
					  sizeof (ip6_header_t));
		      ip_hdr_size = sizeof (ip6_header_t);
		      oh6 = vlib_buffer_get_current (o_b0);
		    }
		  else
		    {
		      ih4 =
			(ip4_header_t *) ((u8 *) esp0 -
					  sizeof (ip4_header_t));
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
		      if (is_ip6)
			vlib_node_increment_counter (vm,
						     esp6_decrypt_node.index,
						     ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						     1);
		      else
			vlib_node_increment_counter (vm,
						     esp4_decrypt_node.index,
						     ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						     1);
		      o_b0 = 0;
		      goto trace;
		    }
		}
	      /* transport mode */
	      else
		{
		  if (is_ip6)
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
  if (is_ip6)
    vlib_node_increment_counter (vm, esp6_decrypt_node.index,
				 ESP_DECRYPT_ERROR_RX_PKTS,
				 from_frame->n_vectors);
  else
    vlib_node_increment_counter (vm, esp4_decrypt_node.index,
				 ESP_DECRYPT_ERROR_RX_PKTS,
				 from_frame->n_vectors);


free_buffers_and_exit:
  if (recycle)
    vlib_buffer_free (vm, recycle, vec_len (recycle));
  vec_free (recycle);
  return from_frame->n_vectors;
}

static uword
esp4_decrypt_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_decrypt_node) = {
  .function = esp4_decrypt_node_fn,
  .name = "esp4-decrypt",
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

VLIB_NODE_FUNCTION_MULTIARCH (esp4_decrypt_node, esp4_decrypt_node_fn);

static uword
esp6_decrypt_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_decrypt_node) = {
  .function = esp6_decrypt_node_fn,
  .name = "esp6-decrypt",
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

VLIB_NODE_FUNCTION_MULTIARCH (esp6_decrypt_node, esp6_decrypt_node_fn);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
