/*
 * esp_decrypt.c : ipsecmb ESP decrypt node
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
#include <ipsecmb/ipsecmb.h>

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

#ifdef CLIB_MARCH_VARIANT
always_inline void
esp_finish_decrypt (vlib_main_t * vm, vlib_node_runtime_t * node,
		    JOB_AES_HMAC * job, u32 * next0, ipsec_sa_t * sa0,
		    int is_ip6)
{
  u32 bi0 = (uintptr_t) job->user_data;
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  esp_footer_t *f0;
  ip4_header_t *ih4 = vlib_buffer_get_current (b0);
  ip6_header_t *ih6 = vlib_buffer_get_current (b0);

  if (NULL_HASH != job->hash_alg)
    {
      if (0 !=
	  memcmp (job->auth_tag_output,
		  job->auth_tag_output - job->auth_tag_output_len_in_bytes,
		  job->auth_tag_output_len_in_bytes))
	{
	  vlib_node_increment_counter (vm, node->node_index,
				       ESP_DECRYPT_ERROR_INTEG_ERROR, 1);
	  *next0 = ESP_DECRYPT_NEXT_DROP;
	  return;
	}
    }

  f0 = (esp_footer_t *) ((u8 *) vlib_buffer_get_current (b0) +
			 b0->current_length);
  b0->current_length -= f0->pad_length;

  /* tunnel mode */
  if (sa0->is_tunnel)
    {
      if (f0->next_header == IP_PROTOCOL_IP_IN_IP)
	{
	  *next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
	}
      else if (f0->next_header == IP_PROTOCOL_IPV6)
	{
	  *next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
	}
      else
	{
	  vlib_node_increment_counter (vm, node->node_index,
				       ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
				       1);
	  *next0 = ESP_DECRYPT_NEXT_DROP;
	  return;
	}
    }
  /* transport mode */
  else
    {
      if (is_ip6)
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
  if ((vnet_buffer (b0)->ipsec.flags & IPSEC_FLAG_IPSEC_GRE_TUNNEL))
    {
      *next0 = ESP_DECRYPT_NEXT_IPSEC_GRE_INPUT;
    }

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
  if (sa0->use_anti_replay)
    {
      if (sa0->use_esn)
	esp_replay_advance_esn (sa0, vnet_buffer (b0)->ipsec.seq);
      else
	esp_replay_advance (sa0, vnet_buffer (b0)->ipsec.seq);
    }
}

always_inline uword
esp_decrypt_ipsecmb_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame, int is_ip6)
{
  u32 n_left_from, *from, next_index, *to_next;
  u32 packets_in_flight = 0;
  ipsec_main_t *im = &ipsec_main;
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  u32 thread_index = vlib_get_thread_index ();
  MB_MGR *mgr = imbm->mb_mgr[thread_index];
  u32 *to_be_freed = NULL;

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
	  ipsecmb_sa_t *samb0;
	  u32 sa_index0 = ~0;
	  u32 seq;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = ESP_DECRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  esp0 = vlib_buffer_get_current (b0);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);
	  samb0 = pool_elt_at_index (imbm->sad, sa_index0);

	  vnet_buffer (b0)->ipsec.seq = seq =
	    clib_host_to_net_u32 (esp0->seq);

	  /* anti-replay check */
	  if (sa0->use_anti_replay)
	    {
	      int rv = 0;

	      if (sa0->use_esn)
		rv = esp_replay_check_esn (sa0, seq);
	      else
		rv = esp_replay_check (sa0, seq);

	      if (PREDICT_FALSE (rv))
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       ESP_DECRYPT_ERROR_REPLAY, 1);
		  goto trace;
		}
	    }

	  sa0->total_data_size += b0->current_length;

	  if (PREDICT_FALSE (b0->n_add_refs > 0))
	    {
	      vec_add1 (to_be_freed, bi0);
	      b0 = vlib_buffer_copy (vm, b0);
	      bi0 = vlib_get_buffer_index (vm, b0);
	    }

	  JOB_AES_HMAC *job = IPSECMB_FUNC (get_next_job) (mgr);
	  int trunc_size = 0;
	  if (sa0->integ_alg != IPSEC_INTEG_ALG_NONE)
	    {
	      trunc_size =
		em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	      // put calculated auth tag after in-packet auth tag
	      job->auth_tag_output =
		vlib_buffer_get_current (b0) + b0->current_length;
	      b0->current_length -= trunc_size;
	      job->msg_len_to_hash_in_bytes = b0->current_length;
	      job->auth_tag_output_len_in_bytes = trunc_size;
	      job->u.HMAC._hashed_auth_key_xor_ipad = samb0->ipad_hash;
	      job->u.HMAC._hashed_auth_key_xor_opad = samb0->opad_hash;
	    }

	  job->hash_alg = imbm->integ_algs[sa0->integ_alg].hash_alg;
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
		(b0->current_length - sizeof (esp_header_t) -
		 iv_size) / block_size;
	      if (b0->current_length - sizeof (esp_header_t) - iv_size <
		  block_size || blocks <= 0)
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       ESP_DECRYPT_ERROR_INTEG_ERROR,
					       1);
		  goto trace;
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
		      vlib_node_increment_counter (vm, node->node_index,
						   ESP_DECRYPT_ERROR_NOT_IP,
						   1);
		      goto trace;
		    }
		}

	      job->chain_order = HASH_CIPHER;
	      job->cipher_direction = DECRYPT;
	      job->src = (u8 *) esp0;
	      job->dst = (u8 *) esp0;
	      vlib_buffer_advance (b0, -ip_hdr_size);
	      job->cipher_mode =
		imbm->crypto_algs[sa0->crypto_alg].cipher_mode;
	      job->aes_enc_key_expanded = samb0->aes_enc_key_expanded;
	      job->aes_dec_key_expanded = samb0->aes_dec_key_expanded;
	      job->aes_key_len_in_bytes = sa0->crypto_key_len;
	      job->iv = esp0->data;
	      job->iv_len_in_bytes = iv_size;
	      job->msg_len_to_cipher_in_bytes = blocks * block_size;
	      job->cipher_start_src_offset_in_bytes =
		sizeof (esp_header_t) + iv_size;
	      job->hash_start_src_offset_in_bytes = 0;

	      job->user_data = (void *) (uintptr_t) bi0;
	      job->user_data2 = sa0;
	      b0->current_length =
		(blocks * block_size) - sizeof (esp_footer_t) + ip_hdr_size;
	      ASSERT ((u8 *) vlib_buffer_get_current (b0) +
		      b0->current_length < job->auth_tag_output);
	      b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	      job = IPSECMB_FUNC (submit_job) (mgr);
	      ++packets_in_flight;

	      if (!job)
		{
		  continue;
		}

	      --packets_in_flight;

	      sa0 = job->user_data2;
	      bi0 = (uintptr_t) job->user_data;
	      b0 = vlib_get_buffer (vm, bi0);
	      esp_finish_decrypt (vm, node, job, &next0, sa0, is_ip6);

	    trace:
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

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

      if (PREDICT_FALSE (n_left_from == 0 && packets_in_flight > 0))
	{
	  JOB_AES_HMAC *job = NULL;
	  while (n_left_to_next > 0 && (job = IPSECMB_FUNC (flush_job) (mgr)))
	    {
	      --packets_in_flight;
	      u32 bi0, next0;
	      bi0 = (uintptr_t) job->user_data;
	      vlib_buffer_t *i_b0 = vlib_get_buffer (vm, bi0);

	      ipsec_sa_t *sa0 = job->user_data2;
	      esp_finish_decrypt (vm, node, job, &next0, sa0, is_ip6);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  esp_decrypt_trace_t *tr =
		    vlib_add_trace (vm, node, i_b0, sizeof (*tr));
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
		}

	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  if (to_be_freed)
    vlib_buffer_free (vm, to_be_freed, vec_len (to_be_freed));
  vec_free (to_be_freed);
  return from_frame->n_vectors;
}

VLIB_NODE_FN (esp4_decrypt_ipsecmb_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * from_frame)
{
  return esp_decrypt_ipsecmb_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

VLIB_NODE_FN (esp6_decrypt_ipsecmb_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * from_frame)
{
  return esp_decrypt_ipsecmb_inline (vm, node, from_frame, 1 /*is_ip6 */ );
}
#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_decrypt_ipsecmb_node) = {
  .name = "esp4-decrypt-ipsecmb",
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_decrypt_ipsecmb_node) = {
  .name = "esp6-decrypt-ipsecmb",
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
