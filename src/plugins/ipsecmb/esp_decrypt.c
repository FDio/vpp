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

#ifdef CLIB_MARCH_VARIANT
always_inline void
ipsecmb_esp_finish_decrypt (vlib_main_t * vm, vlib_node_runtime_t * node,
			    ipsecmb_job_desc_t * job, int is_ip6)
{
  esp_footer_t *f0;
  if (NULL_HASH != job->hash_alg)
    {
      const u8 *in_packet_icv =
	job->src + job->data_len - job->icv_output_len_in_bytes;
      if (0 !=
	  memcmp (job->icv_dst, in_packet_icv, job->icv_output_len_in_bytes))
	{
	  vlib_node_increment_counter (vm, node->node_index,
				       ESP_DECRYPT_ERROR_INTEG_ERROR, 1);
	  job->next = ESP_DECRYPT_NEXT_DROP;
	  job->error = IMB_ERR_INTEG_ERROR;
	  return;
	}
    }

  if (NULL_CIPHER != job->cipher_mode)
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
      if (ipsecmb_split_job_data_to_chain
	  (vm, node, ESP_DECRYPT_ERROR_NO_BUFFER, ESP_DECRYPT_NEXT_DROP, job,
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
	  job->next = ESP_DECRYPT_NEXT_IP4_INPUT;
	}
      else if (f0->next_header == IP_PROTOCOL_IPV6)
	{
	  job->next = ESP_DECRYPT_NEXT_IP6_INPUT;
	}
      else
	{
	  vlib_node_increment_counter (vm, node->node_index,
				       ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
				       1);
	  job->next = ESP_DECRYPT_NEXT_DROP;
	  job->error = IMB_ERR_DECRYPTION_FAILED;
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
	  job->next = ESP_DECRYPT_NEXT_IP6_INPUT;
	  ih6->protocol = f0->next_header;
	  ih6->payload_length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, job->b) -
				  sizeof (ip6_header_t));
	}
      else
	{
	  vlib_buffer_advance (job->b, -sizeof (ip4_header_t));
	  ip4_header_t *ih4 = vlib_buffer_get_current (job->b);
	  job->next = ESP_DECRYPT_NEXT_IP4_INPUT;
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
      job->next = ESP_DECRYPT_NEXT_IPSEC_GRE_INPUT;
    }

  vnet_buffer (job->b)->sw_if_index[VLIB_TX] = (u32) ~ 0;
  if (job->sa->use_anti_replay)
    {
      if (job->sa->use_esn)
	esp_replay_advance_esn (job->sa, vnet_buffer (job->b)->ipsec.seq);
      else
	esp_replay_advance (job->sa, vnet_buffer (job->b)->ipsec.seq);
    }
}

always_inline uword
ipsecmb_esp_decrypt_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame, int is_ip6)
{
  ipsec_main_t *im = &ipsec_main;
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 thread_index = vlib_get_thread_index ();
  ipsecmb_per_thread_data_t *t = &imbm->per_thread_data[thread_index];

  u32 n_left_from = from_frame->n_vectors;
  u32 *from = vlib_frame_vector_args (from_frame);
  ipsecmb_job_desc_t *job = t->jobs;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_get_buffers (vm, from, bufs, from_frame->n_vectors);

  while (n_left_from > 0)
    {
      esp_header_t *esp = 0;
      job->next = ESP_DECRYPT_NEXT_DROP;
      vlib_buffer_t *b0 = job->b = *b;
      u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
      ipsec_sa_t *sa0 = job->sa = pool_elt_at_index (im->sad, sa_index0);
      job->samb = pool_elt_at_index (imbm->sad, sa_index0);

      esp = vlib_buffer_get_current (b0);

      u32 seq = vnet_buffer (b0)->ipsec.seq = clib_host_to_net_u32 (esp->seq);

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
	      job->error = IMB_ERR_REPLAY;
	      goto next;
	    }
	}

      sa0->total_data_size += vlib_buffer_length_in_chain (vm, b0);

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
	    (vlib_buffer_length_in_chain (vm, b0) -
	     job->icv_output_len_in_bytes - sizeof (esp_header_t) -
	     iv_size) / block_size;
	  if (vlib_buffer_length_in_chain (vm, b0) - sizeof (esp_header_t) -
	      iv_size < block_size || blocks <= 0)
	    {
	      vlib_node_increment_counter (vm, node->node_index,
					   ESP_DECRYPT_ERROR_INTEG_ERROR, 1);
	      job->next = ESP_DECRYPT_NEXT_DROP;
	      job->error = IMB_ERR_INTEG_ERROR;
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
		  vlib_node_increment_counter (vm, node->node_index,
					       ESP_DECRYPT_ERROR_NOT_IP, 1);
		  job->error = IMB_ERR_NOT_IP;
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

      ipsecmb_merge_chain_to_job_data (vm, job, 0, 0, 0);

      job->cipher_dst = job->src;
      job->cipher_mode = imbm->crypto_algs[sa0->crypto_alg].cipher_mode;
      job->hash_start_src_offset_in_bytes = 0;
      job->error = IMB_ERR_OK;

      if (sa0->is_tunnel)
	{
	  b0->current_data -= ip_hdr_size;
	}
      b0->current_length = 0;
    next:
      job++;
      b++;
      --n_left_from;
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
					   ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
					   1);
	      job->next = ESP_DECRYPT_NEXT_DROP;
	      job->error = IMB_ERR_DECRYPTION_FAILED;
	    }
	  else
	    {
	      ipsecmb_esp_finish_decrypt (vm, node, job, is_ip6);
	    }
	}

      if (PREDICT_FALSE (job->b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsecmb_esp_trace_t *tr =
	    vlib_add_trace (vm, node, job->b, sizeof (*tr));
	  tr->spi = job->sa->spi;
	  tr->seq = job->sa->seq;
	  tr->integ_alg = job->sa->integ_alg;
	  tr->crypto_alg = job->sa->crypto_alg;
	  tr->error = job->error;
	  tr->sts = job->sts;
	  if (job->src)
	    {
	      tr->data_len = job->data_len;
	    }
	  else
	    {
	      tr->data_len = 0;
	    }
	  tr->crypto_len = job->msg_len_to_cipher_in_bytes;
	  tr->hash_len = job->msg_len_to_hash_in_bytes;
	}
      next[0] = job->next;
      next += 1;
    };

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  if (PREDICT_TRUE (vec_len (t->rb_from_traffic) > 0))
    {
      /* recycle traffic generated buffers, because once the packets are sent
       * out, bytes from these packets are no longer unpredictable */
      vec_add (t->rb_recycle_list, t->rb_from_traffic,
	       vec_len (t->rb_from_traffic));
      _vec_len (t->rb_from_traffic) = 0;
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (esp4_decrypt_ipsecmb_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * from_frame)
{
  return ipsecmb_esp_decrypt_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

VLIB_NODE_FN (esp6_decrypt_ipsecmb_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * from_frame)
{
  return ipsecmb_esp_decrypt_inline (vm, node, from_frame, 1 /*is_ip6 */ );
}
#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_decrypt_ipsecmb_node) = {
  .name = "esp4-decrypt-ipsecmb",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_trace,
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
  .format_trace = format_esp_trace,
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
