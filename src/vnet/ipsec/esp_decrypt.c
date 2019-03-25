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
#include <vnet/ipsec/ipsec_io.h>

#define foreach_esp_decrypt_next                \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input-no-checksum")           \
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

typedef struct
{
  u8 ip_hdr_size;
  u8 icv_sz;
  u8 iv_sz;
} esp_decrypt_post_data_t;

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

always_inline uword
esp_decrypt_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		    int is_ip6)
{
  ipsec_main_t *im = &ipsec_main;
  u32 thread_index = vm->thread_index;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, thread_index);
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left = from_frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  esp_decrypt_post_data_t post_data[VLIB_FRAME_SIZE], *pd = post_data;

  vlib_get_buffers (vm, from, b, n_left);
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->integ_ops);
  clib_memset_u16 (nexts, -1, n_left);

  while (n_left > 0)
    {
      ipsec_sa_t *sa0;
      esp_header_t *esp0;
      u32 seq;
      u32 sa_index0 = ~0;
      esp0 = vlib_buffer_get_current (b[0]);
      sa_index0 = vnet_buffer (b[0])->ipsec.sad_index;
      sa0 = pool_elt_at_index (im->sad, sa_index0);
      seq = clib_host_to_net_u32 (esp0->seq);
      u8 icv_sz = sa0->integ_trunc_size;

      // FIXME linearize chain
      // FIXME if (PREDICT_TRUE (sa0->use_esn)) { sizeof(seq_hi) ... };
      // FIXME payload mod block_size != 0

      if (sa0->use_anti_replay)
	{
	  int rv = 0;

	  if (PREDICT_TRUE (sa0->use_esn))
	    rv = esp_replay_check_esn (sa0, seq);
	  else
	    rv = esp_replay_check (sa0, seq);

	  if (PREDICT_FALSE (rv))
	    {
	      b[0]->error = node->errors[ESP_DECRYPT_ERROR_REPLAY];
	      next[0] = ESP_DECRYPT_NEXT_DROP;
	      goto trace;
	    }
	}

      vlib_increment_combined_counter
	(&ipsec_sa_counters, thread_index, sa_index0,
	 1, b[0]->current_length);

      u8 *payload = vlib_buffer_get_current (b[0]);
      u16 len = b[0]->current_length - icv_sz;
      u8 iv_size = sa0->crypto_iv_size;
      memset (pd, 0, sizeof (*pd));
      pd[0].icv_sz = icv_sz;
      pd[0].iv_sz = iv_size;

      if (PREDICT_TRUE (icv_sz > 0))
	{
	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ptd->integ_ops, op, 1, CLIB_CACHE_LINE_BYTES);

	  op->op = sa0->integ_op_type;
	  op->key = sa0->integ_key.data;
	  op->key_len = sa0->integ_key.len;
	  op->src = payload;
	  op->hmac_trunc_len = icv_sz;
	  op->flags = VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
	  op->user_data = b - bufs;
	  op->dst = payload + len;
	  op->len = len;
	  if (sa0->use_esn)
	    {
	      /* shift ICV for 4 bytes to insert ESN */
	      u8 tmp[ESP_MAX_ICV_SIZE], sz = sizeof (sa0->seq_hi);
	      clib_memcpy_fast (tmp, payload + len, ESP_MAX_ICV_SIZE);
	      clib_memcpy_fast (payload + len, &sa0->seq_hi, sz);
	      clib_memcpy_fast (payload + len + sz, tmp, ESP_MAX_ICV_SIZE);
	      op->len += sz;
	      op->dst += sz;
	    }
	}

      payload += sizeof (esp_header_t);
      len -= sizeof (esp_header_t);

      if (sa0->crypto_enc_op_type != VNET_CRYPTO_OP_NONE)
	{
	  u8 *iv = payload;
	  payload += iv_size;

	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ptd->crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
	  op->op = sa0->crypto_dec_op_type;
	  op->key = sa0->crypto_key.data;
	  op->iv = iv;
	  op->src = op->dst = payload;
	  op->len = len;
	  op->user_data = b - bufs;
	}

      if (PREDICT_FALSE (!sa0->is_tunnel && !sa0->is_tunnel_ip6))
	pd[0].ip_hdr_size = b[0]->current_data -
	  vnet_buffer (b[0])->l3_hdr_offset;

#if 0
      if (PREDICT_TRUE (sa0->use_anti_replay))
	{
	  if (PREDICT_TRUE (sa0->use_esn))
	    esp_replay_advance_esn (sa0, seq);
	  else
	    esp_replay_advance (sa0, seq);
	}

      if ((sa0->crypto_alg >= IPSEC_CRYPTO_ALG_AES_CBC_128 &&
	   sa0->crypto_alg <= IPSEC_CRYPTO_ALG_AES_CBC_256) ||
	  (sa0->crypto_alg >= IPSEC_CRYPTO_ALG_DES_CBC &&
	   sa0->crypto_alg <= IPSEC_CRYPTO_ALG_3DES_CBC))
	{
	  const int BLOCK_SIZE = sa0->crypto_block_size;
	  const int IV_SIZE = sa0->crypto_block_size;
	  esp_footer_t *f0;
	  u8 ip_hdr_size = 0;

	  int blocks =
	    (ib[0]->current_length - sizeof (esp_header_t) -
	     IV_SIZE) / BLOCK_SIZE;

	  ob[0]->current_data = sizeof (ethernet_header_t);

	  /* transport mode */
	  if (PREDICT_FALSE (!sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      tunnel_mode = 0;

	      if (is_ip6)
		{
		  ip_hdr_size = sizeof (ip6_header_t);
		  ih6 = (ip6_header_t *) ((u8 *) esp0 - ip_hdr_size);
		  oh6 = vlib_buffer_get_current (ob[0]);
		}
	      else
		{
		  ip_hdr_size = sizeof (ip4_header_t);
		  if (sa0->udp_encap)
		    ih4 = (ip4_header_t *) ((u8 *) esp0 - ip_hdr_size -
					    sizeof (udp_header_t));
		  else
		    ih4 = (ip4_header_t *) ((u8 *) esp0 - ip_hdr_size);
		  oh4 = vlib_buffer_get_current (ob[0]);
		}
	    }

	  esp_decrypt_cbc (vm, sa0, esp0->data + IV_SIZE,
			   (u8 *) vlib_buffer_get_current (ob[0]) +
			   ip_hdr_size, BLOCK_SIZE * blocks,
			   sa0->crypto_key.data, esp0->data);

	  ob[0]->current_length = (blocks * BLOCK_SIZE) - 2 + ip_hdr_size;
	  ob[0]->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  f0 = (esp_footer_t *) ((u8 *) vlib_buffer_get_current (ob[0]) +
				 ob[0]->current_length);
	  ob[0]->current_length -= f0->pad_length;

	  /* tunnel mode */
	  if (PREDICT_TRUE (tunnel_mode))
	    {
	      if (PREDICT_TRUE (f0->next_header == IP_PROTOCOL_IP_IN_IP))
		{
		  next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
		  oh4 = vlib_buffer_get_current (ob[0]);
		}
	      else if (f0->next_header == IP_PROTOCOL_IPV6)
		next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
	      else
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
					       1);
		  ob[0] = 0;
		  goto trace;
		}
	    }
	  /* transport mode */
	  else
	    {
	      u32 len = vlib_buffer_length_in_chain (vm, ob[0]);
	      if (is_ip6)
		{
		  next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
		  oh6->ip_version_traffic_class_and_flow_label =
		    ih6->ip_version_traffic_class_and_flow_label;
		  oh6->protocol = f0->next_header;
		  oh6->hop_limit = ih6->hop_limit;
		  oh6->src_address.as_u64[0] = ih6->src_address.as_u64[0];
		  oh6->src_address.as_u64[1] = ih6->src_address.as_u64[1];
		  oh6->dst_address.as_u64[0] = ih6->dst_address.as_u64[0];
		  oh6->dst_address.as_u64[1] = ih6->dst_address.as_u64[1];
		  len -= sizeof (ip6_header_t);
		  oh6->payload_length = clib_host_to_net_u16 (len);
		}
	      else
		{
		  next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
		  oh4->ip_version_and_header_length = 0x45;
		  oh4->tos = ih4->tos;
		  oh4->fragment_id = 0;
		  oh4->flags_and_fragment_offset = 0;
		  oh4->ttl = ih4->ttl;
		  oh4->protocol = f0->next_header;
		  oh4->src_address.as_u32 = ih4->src_address.as_u32;
		  oh4->dst_address.as_u32 = ih4->dst_address.as_u32;
		  oh4->length = clib_host_to_net_u16 (len);
		  oh4->checksum = ip4_header_checksum (oh4);
		}
	    }

	  /* for IPSec-GRE tunnel next node is ipsec-gre-input */
	  if (PREDICT_FALSE
	      ((vnet_buffer (ib[0])->ipsec.flags) &
	       IPSEC_FLAG_IPSEC_GRE_TUNNEL))
	    next[0] = ESP_DECRYPT_NEXT_IPSEC_GRE_INPUT;

	  vnet_buffer (ob[0])->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  vnet_buffer (ob[0])->sw_if_index[VLIB_RX] =
	    vnet_buffer (ib[0])->sw_if_index[VLIB_RX];
	}

#endif
    trace:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_decrypt_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->crypto_alg = sa0->crypto_alg;
	  tr->integ_alg = sa0->integ_alg;
	}

      /* next */
      n_left -= 1;
      b += 1;
      next += 1;
      pd += 1;
    }

  u32 n;
  if ((n = vec_len (ptd->integ_ops)))
    {
      n -= vnet_crypto_process_ops (vm, ptd->integ_ops, n);
      if (n)
	clib_warning ("%u failed", n);
    }
  if ((n = vec_len (ptd->crypto_ops)))
    {
      n -= vnet_crypto_process_ops (vm, ptd->crypto_ops, n);
      if (n)
	clib_warning ("%u failed", n);
    }

  n_left = from_frame->n_vectors;
  b = bufs;
  next = nexts;
  pd = post_data;
  while (n_left)
    {
      if (next[0] >= ESP_DECRYPT_N_NEXT)
	{
	  esp_footer_t *f = (esp_footer_t *) (vlib_buffer_get_tail (b[0]) -
					      sizeof (*f) - pd->icv_sz);
	  u16 adv = pd->iv_sz + sizeof (esp_header_t);
	  i16 tail = sizeof (*f) + f->pad_length + pd->icv_sz;

	  if (pd->ip_hdr_size)
	    {
	      u8 *old_ip = vlib_buffer_get_current (b[0]) - pd->ip_hdr_size;
	      u8 *ip = old_ip + adv;

	      fformat (stderr, "\n%U\n", format_hexdump, old_ip,
		       pd->ip_hdr_size);

	      memmove (ip, old_ip, pd->ip_hdr_size);	//FIXME
	      b[0]->current_data += adv - pd->ip_hdr_size;
	      b[0]->current_length -= tail + adv - pd->ip_hdr_size;
	      if (is_ip6)
		{
		  ip6_header_t *ip6 = (ip6_header_t *) ip;
		  u16 l = clib_net_to_host_u16 (ip6->payload_length);
		  ip6->payload_length = clib_host_to_net_u16 (l - adv - tail);
		  ip6->protocol = f->next_header;
		  next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
		}
	      else
		{
		  ip4_header_t *ip4 = (ip4_header_t *) ip;
		  ip_csum_t sum = ip4->checksum;
		  u16 len = clib_net_to_host_u16 (ip4->length) - adv - tail;
		  len = clib_host_to_net_u16 (len);
		  sum = ip_csum_update (sum, ip4->protocol, f->next_header,
					ip4_header_t, protocol);
		  sum = ip_csum_update (sum, ip4->length, len,
					ip4_header_t, length);
		  ip4->checksum = ip_csum_fold (sum);
		  ip4->protocol = f->next_header;
		  ip4->length = len;
		  next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
		}
	    }
	  else
	    {
	      if (PREDICT_TRUE (f->next_header == IP_PROTOCOL_IP_IN_IP))
		{
		  next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
		  b[0]->current_data += adv;
		  b[0]->current_length -= tail - adv;
		}
	      else if (f->next_header == IP_PROTOCOL_IPV6)
		{
		  next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
		  b[0]->current_data += adv;
		  b[0]->current_length -= tail - adv;
		}
	      else
		{
		  next[0] = ESP_DECRYPT_NEXT_DROP;
		  b[0]->error =
		    node->errors[ESP_DECRYPT_ERROR_DECRYPTION_FAILED];
		}
	    }
	}

      /* next */
      n_left -= 1;
      b += 1;
      next += 1;
      pd += 1;
    }

  n_left = from_frame->n_vectors;
  vlib_node_increment_counter (vm, node->node_index,
			       ESP_DECRYPT_ERROR_RX_PKTS, n_left);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);

  b = bufs;
  fformat (stderr, "\n%U\n", format_hexdump, vlib_buffer_get_current (b[0]),
	   b[0]->current_length);
  return n_left;
}

VLIB_NODE_FN (esp4_decrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_decrypt_node) = {
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

VLIB_NODE_FN (esp6_decrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_decrypt_node) = {
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
