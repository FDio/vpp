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
esp_decrypt_cbc (vlib_main_t * vm, ipsec_sa_t * sa,
		 u8 * in, u8 * out, size_t in_len, u8 * key, u8 * iv)
{
  vnet_crypto_op_t _op, *op = &_op;


  if (PREDICT_FALSE (sa->crypto_dec_op_type == VNET_CRYPTO_OP_NONE))
    return;

  op->op = sa->crypto_dec_op_type;
  op->iv = iv;
  op->src = in;
  op->dst = out;
  op->len = in_len;
  op->key = key;

  vnet_crypto_process_ops (vm, op, 1);
}

always_inline uword
esp_decrypt_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		    int is_ip6)
{
  ipsec_main_t *im = &ipsec_main;
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left_from = from_frame->n_vectors;
  u32 new_bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t *i_bufs[VLIB_FRAME_SIZE], **ib = i_bufs;
  vlib_buffer_t *o_bufs[VLIB_FRAME_SIZE], **ob = o_bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 n_alloc, thread_index = vm->thread_index;

  n_alloc = vlib_buffer_alloc (vm, new_bufs, n_left_from);
  if (n_alloc != n_left_from)
    {
      vlib_node_increment_counter (vm, node->node_index,
				   ESP_DECRYPT_ERROR_NO_BUFFER,
				   n_left_from - n_alloc);
      if (n_alloc == 0)
	goto done;
      n_left_from = n_alloc;
    }

  vlib_get_buffers (vm, from, ib, n_left_from);
  vlib_get_buffers (vm, new_bufs, ob, n_left_from);

  while (n_left_from > 0)
    {
      esp_header_t *esp0;
      ipsec_sa_t *sa0;
      u32 sa_index0 = ~0;
      u32 seq;
      ip4_header_t *ih4 = 0, *oh4 = 0;
      ip6_header_t *ih6 = 0, *oh6 = 0;
      u8 tunnel_mode = 1;

      next[0] = ESP_DECRYPT_NEXT_DROP;

      esp0 = vlib_buffer_get_current (ib[0]);
      sa_index0 = vnet_buffer (ib[0])->ipsec.sad_index;
      sa0 = pool_elt_at_index (im->sad, sa_index0);
      seq = clib_host_to_net_u32 (esp0->seq);

      /* anti-replay check */
      if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa0))
	{
	  int rv = 0;

	  if (PREDICT_TRUE (ipsec_sa_is_set_USE_EXTENDED_SEQ_NUM (sa0)))
	    rv = esp_replay_check_esn (sa0, seq);
	  else
	    rv = esp_replay_check (sa0, seq);

	  if (PREDICT_FALSE (rv))
	    {
	      u32 tmp, off = n_alloc - n_left_from;
	      /* send original packet to drop node */
	      tmp = from[off];
	      from[off] = new_bufs[off];
	      new_bufs[off] = tmp;
	      ib[0]->error = node->errors[ESP_DECRYPT_ERROR_REPLAY];
	      next[0] = ESP_DECRYPT_NEXT_DROP;
	      goto trace;
	    }
	}

      vlib_increment_combined_counter
	(&ipsec_sa_counters, thread_index, sa_index0,
	 1, ib[0]->current_length);

      if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	{
	  u8 sig[64];
	  int icv_size = sa0->integ_trunc_size;
	  clib_memset (sig, 0, sizeof (sig));
	  u8 *icv = vlib_buffer_get_current (ib[0]) + ib[0]->current_length -
	    icv_size;
	  ib[0]->current_length -= icv_size;

	  hmac_calc (vm, sa0, (u8 *) esp0, ib[0]->current_length, sig);

	  if (PREDICT_FALSE (memcmp (icv, sig, icv_size)))
	    {
	      u32 tmp, off = n_alloc - n_left_from;
	      /* send original packet to drop node */
	      tmp = from[off];
	      from[off] = new_bufs[off];
	      new_bufs[off] = tmp;
	      ib[0]->error = node->errors[ESP_DECRYPT_ERROR_INTEG_ERROR];
	      next[0] = ESP_DECRYPT_NEXT_DROP;
	      goto trace;
	    }
	}

      if (PREDICT_TRUE (ipsec_sa_is_set_USE_ANTI_REPLAY (sa0)))
	{
	  if (PREDICT_TRUE (ipsec_sa_is_set_USE_EXTENDED_SEQ_NUM (sa0)))
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
	  if (PREDICT_FALSE (!ipsec_sa_is_set_IS_TUNNEL (sa0) &&
			     !ipsec_sa_is_set_IS_TUNNEL_V6 (sa0)))
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
		  if (ipsec_sa_is_set_UDP_ENCAP (sa0))
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
	  if (PREDICT_FALSE (ipsec_sa_is_set_IS_GRE (sa0)))
	    next[0] = ESP_DECRYPT_NEXT_IPSEC_GRE_INPUT;

	  vnet_buffer (ob[0])->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  vnet_buffer (ob[0])->sw_if_index[VLIB_RX] =
	    vnet_buffer (ib[0])->sw_if_index[VLIB_RX];
	}

    trace:
      if (PREDICT_FALSE (ib[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  if (ob[0])
	    {
	      ob[0]->flags |= VLIB_BUFFER_IS_TRACED;
	      ob[0]->trace_index = ib[0]->trace_index;
	      esp_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, ob[0], sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }
	}

      /* next */
      n_left_from -= 1;
      ib += 1;
      ob += 1;
      next += 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       ESP_DECRYPT_ERROR_RX_PKTS, n_alloc);

  vlib_buffer_enqueue_to_next (vm, node, new_bufs, nexts, n_alloc);
done:
  vlib_buffer_free (vm, from, from_frame->n_vectors);
  return n_alloc;
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
