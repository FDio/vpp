/*
 * esp_decrypt.c : IPSec ESP Decrypt node using DPDK Cryptodev
 *
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a opy of the License at:
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
#include <dpdk/buffer.h>
#include <dpdk/ipsec/ipsec.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>

#define foreach_esp_decrypt_next	       \
_(DROP, "error-drop")			       \
_(IP4_INPUT, "ip4-input-no-checksum")	       \
_(IP6_INPUT, "ip6-input")

#define _(v, s) ESP_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_decrypt_next
#undef _
    ESP_DECRYPT_N_NEXT,
} esp_decrypt_next_t;

#define foreach_esp_decrypt_error		 \
 _(RX_PKTS, "ESP pkts received")		 \
 _(DECRYPTION_FAILED, "ESP decryption failed")   \
 _(REPLAY, "SA replayed packet")	         \
 _(NOT_IP, "Not IP packet (dropped)")	         \
 _(ENQ_FAIL, "Enqueue decrypt failed (queue full)")     \
 _(DISCARD, "Not enough crypto operations")      \
 _(BAD_LEN, "Invalid ciphertext length")         \
 _(SESSION, "Failed to get crypto session")      \
 _(NOSUP, "Cipher/Auth not supported")


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

extern vlib_node_registration_t dpdk_esp4_decrypt_node;
extern vlib_node_registration_t dpdk_esp6_decrypt_node;

typedef struct
{
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  u8 packet_data[64];
} esp_decrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_decrypt_trace_t *t = va_arg (*args, esp_decrypt_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "cipher %U auth %U\n",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);
  s = format (s, "%U%U",
	      format_white_space, indent, format_esp_header, t->packet_data);
  return s;
}

always_inline uword
dpdk_esp_decrypt_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame, int is_ip6)
{
  u32 n_left_from, *from, *to_next, next_index, thread_index;
  ipsec_main_t *im = &ipsec_main;
  u32 thread_idx = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_resource_t *res = 0;
  ipsec_sa_t *sa0 = 0;
  crypto_alg_t *cipher_alg = 0, *auth_alg = 0;
  struct rte_cryptodev_sym_session *session = 0;
  u32 ret, last_sa_index = ~0;
  u8 numa = rte_socket_id ();
  u8 is_aead = 0;
  crypto_worker_main_t *cwm =
    vec_elt_at_index (dcm->workers_main, thread_idx);
  struct rte_crypto_op **ops = cwm->ops;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  thread_index = vm->thread_index;

  ret = crypto_alloc_ops (numa, ops, n_left_from);
  if (ret)
    {
      if (is_ip6)
	vlib_node_increment_counter (vm, dpdk_esp6_decrypt_node.index,
				     ESP_DECRYPT_ERROR_DISCARD, n_left_from);
      else
	vlib_node_increment_counter (vm, dpdk_esp4_decrypt_node.index,
				     ESP_DECRYPT_ERROR_DISCARD, n_left_from);
      /* Discard whole frame */
      vlib_buffer_free (vm, from, n_left_from);
      return n_left_from;
    }

  next_index = ESP_DECRYPT_NEXT_DROP;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  clib_error_t *error;
	  u32 bi0, sa_index0, iv_size;
	  u8 trunc_size;
	  vlib_buffer_t *b0;
	  esp_header_t *esp0;
	  struct rte_mbuf *mb0;
	  struct rte_crypto_op *op;
	  u16 res_idx;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  mb0 = rte_mbuf_from_vlib_buffer (b0);
	  esp0 = vlib_buffer_get_current (b0);

	  /* ih0/ih6_0 */
	  CLIB_PREFETCH (esp0, sizeof (esp0[0]) + 16, LOAD);
	  /* mb0 */
	  CLIB_PREFETCH (mb0, CLIB_CACHE_LINE_BYTES, STORE);

	  op = ops[0];
	  ops += 1;
	  ASSERT (op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED);

	  dpdk_op_priv_t *priv = crypto_op_get_priv (op);
	  /* store bi in op private */
	  priv->bi = bi0;
	  priv->encrypt = 0;

	  u16 op_len =
	    sizeof (op[0]) + sizeof (op[0].sym[0]) + sizeof (priv[0]);
	  CLIB_PREFETCH (op, op_len, STORE);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  vlib_prefetch_combined_counter (&ipsec_sa_counters,
					  thread_index, sa_index0);

	  if (sa_index0 != last_sa_index)
	    {
	      sa0 = pool_elt_at_index (im->sad, sa_index0);

	      cipher_alg =
		vec_elt_at_index (dcm->cipher_algs, sa0->crypto_alg);
	      auth_alg = vec_elt_at_index (dcm->auth_algs, sa0->integ_alg);

	      is_aead = (cipher_alg->type == RTE_CRYPTO_SYM_XFORM_AEAD);
	      if (is_aead)
		auth_alg = cipher_alg;

	      res_idx = get_resource (cwm, sa0);

	      if (PREDICT_FALSE (res_idx == (u16) ~ 0))
		{
		  if (is_ip6)
		    vlib_node_increment_counter (vm,
						 dpdk_esp6_decrypt_node.index,
						 ESP_DECRYPT_ERROR_NOSUP, 1);
		  else
		    vlib_node_increment_counter (vm,
						 dpdk_esp4_decrypt_node.index,
						 ESP_DECRYPT_ERROR_NOSUP, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  goto trace;
		}
	      res = vec_elt_at_index (dcm->resource, res_idx);

	      error = crypto_get_session (&session, sa_index0, res, cwm, 0);
	      if (PREDICT_FALSE (error || !session))
		{
		  if (is_ip6)
		    vlib_node_increment_counter (vm,
						 dpdk_esp6_decrypt_node.index,
						 ESP_DECRYPT_ERROR_SESSION,
						 1);
		  else
		    vlib_node_increment_counter (vm,
						 dpdk_esp4_decrypt_node.index,
						 ESP_DECRYPT_ERROR_SESSION,
						 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  goto trace;
		}

	      last_sa_index = sa_index0;
	    }

	  /* anti-replay check */
	  if (ipsec_sa_anti_replay_check
	      (sa0, clib_host_to_net_u32 (esp0->seq)))
	    {
	      if (is_ip6)
		vlib_node_increment_counter (vm,
					     dpdk_esp6_decrypt_node.index,
					     ESP_DECRYPT_ERROR_REPLAY, 1);
	      else
		vlib_node_increment_counter (vm,
					     dpdk_esp4_decrypt_node.index,
					     ESP_DECRYPT_ERROR_REPLAY, 1);
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      goto trace;
	    }

	  if (is_ip6)
	    priv->next = DPDK_CRYPTO_INPUT_NEXT_DECRYPT6_POST;
	  else
	    {
	      priv->next = DPDK_CRYPTO_INPUT_NEXT_DECRYPT4_POST;
	      b0->flags |= VNET_BUFFER_F_IS_IP4;
	    }

	  /* FIXME multi-seg */
	  vlib_increment_combined_counter
	    (&ipsec_sa_counters, thread_index, sa_index0,
	     1, b0->current_length);

	  res->ops[res->n_ops] = op;
	  res->bi[res->n_ops] = bi0;
	  res->n_ops += 1;

	  /* Convert vlib buffer to mbuf */
	  mb0->data_len = b0->current_length;
	  mb0->pkt_len = b0->current_length;
	  mb0->data_off = RTE_PKTMBUF_HEADROOM + b0->current_data;

	  trunc_size = auth_alg->trunc_size;
	  iv_size = cipher_alg->iv_len;

	  /* Outer IP header has already been stripped */
	  u16 payload_len =
	    b0->current_length - sizeof (esp_header_t) - iv_size - trunc_size;

	  ASSERT (payload_len >= 4);

	  if (payload_len & (cipher_alg->boundary - 1))
	    {
	      if (is_ip6)
		vlib_node_increment_counter (vm, dpdk_esp6_decrypt_node.index,
					     ESP_DECRYPT_ERROR_BAD_LEN, 1);
	      else
		vlib_node_increment_counter (vm, dpdk_esp4_decrypt_node.index,
					     ESP_DECRYPT_ERROR_BAD_LEN, 1);
	      res->n_ops -= 1;
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      goto trace;
	    }

	  u32 cipher_off, cipher_len;
	  u32 auth_len = 0;
	  u8 *aad = NULL;

	  u8 *iv = (u8 *) (esp0 + 1);

	  dpdk_gcm_cnt_blk *icb = &priv->cb;

	  cipher_off = sizeof (esp_header_t) + iv_size;
	  cipher_len = payload_len;

	  u8 *digest = vlib_buffer_get_tail (b0) - trunc_size;
	  u64 digest_paddr = mb0->buf_iova + digest - ((u8 *) mb0->buf_addr);

	  if (!is_aead && cipher_alg->alg == RTE_CRYPTO_CIPHER_AES_CBC)
	    clib_memcpy_fast (icb, iv, 16);
	  else			/* CTR/GCM */
	    {
	      u32 *_iv = (u32 *) iv;

	      crypto_set_icb (icb, sa0->salt, _iv[0], _iv[1]);
	    }

	  if (is_aead)
	    {
	      aad = priv->aad;
	      u32 *_aad = (u32 *) aad;
	      clib_memcpy_fast (aad, esp0, 8);

	      /* _aad[3] should always be 0 */
	      if (PREDICT_FALSE (ipsec_sa_is_set_USE_ESN (sa0)))
		{
		  _aad[2] = _aad[1];
		  _aad[1] = clib_host_to_net_u32 (sa0->seq_hi);
		}
	      else
		_aad[2] = 0;
	    }
	  else
	    {
	      auth_len = sizeof (esp_header_t) + iv_size + payload_len;

	      if (ipsec_sa_is_set_USE_ESN (sa0))
		{
		  clib_memcpy_fast (priv->icv, digest, trunc_size);
		  u32 *_digest = (u32 *) digest;
		  _digest[0] = clib_host_to_net_u32 (sa0->seq_hi);
		  auth_len += sizeof (sa0->seq_hi);

		  digest = priv->icv;
		  digest_paddr =
		    op->phys_addr + (uintptr_t) priv->icv - (uintptr_t) op;
		}
	    }

	  crypto_op_setup (is_aead, mb0, op, session, cipher_off, cipher_len,
			   0, auth_len, aad, digest, digest_paddr);
	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	      clib_memcpy_fast (tr->packet_data, vlib_buffer_get_current (b0),
				sizeof (esp_header_t));
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (is_ip6)
    {
      vlib_node_increment_counter (vm, dpdk_esp6_decrypt_node.index,
				   ESP_DECRYPT_ERROR_RX_PKTS,
				   from_frame->n_vectors);

      crypto_enqueue_ops (vm, cwm, dpdk_esp6_decrypt_node.index,
			  ESP_DECRYPT_ERROR_ENQ_FAIL, numa, 0 /* encrypt */ );
    }
  else
    {
      vlib_node_increment_counter (vm, dpdk_esp4_decrypt_node.index,
				   ESP_DECRYPT_ERROR_RX_PKTS,
				   from_frame->n_vectors);

      crypto_enqueue_ops (vm, cwm, dpdk_esp4_decrypt_node.index,
			  ESP_DECRYPT_ERROR_ENQ_FAIL, numa, 0 /* encrypt */ );
    }

  crypto_free_ops (numa, ops, cwm->ops + from_frame->n_vectors - ops);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (dpdk_esp4_decrypt_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return dpdk_esp_decrypt_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp4_decrypt_node) = {
  .name = "dpdk-esp4-decrypt",
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

VLIB_NODE_FN (dpdk_esp6_decrypt_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return dpdk_esp_decrypt_inline (vm, node, from_frame, 1 /*is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp6_decrypt_node) = {
  .name = "dpdk-esp6-decrypt",
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
 * Decrypt Post Node
 */

#define foreach_esp_decrypt_post_error	      \
 _(PKTS, "ESP post pkts")

typedef enum
{
#define _(sym,str) ESP_DECRYPT_POST_ERROR_##sym,
  foreach_esp_decrypt_post_error
#undef _
    ESP_DECRYPT_POST_N_ERROR,
} esp_decrypt_post_error_t;

static char *esp_decrypt_post_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_decrypt_post_error
#undef _
};

extern vlib_node_registration_t dpdk_esp4_decrypt_post_node;
extern vlib_node_registration_t dpdk_esp6_decrypt_post_node;

static u8 *
format_esp_decrypt_post_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_decrypt_trace_t *t = va_arg (*args, esp_decrypt_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "cipher %U auth %U\n",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);

  ip4_header_t *ih4 = (ip4_header_t *) t->packet_data;
  if ((ih4->ip_version_and_header_length & 0xF0) == 0x60)
    s =
      format (s, "%U%U", format_white_space, indent, format_ip6_header, ih4);
  else
    s =
      format (s, "%U%U", format_white_space, indent, format_ip4_header, ih4);

  return s;
}

always_inline uword
dpdk_esp_decrypt_post_inline (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * from_frame, int is_ip6)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  ipsec_sa_t *sa0;
  u32 sa_index0 = ~0;
  ipsec_main_t *im = &ipsec_main;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  esp_footer_t *f0;
	  u32 bi0, iv_size, next0;
	  vlib_buffer_t *b0 = 0;
	  ip4_header_t *ih4 = 0, *oh4 = 0;
	  ip6_header_t *ih6 = 0, *oh6 = 0;
	  crypto_alg_t *cipher_alg, *auth_alg;
	  esp_header_t *esp0;
	  u8 trunc_size, is_aead;
	  u16 udp_encap_adv = 0;

	  next0 = ESP_DECRYPT_NEXT_DROP;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  esp0 = vlib_buffer_get_current (b0);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  to_next[0] = bi0;
	  to_next += 1;

	  cipher_alg = vec_elt_at_index (dcm->cipher_algs, sa0->crypto_alg);
	  auth_alg = vec_elt_at_index (dcm->auth_algs, sa0->integ_alg);
	  is_aead = cipher_alg->type == RTE_CRYPTO_SYM_XFORM_AEAD;
	  if (is_aead)
	    auth_alg = cipher_alg;

	  trunc_size = auth_alg->trunc_size;

	  iv_size = cipher_alg->iv_len;

	  ipsec_sa_anti_replay_advance (sa0,
					clib_host_to_net_u32 (esp0->seq));

	  /* if UDP encapsulation is used adjust the address of the IP header */
	  if (ipsec_sa_is_set_UDP_ENCAP (sa0)
	      && (b0->flags & VNET_BUFFER_F_IS_IP4))
	    {
	      udp_encap_adv = sizeof (udp_header_t);
	    }

	  if (b0->flags & VNET_BUFFER_F_IS_IP4)
	    ih4 = (ip4_header_t *)
	      ((u8 *) esp0 - udp_encap_adv - sizeof (ip4_header_t));
	  else
	    ih4 = (ip4_header_t *) ((u8 *) esp0 - sizeof (ip6_header_t));

	  vlib_buffer_advance (b0, sizeof (esp_header_t) + iv_size);

	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  f0 = (esp_footer_t *) (vlib_buffer_get_tail (b0) - trunc_size - 2);
	  b0->current_length -= (f0->pad_length + trunc_size + 2);
#if 0
	  /* check padding */
	  const u8 *padding = vlib_buffer_get_tail (b0);
	  if (PREDICT_FALSE (memcmp (padding, pad_data, f0->pad_length)))
	    {
	      clib_warning ("bad padding");
	      vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
					   ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
					   1);
	      goto trace;
	    }
#endif
	  if (ipsec_sa_is_set_IS_TUNNEL (sa0))
	    {
	      if (f0->next_header == IP_PROTOCOL_IP_IN_IP)
		next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
	      else if (f0->next_header == IP_PROTOCOL_IPV6)
		next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
	      else
		{
		  clib_warning ("next header: 0x%x", f0->next_header);
		  if (is_ip6)
		    vlib_node_increment_counter (vm,
						 dpdk_esp6_decrypt_node.index,
						 ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						 1);
		  else
		    vlib_node_increment_counter (vm,
						 dpdk_esp4_decrypt_node.index,
						 ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						 1);
		  goto trace;
		}
	    }
	  else			/* transport mode */
	    {
	      if ((ih4->ip_version_and_header_length & 0xF0) == 0x40)
		{
		  u16 ih4_len = ip4_header_bytes (ih4);
		  vlib_buffer_advance (b0, -ih4_len);
		  next0 = ESP_DECRYPT_NEXT_IP4_INPUT;

		  oh4 = vlib_buffer_get_current (b0);
		  memmove (oh4, ih4, ih4_len);
		  oh4->protocol = f0->next_header;
		  oh4->length = clib_host_to_net_u16 (b0->current_length);
		  oh4->checksum = ip4_header_checksum (oh4);
		}
	      else if ((ih4->ip_version_and_header_length & 0xF0) == 0x60)
		{
		  ih6 = (ip6_header_t *) ih4;
		  vlib_buffer_advance (b0, -sizeof (ip6_header_t));
		  oh6 = vlib_buffer_get_current (b0);
		  memmove (oh6, ih6, sizeof (ip6_header_t));

		  next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
		  oh6->protocol = f0->next_header;
		  u16 len = b0->current_length - sizeof (ip6_header_t);
		  oh6->payload_length = clib_host_to_net_u16 (len);
		}
	      else
		{
		  clib_warning ("next header: 0x%x", f0->next_header);
		  if (is_ip6)
		    vlib_node_increment_counter (vm,
						 dpdk_esp6_decrypt_node.index,
						 ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						 1);
		  else
		    vlib_node_increment_counter (vm,
						 dpdk_esp4_decrypt_node.index,
						 ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						 1);
		  goto trace;
		}
	    }

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	      ih4 = vlib_buffer_get_current (b0);
	      clib_memcpy_fast (tr->packet_data, ih4, sizeof (ip6_header_t));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (is_ip6)
    vlib_node_increment_counter (vm, dpdk_esp6_decrypt_post_node.index,
				 ESP_DECRYPT_POST_ERROR_PKTS,
				 from_frame->n_vectors);
  else
    vlib_node_increment_counter (vm, dpdk_esp4_decrypt_post_node.index,
				 ESP_DECRYPT_POST_ERROR_PKTS,
				 from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (dpdk_esp4_decrypt_post_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * from_frame)
{
  return dpdk_esp_decrypt_post_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp4_decrypt_post_node) = {
  .name = "dpdk-esp4-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_post_error_strings),
  .error_strings = esp_decrypt_post_error_strings,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_DECRYPT_NEXT_##s] = n,
    foreach_esp_decrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (dpdk_esp6_decrypt_post_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * from_frame)
{
  return dpdk_esp_decrypt_post_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp6_decrypt_post_node) = {
  .name = "dpdk-esp6-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_post_error_strings),
  .error_strings = esp_decrypt_post_error_strings,

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
