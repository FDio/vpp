/*
 * esp_decrypt.c : IPSec ESP Decrypt node using DPDK Cryptodev
 *
 * Copyright (c) 2016 Intel and/or its affiliates.
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
#include <dpdk/ipsec/ipsec.h>
#include <dpdk/ipsec/esp.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>

#define foreach_esp_decrypt_next	       \
_(DROP, "error-drop")			       \
_(IP4_INPUT, "ip4-input")		       \
_(IP6_INPUT, "ip6-input")

#define _(v, s) ESP_DECRYPT_NEXT_##v,
typedef enum {
  foreach_esp_decrypt_next
#undef _
  ESP_DECRYPT_N_NEXT,
} esp_decrypt_next_t;

#define foreach_esp_decrypt_error		 \
 _(RX_PKTS, "ESP pkts received")		 \
 _(DECRYPTION_FAILED, "ESP decryption failed")   \
 _(REPLAY, "SA replayed packet")	         \
 _(NOT_IP, "Not IP packet (dropped)")	         \
 _(ENQ_FAIL, "Enqueue failed (buffer full)")     \
 _(NO_CRYPTODEV, "Cryptodev not configured")     \
 _(BAD_LEN, "Invalid ciphertext length")


typedef enum {
#define _(sym,str) ESP_DECRYPT_ERROR_##sym,
  foreach_esp_decrypt_error
#undef _
  ESP_DECRYPT_N_ERROR,
} esp_decrypt_error_t;

static char * esp_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_decrypt_error
#undef _
};

vlib_node_registration_t dpdk_esp_decrypt_node;

typedef struct {
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_decrypt_trace_t;

/* packet trace format function */
static u8 * format_esp_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_decrypt_trace_t * t = va_arg (*args, esp_decrypt_trace_t *);

  s = format (s, "esp: crypto %U integrity %U",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);
  return s;
}

static uword
dpdk_esp_decrypt_node_fn (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next, next_index;
  ipsec_main_t *im = &ipsec_main;
  u32 thread_index = vlib_get_thread_index();
  dpdk_crypto_main_t * dcm = &dpdk_crypto_main;
  dpdk_esp_main_t * em = &dpdk_esp_main;
  u32 i;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  crypto_worker_main_t *cwm =
    vec_elt_at_index(dcm->workers_main, thread_index);
  u32 n_qps = vec_len(cwm->qp_data);
  struct rte_crypto_op ** cops_to_enq[n_qps];
  u32 n_cop_qp[n_qps], * bi_to_enq[n_qps];

  for (i = 0; i < n_qps; i++)
    {
      bi_to_enq[i] = cwm->qp_data[i].bi;
      cops_to_enq[i] = cwm->qp_data[i].cops;
    }

  memset(n_cop_qp, 0, n_qps * sizeof(u32));

  crypto_alloc_cops();

  next_index = ESP_DECRYPT_NEXT_DROP;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, sa_index0 = ~0, seq, trunc_size, iv_size;
	  vlib_buffer_t * b0;
	  esp_header_t * esp0;
	  ipsec_sa_t * sa0;
	  struct rte_mbuf * mb0 = 0;
	  const int BLOCK_SIZE = 16;
	  crypto_sa_session_t * sa_sess;
	  void * sess;
	  u16 qp_index;
	  struct rte_crypto_op * cop = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  esp0 = vlib_buffer_get_current (b0);

	  sa_index0 = vnet_buffer(b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  seq = clib_host_to_net_u32(esp0->seq);

	  /* anti-replay check */
	  if (sa0->use_anti_replay)
	    {
	      int rv = 0;

	      if (PREDICT_TRUE(sa0->use_esn))
		rv = esp_replay_check_esn(sa0, seq);
	      else
		rv = esp_replay_check(sa0, seq);

	      if (PREDICT_FALSE(rv))
		{
		  clib_warning ("anti-replay SPI %u seq %u", sa0->spi, seq);
		  vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_REPLAY, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  goto trace;
		}
	    }

	  sa0->total_data_size += b0->current_length;

	  sa_sess = pool_elt_at_index(cwm->sa_sess_d[0], sa_index0);

	  if (PREDICT_FALSE(!sa_sess->sess))
	    {
	      int ret = create_sym_sess(sa0, sa_sess, 0);

	      if (PREDICT_FALSE (ret))
		{
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  goto trace;
		}
	    }

	  sess = sa_sess->sess;
	  qp_index = sa_sess->qp_index;

	  ASSERT (vec_len (vec_elt (cwm->qp_data, qp_index).free_cops) > 0);
	  cop = vec_pop (vec_elt (cwm->qp_data, qp_index).free_cops);
	  ASSERT (cop->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED);

	  cops_to_enq[qp_index][0] = cop;
	  cops_to_enq[qp_index] += 1;
	  n_cop_qp[qp_index] += 1;
	  bi_to_enq[qp_index][0] = bi0;
	  bi_to_enq[qp_index] += 1;

	  rte_crypto_op_attach_sym_session(cop, sess);

	  if (sa0->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128)
	    trunc_size = 16;
	  else
	    trunc_size = em->esp_integ_algs[sa0->integ_alg].trunc_size;
	  iv_size = em->esp_crypto_algs[sa0->crypto_alg].iv_len;

	  /* Convert vlib buffer to mbuf */
	  mb0 = rte_mbuf_from_vlib_buffer(b0);
	  mb0->data_len = b0->current_length;
	  mb0->pkt_len = b0->current_length;
	  mb0->data_off = RTE_PKTMBUF_HEADROOM + b0->current_data;

	  /* Outer IP header has already been stripped */
	  u16 payload_len = rte_pktmbuf_pkt_len(mb0) - sizeof (esp_header_t) -
	      iv_size - trunc_size;

	  if ((payload_len & (BLOCK_SIZE - 1)) || (payload_len <= 0))
	    {
	      clib_warning ("payload %u not multiple of %d\n",
			    payload_len, BLOCK_SIZE);
	      vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
					   ESP_DECRYPT_ERROR_BAD_LEN, 1);
	      vec_add (vec_elt (cwm->qp_data, qp_index).free_cops, &cop, 1);
	      bi_to_enq[qp_index] -= 1;
	      cops_to_enq[qp_index] -= 1;
	      n_cop_qp[qp_index] -= 1;
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      goto trace;
	    }

	  struct rte_crypto_sym_op *sym_cop = (struct rte_crypto_sym_op *)(cop + 1);

	  u8 is_aead = sa0->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128;
	  u32 cipher_off, cipher_len;
	  u32 auth_off = 0, auth_len = 0, aad_size = 0;
	  u8 *aad = NULL, *digest = NULL;
	  u64 digest_paddr = 0;

          u8 *iv = rte_pktmbuf_mtod_offset(mb0, void*, sizeof (esp_header_t));
          dpdk_cop_priv_t *priv = (dpdk_cop_priv_t *)(sym_cop + 1);
          dpdk_gcm_cnt_blk *icb = &priv->cb;

	  cipher_off = sizeof (esp_header_t) + iv_size;
	  cipher_len = payload_len;

          digest =
	    vlib_buffer_get_current (b0) + sizeof(esp_header_t) +
	    iv_size + payload_len;

          if (is_aead)
            {
	      u32 *_iv = (u32 *) iv;

	      crypto_set_icb (icb, sa0->salt, _iv[0], _iv[1]);
	      iv_size = 16;

              aad = priv->aad;
              clib_memcpy(aad, esp0, 8);
	      aad_size = 8;
              if (sa0->use_esn)
		{
		  *((u32*)&aad[8]) = sa0->seq_hi;
		  aad_size = 12;
		}
            }
          else
            {
	      clib_memcpy(icb, iv, 16);

	      auth_off = 0;
	      auth_len = sizeof(esp_header_t) + iv_size + payload_len;

              if (sa0->use_esn)
                {
                  dpdk_cop_priv_t* priv = (dpdk_cop_priv_t*) (sym_cop + 1);

                  clib_memcpy (priv->icv, digest, trunc_size);
                  *((u32*) digest) = sa0->seq_hi;
		  auth_len += sizeof(sa0->seq_hi);

                  digest = priv->icv;
		  digest_paddr =
		    cop->phys_addr + (uintptr_t) priv->icv - (uintptr_t) cop;
                }
            }

	  crypto_op_setup (is_aead, mb0, cop, sess,
			   cipher_off, cipher_len, (u8 *) icb, iv_size,
			   auth_off, auth_len, aad, aad_size,
			   digest, digest_paddr, trunc_size);
trace:
	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_decrypt_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);
  crypto_qp_data_t *qpd;
  /* *INDENT-OFF* */
  vec_foreach_index (i, cwm->qp_data)
    {
      u32 enq;

      if (!n_cop_qp[i])
	continue;

      qpd = vec_elt_at_index(cwm->qp_data, i);
      enq = rte_cryptodev_enqueue_burst(qpd->dev_id, qpd->qp_id,
					qpd->cops, n_cop_qp[i]);
      qpd->inflights += enq;

      if (PREDICT_FALSE(enq < n_cop_qp[i]))
	{
	  crypto_free_cop (qpd, &qpd->cops[enq], n_cop_qp[i] - enq);
	  vlib_buffer_free (vm, &qpd->bi[enq], n_cop_qp[i] - enq);

	  vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
				       ESP_DECRYPT_ERROR_ENQ_FAIL,
				       n_cop_qp[i] - enq);
	}
    }
  /* *INDENT-ON* */

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp_decrypt_node) = {
  .function = dpdk_esp_decrypt_node_fn,
  .name = "dpdk-esp-decrypt",
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

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_decrypt_node, dpdk_esp_decrypt_node_fn)

/*
 * Decrypt Post Node
 */

#define foreach_esp_decrypt_post_error	      \
 _(PKTS, "ESP post pkts")

typedef enum {
#define _(sym,str) ESP_DECRYPT_POST_ERROR_##sym,
  foreach_esp_decrypt_post_error
#undef _
  ESP_DECRYPT_POST_N_ERROR,
} esp_decrypt_post_error_t;

static char * esp_decrypt_post_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_decrypt_post_error
#undef _
};

vlib_node_registration_t dpdk_esp_decrypt_post_node;

static u8 * format_esp_decrypt_post_trace (u8 * s, va_list * args)
{
  return s;
}

static uword
dpdk_esp_decrypt_post_node_fn (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  ipsec_sa_t * sa0;
  u32 sa_index0 = ~0;
  ipsec_main_t *im = &ipsec_main;
  dpdk_esp_main_t *em = &dpdk_esp_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  esp_footer_t * f0;
	  u32 bi0, next0, trunc_size, iv_size;
	  vlib_buffer_t * b0 = 0;
	  ip4_header_t *ih4 = 0, *oh4 = 0;
	  ip6_header_t *ih6 = 0, *oh6 = 0;
	  u8 tunnel_mode = 1;
	  u8 transport_ip6 = 0;

	  next0 = ESP_DECRYPT_NEXT_DROP;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sa_index0 = vnet_buffer(b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  to_next[0] = bi0;
	  to_next += 1;

	  if (sa0->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128)
	    trunc_size = 16;
	  else
	    trunc_size = em->esp_integ_algs[sa0->integ_alg].trunc_size;
	  iv_size = em->esp_crypto_algs[sa0->crypto_alg].iv_len;

	  if (sa0->use_anti_replay)
	    {
	      esp_header_t * esp0 = vlib_buffer_get_current (b0);
	      u32 seq;
	      seq = clib_host_to_net_u32(esp0->seq);
	      if (PREDICT_TRUE(sa0->use_esn))
		esp_replay_advance_esn(sa0, seq);
	      else
		esp_replay_advance(sa0, seq);
	    }

	  ih4 = (ip4_header_t *) (b0->data + sizeof(ethernet_header_t));
	  vlib_buffer_advance (b0, sizeof (esp_header_t) + iv_size);

	  b0->current_length -= (trunc_size + 2);
	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  f0 = (esp_footer_t *) ((u8 *) vlib_buffer_get_current (b0) +
				 b0->current_length);
	  b0->current_length -= f0->pad_length;

	  /* transport mode */
	  if (PREDICT_FALSE(!sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      tunnel_mode = 0;

	      if (PREDICT_TRUE((ih4->ip_version_and_header_length & 0xF0) != 0x40))
		{
		  if (PREDICT_TRUE((ih4->ip_version_and_header_length & 0xF0) == 0x60))
		    transport_ip6 = 1;
		  else
		    {
		      clib_warning("next header: 0x%x", f0->next_header);
		      vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
						   ESP_DECRYPT_ERROR_NOT_IP, 1);
		      goto trace;
		    }
		}
	    }

	  if (PREDICT_TRUE (tunnel_mode))
	    {
	      if (PREDICT_TRUE(f0->next_header == IP_PROTOCOL_IP_IN_IP))
		next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
	      else if (f0->next_header == IP_PROTOCOL_IPV6)
		next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
	      else
		{
		  clib_warning("next header: 0x%x", f0->next_header);
		  vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
					       1);
		  goto trace;
		}
	    }
	  /* transport mode */
	  else
	    {
	      if (PREDICT_FALSE(transport_ip6))
		{
		  ih6 = (ip6_header_t *) (b0->data + sizeof(ethernet_header_t));
		  vlib_buffer_advance (b0, -sizeof(ip6_header_t));
		  oh6 = vlib_buffer_get_current (b0);
		  memmove(oh6, ih6, sizeof(ip6_header_t));

		  next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
		  oh6->protocol = f0->next_header;
		  oh6->payload_length =
		      clib_host_to_net_u16 (
			  vlib_buffer_length_in_chain(vm, b0) -
			  sizeof (ip6_header_t));
		}
	      else
		{
		  vlib_buffer_advance (b0, -sizeof(ip4_header_t));
		  oh4 = vlib_buffer_get_current (b0);
		  memmove(oh4, ih4, sizeof(ip4_header_t));

		  next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
		  oh4->ip_version_and_header_length = 0x45;
		  oh4->fragment_id = 0;
		  oh4->flags_and_fragment_offset = 0;
		  oh4->protocol = f0->next_header;
		  oh4->length = clib_host_to_net_u16 (
		      vlib_buffer_length_in_chain (vm, b0));
		  oh4->checksum = ip4_header_checksum (oh4);
		}
	    }

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;

trace:
	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_decrypt_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, dpdk_esp_decrypt_post_node.index,
			       ESP_DECRYPT_POST_ERROR_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp_decrypt_post_node) = {
  .function = dpdk_esp_decrypt_post_node_fn,
  .name = "dpdk-esp-decrypt-post",
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

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_decrypt_post_node, dpdk_esp_decrypt_post_node_fn)
