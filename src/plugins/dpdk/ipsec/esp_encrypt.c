/*
 * esp_encrypt.c : IPSec ESP encrypt node using DPDK Cryptodev
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
 _(SEQ_CYCLED, "sequence number cycled")            \
 _(ENQ_FAIL, "Enqueue failed (buffer full)")        \
 _(NO_CRYPTODEV, "Cryptodev not configured")


typedef enum
{
#define _(sym,str) ESP_ENCRYPT_ERROR_##sym,
  foreach_esp_encrypt_error
#undef _
    ESP_ENCRYPT_N_ERROR,
} esp_encrypt_error_t;

static char *esp_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_encrypt_error
#undef _
};

vlib_node_registration_t dpdk_esp_encrypt_node;

typedef struct
{
  u32 spi;
  u32 seq;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_encrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);

  s = format (s, "esp: spi %u seq %u crypto %U integrity %U",
	      t->spi, t->seq,
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);
  return s;
}

static uword
dpdk_esp_encrypt_node_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next, next_index;
  ipsec_main_t *im = &ipsec_main;
  u32 thread_index = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  dpdk_esp_main_t *em = &dpdk_esp_main;
  u32 i;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  crypto_worker_main_t *cwm =
    vec_elt_at_index (dcm->workers_main, thread_index);
  u32 n_qps = vec_len (cwm->qp_data);
  struct rte_crypto_op **cops_to_enq[n_qps];
  u32 n_cop_qp[n_qps], *bi_to_enq[n_qps];

  for (i = 0; i < n_qps; i++)
    {
      bi_to_enq[i] = cwm->qp_data[i].bi;
      cops_to_enq[i] = cwm->qp_data[i].cops;
    }

  memset (n_cop_qp, 0, n_qps * sizeof (u32));

  crypto_alloc_cops ();

  next_index = ESP_ENCRYPT_NEXT_DROP;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0 = 0;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ip4_and_esp_header_t *ih0, *oh0 = 0;
	  ip6_and_esp_header_t *ih6_0, *oh6_0 = 0;
	  struct rte_mbuf *mb0 = 0;
	  esp_footer_t *f0;
	  u8 is_ipv6;
	  u8 ip_hdr_size;
	  u8 next_hdr_type;
	  u8 transport_mode = 0;
	  const int BLOCK_SIZE = 16;
	  u32 iv_size;
	  u16 orig_sz;
	  u8 trunc_size;
	  crypto_sa_session_t *sa_sess;
	  void *sess;
	  struct rte_crypto_op *cop = 0;
	  u16 qp_index;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index,
					   ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      //TODO: rekey SA
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      goto trace;
	    }

	  sa0->total_data_size += b0->current_length;

	  sa_sess = pool_elt_at_index (cwm->sa_sess_d[1], sa_index0);
	  if (PREDICT_FALSE (!sa_sess->sess))
	    {
	      int ret = create_sym_sess (sa0, sa_sess, 1);

	      if (PREDICT_FALSE (ret))
		{
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  goto trace;
		}
	    }

	  qp_index = sa_sess->qp_index;
	  sess = sa_sess->sess;

	  ASSERT (vec_len (vec_elt (cwm->qp_data, qp_index).free_cops) > 0);
	  cop = vec_pop (vec_elt (cwm->qp_data, qp_index).free_cops);
	  ASSERT (cop->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED);

	  cops_to_enq[qp_index][0] = cop;
	  cops_to_enq[qp_index] += 1;
	  n_cop_qp[qp_index] += 1;
	  bi_to_enq[qp_index][0] = bi0;
	  bi_to_enq[qp_index] += 1;

	  ssize_t adv;
	  iv_size = em->esp_crypto_algs[sa0->crypto_alg].iv_len;
	  if (sa0->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128)
	    trunc_size = 16;
	  else
	    trunc_size = em->esp_integ_algs[sa0->integ_alg].trunc_size;

	  ih0 = vlib_buffer_get_current (b0);
	  orig_sz = b0->current_length;
	  is_ipv6 = (ih0->ip4.ip_version_and_header_length & 0xF0) == 0x60;
	  /* is ipv6 */
	  if (PREDICT_TRUE (sa0->is_tunnel))
	    {
	      if (PREDICT_TRUE (!is_ipv6))
		adv = -sizeof (ip4_and_esp_header_t);
	      else
		adv = -sizeof (ip6_and_esp_header_t);
	    }
	  else
	    {
	      adv = -sizeof (esp_header_t);
	      if (PREDICT_TRUE (!is_ipv6))
		orig_sz -= sizeof (ip4_header_t);
	      else
		orig_sz -= sizeof (ip6_header_t);
	    }

	  /*transport mode save the eth header before it is overwritten */
	  if (PREDICT_FALSE (!sa0->is_tunnel))
	    {
	      ethernet_header_t *ieh0 = (ethernet_header_t *)
		((u8 *) vlib_buffer_get_current (b0) -
		 sizeof (ethernet_header_t));
	      ethernet_header_t *oeh0 =
		(ethernet_header_t *) ((u8 *) ieh0 + (adv - iv_size));
	      clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	    }

	  vlib_buffer_advance (b0, adv - iv_size);

	  /* XXX IP6/ip4 and IP4/IP6 not supported, only IP4/IP4 and IP6/IP6 */

	  /* is ipv6 */
	  if (PREDICT_FALSE (is_ipv6))
	    {
	      ih6_0 = (ip6_and_esp_header_t *) ih0;
	      ip_hdr_size = sizeof (ip6_header_t);
	      oh6_0 = vlib_buffer_get_current (b0);

	      if (PREDICT_TRUE (sa0->is_tunnel))
		{
		  next_hdr_type = IP_PROTOCOL_IPV6;
		  oh6_0->ip6.ip_version_traffic_class_and_flow_label =
		    ih6_0->ip6.ip_version_traffic_class_and_flow_label;
		}
	      else
		{
		  next_hdr_type = ih6_0->ip6.protocol;
		  memmove (oh6_0, ih6_0, sizeof (ip6_header_t));
		}

	      oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
	      oh6_0->ip6.hop_limit = 254;
	      oh6_0->esp.spi = clib_net_to_host_u32 (sa0->spi);
	      oh6_0->esp.seq = clib_net_to_host_u32 (sa0->seq);
	    }
	  else
	    {
	      ip_hdr_size = sizeof (ip4_header_t);
	      oh0 = vlib_buffer_get_current (b0);

	      if (PREDICT_TRUE (sa0->is_tunnel))
		{
		  next_hdr_type = IP_PROTOCOL_IP_IN_IP;
		  oh0->ip4.tos = ih0->ip4.tos;
		}
	      else
		{
		  next_hdr_type = ih0->ip4.protocol;
		  memmove (oh0, ih0, sizeof (ip4_header_t));
		}

	      oh0->ip4.ip_version_and_header_length = 0x45;
	      oh0->ip4.fragment_id = 0;
	      oh0->ip4.flags_and_fragment_offset = 0;
	      oh0->ip4.ttl = 254;
	      oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
	      oh0->esp.spi = clib_net_to_host_u32 (sa0->spi);
	      oh0->esp.seq = clib_net_to_host_u32 (sa0->seq);
	    }

	  if (PREDICT_TRUE
	      (!is_ipv6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      oh0->ip4.src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	      oh0->ip4.dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	      /* in tunnel mode send it back to FIB */
	      next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
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

	      /* in tunnel mode send it back to FIB */
	      next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else
	    {
	      next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	      transport_mode = 1;
	    }

	  int blocks = 1 + (orig_sz + 1) / BLOCK_SIZE;

	  /* pad packet in input buffer */
	  u8 pad_bytes = BLOCK_SIZE * blocks - 2 - orig_sz;
	  u8 i;
	  u8 *padding = vlib_buffer_get_current (b0) + b0->current_length;

	  for (i = 0; i < pad_bytes; ++i)
	    padding[i] = i + 1;

	  f0 = vlib_buffer_get_current (b0) + b0->current_length + pad_bytes;
	  f0->pad_length = pad_bytes;
	  f0->next_header = next_hdr_type;
	  b0->current_length += pad_bytes + 2 + trunc_size;

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  struct rte_crypto_sym_op *sym_cop;
	  sym_cop = (struct rte_crypto_sym_op *) (cop + 1);

	  dpdk_cop_priv_t *priv = (dpdk_cop_priv_t *) (sym_cop + 1);

	  vnet_buffer (b0)->unused[0] = next0;

	  mb0 = rte_mbuf_from_vlib_buffer (b0);
	  mb0->data_len = b0->current_length;
	  mb0->pkt_len = b0->current_length;
	  mb0->data_off = RTE_PKTMBUF_HEADROOM + b0->current_data;

	  dpdk_gcm_cnt_blk *icb = &priv->cb;

	  crypto_set_icb (icb, sa0->salt, sa0->seq, sa0->seq_hi);

	  u8 is_aead = sa0->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128;
	  u32 cipher_off, cipher_len;
	  u32 auth_off = 0, auth_len = 0, aad_size = 0;
	  u8 *aad = NULL, *digest = NULL;

	  if (is_aead)
	    {
	      u32 *esp_iv =
		(u32 *) (b0->data + b0->current_data + ip_hdr_size +
			 sizeof (esp_header_t));
	      esp_iv[0] = sa0->seq;
	      esp_iv[1] = sa0->seq_hi;

	      cipher_off = ip_hdr_size + sizeof (esp_header_t) + iv_size;
	      cipher_len = BLOCK_SIZE * blocks;
	      iv_size = 16;	/* GCM IV size, not ESP IV size */

	      aad = priv->aad;
	      clib_memcpy (aad, vlib_buffer_get_current (b0) + ip_hdr_size,
			   8);
	      aad_size = 8;
	      if (PREDICT_FALSE (sa0->use_esn))
		{
		  *((u32 *) & aad[8]) = sa0->seq_hi;
		  aad_size = 12;
		}

	      digest =
		vlib_buffer_get_current (b0) + b0->current_length -
		trunc_size;
	    }
	  else
	    {
	      cipher_off = ip_hdr_size + sizeof (esp_header_t);
	      cipher_len = BLOCK_SIZE * blocks + iv_size;

	      auth_off = ip_hdr_size;
	      auth_len = b0->current_length - ip_hdr_size - trunc_size;

	      digest =
		vlib_buffer_get_current (b0) + b0->current_length -
		trunc_size;

	      if (PREDICT_FALSE (sa0->use_esn))
		{
		  *((u32 *) digest) = sa0->seq_hi;
		  auth_len += sizeof (sa0->seq_hi);
		}
	    }

	  crypto_op_setup (is_aead, mb0, cop, sess,
			   cipher_off, cipher_len, (u8 *) icb, iv_size,
			   auth_off, auth_len, aad, aad_size,
			   digest, 0, trunc_size);

	  if (PREDICT_FALSE (is_ipv6))
	    {
	      oh6_0->ip6.payload_length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
				      sizeof (ip6_header_t));
	    }
	  else
	    {
	      oh0->ip4.length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	      oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
	    }

	  if (transport_mode)
	    vlib_buffer_advance (b0, -sizeof (ethernet_header_t));

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq - 1;
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
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

          vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index,
				       ESP_ENCRYPT_ERROR_ENQ_FAIL,
				       n_cop_qp[i] - enq);
        }
    }
  /* *INDENT-ON* */

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp_encrypt_node) = {
  .function = dpdk_esp_encrypt_node_fn,
  .name = "dpdk-esp-encrypt",
  .flags = VLIB_NODE_FLAG_IS_OUTPUT,
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .n_errors = ARRAY_LEN (esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
  .n_next_nodes = 1,
  .next_nodes =
    {
      [ESP_ENCRYPT_NEXT_DROP] = "error-drop",
    }
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_encrypt_node, dpdk_esp_encrypt_node_fn)
/*
 * ESP Encrypt Post Node
 */
#define foreach_esp_encrypt_post_error              \
 _(PKTS, "ESP post pkts")
     typedef enum
     {
#define _(sym,str) ESP_ENCRYPT_POST_ERROR_##sym,
       foreach_esp_encrypt_post_error
#undef _
	 ESP_ENCRYPT_POST_N_ERROR,
     } esp_encrypt_post_error_t;

     static char *esp_encrypt_post_error_strings[] = {
#define _(sym,string) string,
       foreach_esp_encrypt_post_error
#undef _
     };

vlib_node_registration_t dpdk_esp_encrypt_post_node;

static u8 *
format_esp_encrypt_post_trace (u8 * s, va_list * args)
{
  return s;
}

static uword
dpdk_esp_encrypt_post_node_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0 = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  to_next[0] = bi0;
	  to_next += 1;

	  next0 = vnet_buffer (b0)->unused[0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, dpdk_esp_encrypt_post_node.index,
			       ESP_ENCRYPT_POST_ERROR_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp_encrypt_post_node) = {
  .function = dpdk_esp_encrypt_post_node_fn,
  .name = "dpdk-esp-encrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (esp_encrypt_post_error_strings),
  .error_strings = esp_encrypt_post_error_strings,
  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes =
    {
#define _(s,n) [ESP_ENCRYPT_NEXT_##s] = n,
      foreach_esp_encrypt_next
#undef _
    }
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_encrypt_post_node,
			      dpdk_esp_encrypt_post_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
