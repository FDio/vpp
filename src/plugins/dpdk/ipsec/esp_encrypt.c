/*
 * esp_encrypt.c : IPSec ESP encrypt node using DPDK Cryptodev
 *
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <vnet/udp/udp_local.h>
#include <dpdk/buffer.h>
#include <dpdk/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>
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
 _(SEQ_CYCLED, "Sequence number cycled")            \
 _(ENQ_FAIL, "Enqueue encrypt failed (queue full)")     \
 _(DISCARD, "Not enough crypto operations")         \
 _(SESSION, "Failed to get crypto session")         \
 _(NOSUP, "Cipher/Auth not supported")


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

extern vlib_node_registration_t dpdk_esp4_encrypt_node;
extern vlib_node_registration_t dpdk_esp6_encrypt_node;
extern vlib_node_registration_t dpdk_esp4_encrypt_tun_node;
extern vlib_node_registration_t dpdk_esp6_encrypt_tun_node;

typedef struct
{
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  u8 packet_data[64];
} esp_encrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);
  ip4_header_t *ih4 = (ip4_header_t *) t->packet_data;
  u32 indent = format_get_indent (s), offset;

  s = format (s, "cipher %U auth %U\n",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);

  if ((ih4->ip_version_and_header_length & 0xF0) == 0x60)
    {
      s = format (s, "%U%U", format_white_space, indent,
		  format_ip6_header, ih4);
      offset = sizeof (ip6_header_t);
    }
  else
    {
      s = format (s, "%U%U", format_white_space, indent,
		  format_ip4_header, ih4);
      offset = ip4_header_bytes (ih4);
    }

  s = format (s, "\n%U%U", format_white_space, indent,
	      format_esp_header, t->packet_data + offset);

  return s;
}

always_inline uword
dpdk_esp_encrypt_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame, int is_ip6, int is_tun)
{
  u32 n_left_from, *from, *to_next, next_index, thread_index;
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_interface_main_t *vim = &vnm->interface_main;
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
	vlib_node_increment_counter (vm, dpdk_esp6_encrypt_node.index,
				     ESP_ENCRYPT_ERROR_DISCARD, n_left_from);
      else
	vlib_node_increment_counter (vm, dpdk_esp4_encrypt_node.index,
				     ESP_ENCRYPT_ERROR_DISCARD, n_left_from);
      /* Discard whole frame */
      vlib_buffer_free (vm, from, n_left_from);
      return n_left_from;
    }

  next_index = ESP_ENCRYPT_NEXT_DROP;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  clib_error_t *error;
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 sa_index0;
	  ip4_and_esp_header_t *ih0, *oh0 = 0;
	  ip6_and_esp_header_t *ih6_0, *oh6_0 = 0;
	  ip4_and_udp_and_esp_header_t *ouh0 = 0;
	  esp_header_t *esp0;
	  esp_footer_t *f0;
	  u8 next_hdr_type;
	  u32 iv_size;
	  u16 orig_sz;
	  u8 trunc_size;
	  u16 rewrite_len;
	  u16 udp_encap_adv = 0;
	  struct rte_mbuf *mb0;
	  struct rte_crypto_op *op;
	  u16 res_idx;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ih0 = vlib_buffer_get_current (b0);
	  mb0 = rte_mbuf_from_vlib_buffer (b0);

	  /* ih0/ih6_0 */
	  CLIB_PREFETCH (ih0, sizeof (ih6_0[0]), LOAD);
	  /* f0 */
	  CLIB_PREFETCH (vlib_buffer_get_tail (b0), 20, STORE);
	  /* mb0 */
	  CLIB_PREFETCH (mb0, CLIB_CACHE_LINE_BYTES, STORE);

	  if (n_left_from > 1)
	    {
	      bi1 = from[1];
	      b1 = vlib_get_buffer (vm, bi1);

	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (b1->data - CLIB_CACHE_LINE_BYTES,
			     CLIB_CACHE_LINE_BYTES, STORE);
	    }

	  op = ops[0];
	  ops += 1;
	  ASSERT (op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED);

	  dpdk_op_priv_t *priv = crypto_op_get_priv (op);
	  /* store bi in op private */
	  priv->bi = bi0;
	  priv->encrypt = 1;

	  u16 op_len =
	    sizeof (op[0]) + sizeof (op[0].sym[0]) + sizeof (priv[0]);
	  CLIB_PREFETCH (op, op_len, STORE);

	  if (is_tun)
	    {
	      /* we are on a ipsec tunnel's feature arc */
	      vnet_buffer (b0)->ipsec.sad_index =
		sa_index0 = ipsec_tun_protect_get_sa_out
		(vnet_buffer (b0)->ip.adj_index);
	    }
	  else
	    sa_index0 = vnet_buffer (b0)->ipsec.sad_index;

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
						 dpdk_esp6_encrypt_node.index,
						 ESP_ENCRYPT_ERROR_NOSUP, 1);
		  else
		    vlib_node_increment_counter (vm,
						 dpdk_esp4_encrypt_node.index,
						 ESP_ENCRYPT_ERROR_NOSUP, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  goto trace;
		}
	      res = vec_elt_at_index (dcm->resource, res_idx);

	      error = crypto_get_session (&session, sa_index0, res, cwm, 1);
	      if (PREDICT_FALSE (error || !session))
		{
		  if (is_ip6)
		    vlib_node_increment_counter (vm,
						 dpdk_esp6_encrypt_node.index,
						 ESP_ENCRYPT_ERROR_SESSION,
						 1);
		  else
		    vlib_node_increment_counter (vm,
						 dpdk_esp4_encrypt_node.index,
						 ESP_ENCRYPT_ERROR_SESSION,
						 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  goto trace;
		}

	      last_sa_index = sa_index0;
	    }

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      if (is_ip6)
		vlib_node_increment_counter (vm,
					     dpdk_esp6_encrypt_node.index,
					     ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      else
		vlib_node_increment_counter (vm,
					     dpdk_esp4_encrypt_node.index,
					     ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      //TODO: rekey SA
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      goto trace;
	    }

	  orig_sz = b0->current_length;

	  /* TODO multi-seg support - total_length_not_including_first_buffer */
	  vlib_increment_combined_counter
	    (&ipsec_sa_counters, thread_index, sa_index0,
	     1, b0->current_length);

	  /* Update tunnel interface tx counters */
	  if (is_tun)
	    vlib_increment_combined_counter
	      (vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
	       thread_index, vnet_buffer (b0)->sw_if_index[VLIB_TX],
	       1, b0->current_length);

	  res->ops[res->n_ops] = op;
	  res->bi[res->n_ops] = bi0;
	  res->n_ops += 1;

	  dpdk_gcm_cnt_blk *icb = &priv->cb;

	  crypto_set_icb (icb, sa0->salt, sa0->seq, sa0->seq_hi);

	  iv_size = cipher_alg->iv_len;
	  trunc_size = auth_alg->trunc_size;

	  /* if UDP encapsulation is used adjust the address of the IP header */
	  if (ipsec_sa_is_set_UDP_ENCAP (sa0) && !is_ip6)
	    udp_encap_adv = sizeof (udp_header_t);

	  if (ipsec_sa_is_set_IS_TUNNEL (sa0))
	    {
	      rewrite_len = 0;
	      if (!ipsec_sa_is_set_IS_TUNNEL_V6 (sa0))	/* ip4 */
		{
		  /* in tunnel mode send it back to FIB */
		  priv->next = DPDK_CRYPTO_INPUT_NEXT_IP4_LOOKUP;
		  u8 adv = sizeof (ip4_header_t) + udp_encap_adv +
		    sizeof (esp_header_t) + iv_size;
		  vlib_buffer_advance (b0, -adv);
		  oh0 = vlib_buffer_get_current (b0);
		  ouh0 = vlib_buffer_get_current (b0);
		  next_hdr_type = (is_ip6 ?
				   IP_PROTOCOL_IPV6 : IP_PROTOCOL_IP_IN_IP);
		  /*
		   * oh0->ip4.ip_version_and_header_length = 0x45;
		   * oh0->ip4.tos = ih0->ip4.tos;
		   * oh0->ip4.fragment_id = 0;
		   * oh0->ip4.flags_and_fragment_offset = 0;
		   */
		  oh0->ip4.checksum_data_64[0] =
		    clib_host_to_net_u64 (0x45ULL << 56);
		  /*
		   * oh0->ip4.ttl = 254;
		   * oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
		   */
		  oh0->ip4.checksum_data_32[2] =
		    clib_host_to_net_u32 (0xfe320000);

		  oh0->ip4.src_address.as_u32 =
		    sa0->tunnel_src_addr.ip4.as_u32;
		  oh0->ip4.dst_address.as_u32 =
		    sa0->tunnel_dst_addr.ip4.as_u32;

		  if (ipsec_sa_is_set_UDP_ENCAP (sa0))
		    {
		      oh0->ip4.protocol = IP_PROTOCOL_UDP;
		      esp0 = &ouh0->esp;
		    }
		  else
		    esp0 = &oh0->esp;
		  esp0->spi = clib_host_to_net_u32 (sa0->spi);
		  esp0->seq = clib_host_to_net_u32 (sa0->seq);
		}
	      else
		{
		  /* ip6 */
		  /* in tunnel mode send it back to FIB */
		  priv->next = DPDK_CRYPTO_INPUT_NEXT_IP6_LOOKUP;

		  u8 adv =
		    sizeof (ip6_header_t) + sizeof (esp_header_t) + iv_size;
		  vlib_buffer_advance (b0, -adv);
		  ih6_0 = (ip6_and_esp_header_t *) ih0;
		  oh6_0 = vlib_buffer_get_current (b0);

		  next_hdr_type = (is_ip6 ?
				   IP_PROTOCOL_IPV6 : IP_PROTOCOL_IP_IN_IP);

		  oh6_0->ip6.ip_version_traffic_class_and_flow_label =
		    ih6_0->ip6.ip_version_traffic_class_and_flow_label;

		  oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
		  oh6_0->ip6.hop_limit = 254;
		  oh6_0->ip6.src_address.as_u64[0] =
		    sa0->tunnel_src_addr.ip6.as_u64[0];
		  oh6_0->ip6.src_address.as_u64[1] =
		    sa0->tunnel_src_addr.ip6.as_u64[1];
		  oh6_0->ip6.dst_address.as_u64[0] =
		    sa0->tunnel_dst_addr.ip6.as_u64[0];
		  oh6_0->ip6.dst_address.as_u64[1] =
		    sa0->tunnel_dst_addr.ip6.as_u64[1];
		  esp0 = &oh6_0->esp;
		  oh6_0->esp.spi = clib_host_to_net_u32 (sa0->spi);
		  oh6_0->esp.seq = clib_host_to_net_u32 (sa0->seq);
		}

	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else			/* transport mode */
	    {
	      if (is_tun)
		{
		  rewrite_len = 0;
		  priv->next = DPDK_CRYPTO_INPUT_NEXT_MIDCHAIN;
		}
	      else
		{
		  priv->next = DPDK_CRYPTO_INPUT_NEXT_INTERFACE_OUTPUT;
		  rewrite_len = vnet_buffer (b0)->ip.save_rewrite_length;
		}
	      u16 adv = sizeof (esp_header_t) + iv_size + udp_encap_adv;
	      vlib_buffer_advance (b0, -adv - rewrite_len);
	      u8 *src = ((u8 *) ih0) - rewrite_len;
	      u8 *dst = vlib_buffer_get_current (b0);
	      oh0 = vlib_buffer_get_current (b0) + rewrite_len;
	      ouh0 = vlib_buffer_get_current (b0) + rewrite_len;

	      if (is_ip6)
		{
		  orig_sz -= sizeof (ip6_header_t);
		  ih6_0 = (ip6_and_esp_header_t *) ih0;
		  next_hdr_type = ih6_0->ip6.protocol;
		  memmove (dst, src, rewrite_len + sizeof (ip6_header_t));
		  oh6_0 = (ip6_and_esp_header_t *) oh0;
		  oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
		  esp0 = &oh6_0->esp;
		}
	      else		/* ipv4 */
		{
		  u16 ip_size = ip4_header_bytes (&ih0->ip4);
		  orig_sz -= ip_size;
		  next_hdr_type = ih0->ip4.protocol;
		  memmove (dst, src, rewrite_len + ip_size);
		  oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
		  esp0 = (esp_header_t *) (((u8 *) oh0) + ip_size);
		  if (ipsec_sa_is_set_UDP_ENCAP (sa0))
		    {
		      oh0->ip4.protocol = IP_PROTOCOL_UDP;
		      esp0 = (esp_header_t *)
			(((u8 *) oh0) + ip_size + udp_encap_adv);
		    }
		  else
		    {
		      oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
		      esp0 = (esp_header_t *) (((u8 *) oh0) + ip_size);
		    }
		}
	      esp0->spi = clib_host_to_net_u32 (sa0->spi);
	      esp0->seq = clib_host_to_net_u32 (sa0->seq);
	    }

	  if (ipsec_sa_is_set_UDP_ENCAP (sa0) && ouh0)
	    {
	      ouh0->udp.src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
	      ouh0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
	      ouh0->udp.checksum = 0;
	    }
	  ASSERT (is_pow2 (cipher_alg->boundary));
	  u16 mask = cipher_alg->boundary - 1;
	  u16 pad_payload_len = ((orig_sz + 2) + mask) & ~mask;
	  u8 pad_bytes = pad_payload_len - 2 - orig_sz;

	  u8 *padding =
	    vlib_buffer_put_uninit (b0, pad_bytes + 2 + trunc_size);

	  /* The extra pad bytes would be overwritten by the digest */
	  if (pad_bytes)
	    clib_memcpy_fast (padding, pad_data, 16);

	  f0 = (esp_footer_t *) (padding + pad_bytes);
	  f0->pad_length = pad_bytes;
	  f0->next_header = next_hdr_type;

	  if (oh6_0)
	    {
	      u16 len = b0->current_length - sizeof (ip6_header_t);
	      oh6_0->ip6.payload_length =
		clib_host_to_net_u16 (len - rewrite_len);
	    }
	  else if (oh0)
	    {
	      oh0->ip4.length =
		clib_host_to_net_u16 (b0->current_length - rewrite_len);
	      oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
	      if (ipsec_sa_is_set_UDP_ENCAP (sa0) && ouh0)
		{
		  ouh0->udp.length =
		    clib_host_to_net_u16 (clib_net_to_host_u16
					  (ouh0->ip4.length) -
					  ip4_header_bytes (&ouh0->ip4));
		}
	    }
	  else			/* should never happen */
	    clib_warning ("No outer header found for ESP packet");

	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  /* mbuf packet starts at ESP header */
	  mb0->data_len = vlib_buffer_get_tail (b0) - ((u8 *) esp0);
	  mb0->pkt_len = vlib_buffer_get_tail (b0) - ((u8 *) esp0);
	  mb0->data_off = ((void *) esp0) - mb0->buf_addr;

	  u32 cipher_off, cipher_len, auth_len = 0;
	  u32 *aad = NULL;

	  u8 *digest = vlib_buffer_get_tail (b0) - trunc_size;
	  u64 digest_paddr =
	    mb0->buf_physaddr + digest - ((u8 *) mb0->buf_addr);

	  if (!is_aead && (cipher_alg->alg == RTE_CRYPTO_CIPHER_AES_CBC ||
			   cipher_alg->alg == RTE_CRYPTO_CIPHER_NULL))
	    {
	      cipher_off = sizeof (esp_header_t);
	      cipher_len = iv_size + pad_payload_len;
	    }
	  else			/* CTR/GCM */
	    {
	      u32 *esp_iv = (u32 *) (esp0 + 1);
	      esp_iv[0] = sa0->seq;
	      esp_iv[1] = sa0->seq_hi;

	      cipher_off = sizeof (esp_header_t) + iv_size;
	      cipher_len = pad_payload_len;
	    }

	  if (is_aead)
	    {
	      aad = (u32 *) priv->aad;
	      aad[0] = esp0->spi;

	      /* aad[3] should always be 0 */
	      if (PREDICT_FALSE (ipsec_sa_is_set_USE_ESN (sa0)))
		{
		  aad[1] = clib_host_to_net_u32 (sa0->seq_hi);
		  aad[2] = esp0->seq;
		}
	      else
		{
		  aad[1] = esp0->seq;
		  aad[2] = 0;
		}
	    }
	  else
	    {
	      auth_len =
		vlib_buffer_get_tail (b0) - ((u8 *) esp0) - trunc_size;
	      if (ipsec_sa_is_set_USE_ESN (sa0))
		{
		  u32 *_digest = (u32 *) digest;
		  _digest[0] = clib_host_to_net_u32 (sa0->seq_hi);
		  auth_len += 4;
		}
	    }

	  crypto_op_setup (is_aead, mb0, op, session, cipher_off, cipher_len,
			   0, auth_len, (u8 *) aad, digest, digest_paddr);

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	      u8 *p = vlib_buffer_get_current (b0);
	      if (!ipsec_sa_is_set_IS_TUNNEL (sa0) && !is_tun)
		p += vnet_buffer (b0)->ip.save_rewrite_length;
	      clib_memcpy_fast (tr->packet_data, p, sizeof (tr->packet_data));
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  if (is_ip6)
    {
      vlib_node_increment_counter (vm,
				   (is_tun ?
				    dpdk_esp6_encrypt_tun_node.index :
				    dpdk_esp6_encrypt_node.index),
				   ESP_ENCRYPT_ERROR_RX_PKTS,
				   from_frame->n_vectors);

      crypto_enqueue_ops (vm, cwm, dpdk_esp6_encrypt_node.index,
			  ESP_ENCRYPT_ERROR_ENQ_FAIL, numa, 1 /* encrypt */ );
    }
  else
    {
      vlib_node_increment_counter (vm,
				   (is_tun ?
				    dpdk_esp4_encrypt_tun_node.index :
				    dpdk_esp4_encrypt_node.index),
				   ESP_ENCRYPT_ERROR_RX_PKTS,
				   from_frame->n_vectors);

      crypto_enqueue_ops (vm, cwm, dpdk_esp4_encrypt_node.index,
			  ESP_ENCRYPT_ERROR_ENQ_FAIL, numa, 1 /* encrypt */ );
    }

  crypto_free_ops (numa, ops, cwm->ops + from_frame->n_vectors - ops);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (dpdk_esp4_encrypt_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return dpdk_esp_encrypt_inline (vm, node, from_frame, 0 /*is_ip6 */ , 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp4_encrypt_node) = {
  .name = "dpdk-esp4-encrypt",
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

VLIB_NODE_FN (dpdk_esp6_encrypt_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return dpdk_esp_encrypt_inline (vm, node, from_frame, 1 /*is_ip6 */ , 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp6_encrypt_node) = {
  .name = "dpdk-esp6-encrypt",
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

VLIB_NODE_FN (dpdk_esp4_encrypt_tun_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * from_frame)
{
  return dpdk_esp_encrypt_inline (vm, node, from_frame, 0 /*is_ip6 */ , 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp4_encrypt_tun_node) = {
  .name = "dpdk-esp4-encrypt-tun",
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

VLIB_NODE_FN (dpdk_esp6_encrypt_tun_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * from_frame)
{
  return dpdk_esp_encrypt_inline (vm, node, from_frame, 1 /*is_ip6 */ , 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp6_encrypt_tun_node) = {
  .name = "dpdk-esp6-encrypt-tun",
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
