/*
 * dpdk_esp_encrypt.c : IPSec ESP encrypt node using DPDK Cryptodev
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
#include <vnet/ipsec/dpdk_ipsec.h>
#include <vnet/ipsec/esp.h>

#define ESP_SEQ_MAX (4294967295UL)

#define foreach_esp_encrypt_next                   \
_(DROP, "error-drop")                              \
_(IP4_INPUT, "ip4-input")                          \
_(IP6_INPUT, "ip6-input")                          \
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ESP_ENCRYPT_NEXT_##v,
typedef enum {
  foreach_esp_encrypt_next
#undef _
  ESP_ENCRYPT_N_NEXT,
} esp_encrypt_next_t;

#define foreach_esp_encrypt_error                   \
 _(RX_PKTS, "ESP pkts received")                    \
 _(NO_BUFFER, "No buffer (packet dropped)")         \
 _(DECRYPTION_FAILED, "ESP encryption failed")      \
 _(SEQ_CYCLED, "sequence number cycled")


typedef enum {
#define _(sym,str) ESP_ENCRYPT_ERROR_##sym,
  foreach_esp_encrypt_error
#undef _
  ESP_ENCRYPT_N_ERROR,
} esp_encrypt_error_t;

static char * esp_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_encrypt_error
#undef _
};

vlib_node_registration_t dpdk_esp_encrypt_node;

typedef struct {
  u32 spi;
  u32 seq;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_encrypt_trace_t;

/* packet trace format function */
static u8 * format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t * t = va_arg (*args, esp_encrypt_trace_t *);

  s = format (s, "esp: spi %u seq %u crypto %U integrity %U",
              t->spi, t->seq,
              format_ipsec_crypto_alg, t->crypto_alg,
              format_ipsec_integ_alg, t->integ_alg);
  return s;
}

/* TODO seq increment should be atomic for multiple-worker support */
always_inline int
esp_seq_advance (ipsec_sa_t * sa)
{
  if (PREDICT_TRUE(sa->use_esn))
    {
      if (PREDICT_FALSE(sa->seq == ESP_SEQ_MAX))
        {
          if (PREDICT_FALSE(sa->use_anti_replay && sa->seq_hi == ESP_SEQ_MAX))
            return 1;
          sa->seq_hi++;
        }
      sa->seq++;
    }
  else
    {
      if (PREDICT_FALSE(sa->use_anti_replay && sa->seq == ESP_SEQ_MAX))
        return 1;
      sa->seq++;
    }

  return 0;
}

static uword
dpdk_esp_encrypt_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame)
{
  esp_main_t * em = &esp_main;
  dpdk_crypto_main_t * dcm = &dpdk_crypto_main;
  u32 n_left_from, *from;
  ipsec_main_t *im = &ipsec_main;
  u32 cpu_index = os_get_cpu_number();
  esp_main_per_thread_data_t * ptd = &em->per_thread_data[cpu_index];
  ipsec_lcore_main_t *lcore_main = dcm->lcores_main[cpu_index];
  const u32 n_qps = lcore_main->n_qps;
  u32 n_cop_qp[n_qps];
  struct rte_crypto_op *cops_to_enq_cache[n_qps][VLIB_FRAME_SIZE];
  struct rte_crypto_op **cops_to_enq[n_qps];
  u32 i;

  for (i = 0; i < n_qps; i++)
    cops_to_enq[i] = cops_to_enq_cache[i];

  memset(n_cop_qp, 0, n_qps * sizeof(u32));

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  ipsec_alloc_cops();

  while (n_left_from > 0)
    {
      u32 bi0, next0;
      vlib_buffer_t * b0 = 0;
      u32 sa_index0;
      ipsec_sa_t * sa0;
      ip4_and_esp_header_t * ih0, * oh0 = 0;
      ip6_and_esp_header_t * ih6_0, * oh6_0 = 0;
      struct rte_mbuf * mb0 = 0;
      esp_footer_t *f0;
      u8 is_ipv6;
      u8 ip_hdr_size;
      u8 next_hdr_type;
      const int BLOCK_SIZE = 16;
      const int IV_SIZE = 16;
      u16 orig_sz;
      esp_sa_session_t *sa_sess;
      void *sess;
      uword last_cop;
      struct rte_crypto_op * cop = 0, **cops;
      u16 qp_index;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      next0 = ESP_ENCRYPT_NEXT_DROP;

      b0 = vlib_get_buffer (vm, bi0);
      sa_index0 = vnet_buffer(b0)->output_features.ipsec_sad_index;
      sa0 = pool_elt_at_index(im->sad, sa_index0);

      if (PREDICT_FALSE(esp_seq_advance(sa0)))
	{
	  clib_warning("sequence number counter has cycled SPI %u", sa0->spi);
	  vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index,
				       ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	  //TODO: rekey SA
	  goto trace;
	}

      sa_sess = pool_elt_at_index(ptd->sa_sess_d[1], sa_index0);
      if (PREDICT_FALSE(!sa_sess->sess))
	{
	  int ret = create_sym_sess(sa0, sa_sess, 1);
	  ASSERT(ret == 0);
	}

      qp_index = sa_sess->qp_index;
      sess = sa_sess->sess;
      cops = lcore_main->qp_data[qp_index].cops;

      /* grab cop */
      last_cop = vec_len(cops) - 1;
      cop = cops[last_cop];
      _vec_len (cops) = last_cop;

      cops_to_enq[qp_index][0] = cop;
      cops_to_enq[qp_index] += 1;
      n_cop_qp[qp_index] += 1;

      ssize_t adv;
      /* is ipv6 */
      if (PREDICT_TRUE(sa0->is_tunnel && !sa0->is_tunnel_ip6))
	adv = -sizeof(ip4_and_esp_header_t);
      else if(sa0->is_tunnel && sa0->is_tunnel_ip6)
	adv = -sizeof(ip6_and_esp_header_t);
      else
	{
	  clib_warning("only tunnel mode supported SPI %u", sa0->spi);
	  vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index,
				       ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	  bi0 = bi0;
	  goto trace;
	}
      /* XXX in-place encryption, only tunnel */
      /* TODO check enough headroom space? */
      orig_sz = b0->current_length;
      vlib_buffer_advance(b0, adv - IV_SIZE);

      ih0 = vlib_buffer_get_current (b0);

      /* XXX IP6/ip4 and IP4/IP6 not supported, only IP4/IP4 and IP6/IP6 */

      /* is ipv6 */
      if (PREDICT_FALSE((ih0->ip4.ip_version_and_header_length & 0xF0 ) == 0x60))
	{
	  is_ipv6 = 1;
	  ih6_0 = (ip6_and_esp_header_t *)ih0;
	  ip_hdr_size = sizeof(ip6_header_t);
	  next_hdr_type = IP_PROTOCOL_IPV6;
	  oh6_0 = vlib_buffer_get_current (b0);

	  oh6_0->ip6.ip_version_traffic_class_and_flow_label =
	      ih6_0->ip6.ip_version_traffic_class_and_flow_label;
	  oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
	  oh6_0->ip6.hop_limit = 254;
	  oh6_0->esp.spi = clib_net_to_host_u32(sa0->spi);
	  oh6_0->esp.seq = clib_net_to_host_u32(sa0->seq);
	}
      else
	{
	  is_ipv6 = 0;
	  ip_hdr_size = sizeof(ip4_header_t);
	  next_hdr_type = IP_PROTOCOL_IP_IN_IP;
	  oh0 = vlib_buffer_get_current (b0);

	  oh0->ip4.ip_version_and_header_length = 0x45;
	  oh0->ip4.tos = ih0->ip4.tos;
	  oh0->ip4.fragment_id = 0;
	  oh0->ip4.flags_and_fragment_offset = 0;
	  oh0->ip4.ttl = 254;
	  oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
	  oh0->esp.spi = clib_net_to_host_u32(sa0->spi);
	  oh0->esp.seq = clib_net_to_host_u32(sa0->seq);
	}

      if (PREDICT_TRUE(sa0->is_tunnel && !sa0->is_tunnel_ip6))
	{
	  oh0->ip4.src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	  oh0->ip4.dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	  /* in tunnel mode send it back to FIB */
	  next0 = ESP_ENCRYPT_NEXT_IP4_INPUT;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;
	}
      else if(sa0->is_tunnel && sa0->is_tunnel_ip6)
	{
	  oh6_0->ip6.src_address.as_u64[0] = sa0->tunnel_src_addr.ip6.as_u64[0];
	  oh6_0->ip6.src_address.as_u64[1] = sa0->tunnel_src_addr.ip6.as_u64[1];
	  oh6_0->ip6.dst_address.as_u64[0] = sa0->tunnel_dst_addr.ip6.as_u64[0];
	  oh6_0->ip6.dst_address.as_u64[1] = sa0->tunnel_dst_addr.ip6.as_u64[1];

	  /* in tunnel mode send it back to FIB */
	  next0 = ESP_ENCRYPT_NEXT_IP6_INPUT;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;
	}
      else
	{
						    /* FIXME - Transport mode currently unsupported */
	  next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
							      vnet_buffer (b0)->sw_if_index[VLIB_TX];
	}

      ASSERT(sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);
      ASSERT(sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE);

      int blocks = 1 + (orig_sz + 1) / BLOCK_SIZE;

      /* pad packet in input buffer */
      u8 pad_bytes = BLOCK_SIZE * blocks - 2 - orig_sz;
      u8 i;
      u8 * padding = vlib_buffer_get_current (b0) + b0->current_length;

      for (i = 0; i < pad_bytes; ++i)
	      {
		      padding[i] = i + 1;
	      }
      f0 = vlib_buffer_get_current (b0) + b0->current_length + pad_bytes;
      f0->pad_length = pad_bytes;
      f0->next_header = next_hdr_type;
      b0->current_length += pad_bytes + 2 +
	  em->esp_integ_algs[sa0->integ_alg].trunc_size;

      vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	      vnet_buffer (b0)->sw_if_index[VLIB_RX];
      b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;

      struct rte_crypto_sym_op *sym_cop;
      sym_cop = (struct rte_crypto_sym_op *)(cop + 1);

      dpdk_cop_priv_t * priv = (dpdk_cop_priv_t *)(sym_cop + 1);
      /* FIXME */
      vnet_buffer(b0)->output_features.unused[0] = next0;
      priv->iv[0] = sa0->seq;
      priv->iv[1] = sa0->seq_hi;

      mb0 = rte_mbuf_from_vlib_buffer(b0);
      mb0->data_len = b0->current_length;
      mb0->pkt_len = b0->current_length;
      mb0->data_off = RTE_PKTMBUF_HEADROOM + b0->current_data;

      rte_crypto_op_attach_sym_session(cop, sess);

      sym_cop->m_src = mb0;
      /* XXX We do one extra encrypto to generate IV */
      sym_cop->cipher.data.offset = ip_hdr_size + sizeof(esp_header_t);
      sym_cop->cipher.data.length = BLOCK_SIZE * blocks + IV_SIZE;

      sym_cop->cipher.iv.data = (u8 *)priv->iv;
      sym_cop->cipher.iv.phys_addr = cop->phys_addr +
		      (uintptr_t)priv->iv - (uintptr_t)cop;
      sym_cop->cipher.iv.length = IV_SIZE;

      ASSERT(sa0->integ_alg < IPSEC_INTEG_N_ALG);
      ASSERT(sa0->integ_alg != IPSEC_INTEG_ALG_NONE);

      /* FIXME ESN */

      sym_cop->auth.data.offset = ip_hdr_size;
      sym_cop->auth.data.length = b0->current_length - ip_hdr_size -
		      em->esp_integ_algs[sa0->integ_alg].trunc_size;

      sym_cop->auth.digest.data = vlib_buffer_get_current(b0) +
		      b0->current_length -
		      em->esp_integ_algs[sa0->integ_alg].trunc_size;
      sym_cop->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(mb0,
		      b0->current_length -
		      em->esp_integ_algs[sa0->integ_alg].trunc_size);
      sym_cop->auth.digest.length =
		      em->esp_integ_algs[sa0->integ_alg].trunc_size;

      if (PREDICT_FALSE(is_ipv6))
	{
	  oh6_0->ip6.payload_length = clib_host_to_net_u16 (
	      vlib_buffer_length_in_chain (vm, b0) - sizeof(ip6_header_t));
	}
      else
	{
	  oh0->ip4.length = clib_host_to_net_u16 (
	      vlib_buffer_length_in_chain (vm, b0));
	  oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
	}

trace:
      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) {
	if (b0) {
	  b0->flags |= VLIB_BUFFER_IS_TRACED;
	  b0->trace_index = b0->trace_index;
	}
	esp_encrypt_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	tr->spi = sa0->spi;
	tr->seq = sa0->seq - 1;
	tr->crypto_alg = sa0->crypto_alg;
	tr->integ_alg = sa0->integ_alg;
      }

      if (PREDICT_FALSE(next0 == ESP_ENCRYPT_NEXT_DROP))
	rte_pktmbuf_free(mb0);
    }
  vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  for (i = 0; i < n_qps; i++)
    {
      u32 enq = rte_cryptodev_enqueue_burst(
	  lcore_main->qp_data[i].dev_id,
	  lcore_main->qp_data[i].qp_id,
	  cops_to_enq[i] - n_cop_qp[i],
	  n_cop_qp[i]);
      ASSERT(enq == n_cop_qp[i]);
    }

  return from_frame->n_vectors;
}


VLIB_REGISTER_NODE (dpdk_esp_encrypt_node) = {
  .function = dpdk_esp_encrypt_node_fn,
  .name = "dpdk-esp-encrypt",
	.flags = VLIB_NODE_FLAG_IS_OUTPUT,
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_encrypt_node, dpdk_esp_encrypt_node_fn)



/*
 * Encrypt Post Node
 */

#define foreach_esp_encrypt_post_error              \
 _(PKTS, "ESP post pkts")

typedef enum {
#define _(sym,str) ESP_ENCRYPT_POST_ERROR_##sym,
  foreach_esp_encrypt_post_error
#undef _
  ESP_ENCRYPT_POST_N_ERROR,
} esp_encrypt_post_error_t;

static char * esp_encrypt_post_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_encrypt_post_error
#undef _
};

vlib_node_registration_t dpdk_esp_encrypt_post_node;

static u8 * format_esp_encrypt_post_trace (u8 * s, va_list * args)
{
  return s;
}

static uword
dpdk_esp_encrypt_post_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, * to_next = 0, next_index;

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
          vlib_buffer_t * b0 = 0;

          bi0 = from[0];
          from += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          to_next[0] = bi0;
          to_next += 1;

	  /* FIXME */
	  next0 = vnet_buffer(b0)->output_features.unused[0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
              to_next, n_left_to_next, bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, dpdk_esp_encrypt_post_node.index,
                               ESP_ENCRYPT_POST_ERROR_PKTS,
                               from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (dpdk_esp_encrypt_post_node) = {
  .function = dpdk_esp_encrypt_post_node_fn,
  .name = "dpdk-esp-encrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_post_error_strings),
  .error_strings = esp_encrypt_post_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_ENCRYPT_NEXT_##s] = n,
    foreach_esp_encrypt_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_encrypt_post_node, dpdk_esp_encrypt_post_node_fn)

