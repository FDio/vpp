/*
 * dpdk_esp_decrypt.c : IPSec ESP Decrypt node using DPDK Cryptodev
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
//#include <vnet/ipsec/dpdk_esp.h>

#define ESP_WINDOW_SIZE 64

#define foreach_esp_decrypt_next                \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")

#define _(v, s) ESP_DECRYPT_NEXT_##v,
typedef enum {
  foreach_esp_decrypt_next
#undef _
  ESP_DECRYPT_N_NEXT,
} esp_decrypt_next_t;


#define foreach_esp_decrypt_error                   \
 _(RX_PKTS, "ESP pkts received")                    \
 _(NO_BUFFER, "No buffer (packed dropped)")         \
 _(DECRYPTION_FAILED, "ESP decryption failed")      \
 _(INTEG_ERROR, "Integrity check failed")           \
 _(REPLAY, "SA replayed packet")


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

always_inline int
esp_replay_check (ipsec_sa_t * sa, u32 seq)
{
  u32 diff;

  if (PREDICT_TRUE(seq > sa->last_seq))
    return 0;

  diff = sa->last_seq - seq;

  if (ESP_WINDOW_SIZE > diff)
    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
  else
    return 1;

  return 0;
}

always_inline int
esp_replay_check_esn (ipsec_sa_t * sa, u32 seq)
{
  u32 tl = sa->last_seq;
  u32 th = sa->last_seq_hi;
  u32 diff = tl - seq;

  if (PREDICT_TRUE(tl >= (ESP_WINDOW_SIZE - 1)))
    {
      if (seq >= (tl - ESP_WINDOW_SIZE + 1))
        {
          sa->seq_hi = th;
          if (seq <= tl)
            return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
          else
            return 0;
        }
      else
        {
          sa->seq_hi = th + 1;
          return 0;
        }
    }
  else
    {
      if (seq >= (tl - ESP_WINDOW_SIZE + 1))
        {
          sa->seq_hi = th - 1;
          return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
        }
      else
        {
          sa->seq_hi = th;
          if (seq <= tl)
            return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
          else
            return 0;
        }
    }

  return 0;
}

always_inline void
esp_replay_advance (ipsec_sa_t * sa, u32 seq)
{
  u32 pos;

  if (seq > sa->last_seq)
    {
      pos = seq - sa->last_seq;
      if (pos < ESP_WINDOW_SIZE)
        sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
        sa->replay_window = 1;
      sa->last_seq = seq;
    }
  else
    {
      pos = sa->last_seq - seq;
      sa->replay_window |= (1ULL << pos);
    }
}

always_inline void
esp_replay_advance_esn (ipsec_sa_t * sa, u32 seq)
{
  int wrap = sa->seq_hi - sa->last_seq_hi;
  u32 pos;

  if (wrap == 0 && seq > sa->last_seq)
    {
      pos = seq - sa->last_seq;
      if (pos < ESP_WINDOW_SIZE)
        sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
        sa->replay_window = 1;
      sa->last_seq = seq;
    }
  else if (wrap > 0)
    {
      pos = ~seq + sa->last_seq + 1;
      if (pos < ESP_WINDOW_SIZE)
        sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
        sa->replay_window = 1;
      sa->last_seq = seq;
      sa->last_seq_hi = sa->seq_hi;
    }
  else if (wrap < 0)
    {
      pos = ~seq + sa->last_seq + 1;
      sa->replay_window |= (1ULL << pos);
    }
  else
    {
      pos = sa->last_seq - seq;
      sa->replay_window |= (1ULL << pos);
    }
}

static uword
dpdk_esp_decrypt_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  dpdk_crypto_main_t * dcm = &dpdk_crypto_main;
  ipsec_main_t *im = &ipsec_main;
  esp_main_t *em = &esp_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  u32 cpu_index = os_get_cpu_number();
  ipsec_lcore_main_t *lcore_main = dcm->lcores_main[cpu_index];
  esp_main_per_thread_data_t * ptd = &em->per_thread_data[cpu_index];
  const u32 n_qps = lcore_main->n_qps;
  struct rte_crypto_op *cops_to_enq_cache[n_qps][VLIB_FRAME_SIZE];
  struct rte_crypto_op **cops_to_enq[n_qps];
  u32 n_cop_qp[n_qps], i;

  memset(n_cop_qp, 0, n_qps * sizeof(u32));

  for (i = 0; i < n_qps; i++)
    cops_to_enq[i] = cops_to_enq_cache[i];

  ipsec_alloc_cops();

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 i_bi0, next0;
          vlib_buffer_t * b0;
          esp_header_t * esp0;
          ipsec_sa_t * sa0;
          u32 sa_index0 = ~0;
          u32 seq;
	  struct rte_mbuf * mb0 = 0;
	  const int BLOCK_SIZE = 16;
	  const int IV_SIZE = 16;
	  esp_sa_session_t *sa_sess;
	  void *sess;

          i_bi0 = from[0];
          from += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          next0 = ESP_DECRYPT_NEXT_DROP;

          b0 = vlib_get_buffer (vm, i_bi0);
          esp0 = vlib_buffer_get_current (b0);

          sa_index0 = vnet_buffer(b0)->output_features.ipsec_sad_index;
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
                  clib_warning("anti-replay SPI %u seq %u", sa0->spi, seq);
                  vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
                                               ESP_DECRYPT_ERROR_REPLAY, 1);
                  goto trace;
                }
            }

          if (PREDICT_TRUE(sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
            {
              u16 qp_index;
              uword last_cop;
              struct rte_crypto_op *cop = 0, **cops;

              sa_sess = pool_elt_at_index(ptd->sa_sess_d[0], sa_index0);

              if (PREDICT_FALSE(!sa_sess->sess))
        	{
		  int ret = create_sym_sess(sa0, sa_sess, 0);
		  ASSERT(ret == 0);
		}

	      sess = sa_sess->sess;

	      qp_index = sa_sess->qp_index;

	      cops = lcore_main->qp_data[qp_index].cops;

	      last_cop = vec_len(cops) - 1;
	      cop = cops[last_cop];
	      _vec_len (cops) = last_cop;

	      cops_to_enq[qp_index][0] = cop;
	      cops_to_enq[qp_index] += 1;
	      n_cop_qp[qp_index] += 1;

	      rte_crypto_op_attach_sym_session(cop, sess);

	      int icv_size = em->esp_integ_algs[sa0->integ_alg].trunc_size;

              /*Convert vlib buffer to mbuf*/
	      mb0 = rte_mbuf_from_vlib_buffer(b0);
	      mb0->data_len = b0->current_length;
	      mb0->pkt_len = b0->current_length;
	      mb0->data_off = RTE_PKTMBUF_HEADROOM + b0->current_data;

	      //u16 IP_ESP_HDR_SZ = sizeof (esp_header_t) + sizeof (ip4_header_t);
	      /*Outer IP header has already been stripped*/
              u16 payload_len = rte_pktmbuf_pkt_len(mb0) - sizeof (esp_header_t) - IV_SIZE - icv_size;

              if ((payload_len & (BLOCK_SIZE - 1)) || (payload_len <= 0))
                {
                  fprintf(stdout, "payload %d not multiple of %u\n",
                          payload_len, BLOCK_SIZE);
                  return -EINVAL;
                }

              struct rte_crypto_sym_op *sym_cop = (struct rte_crypto_sym_op *)(cop + 1);

              sym_cop->m_src = mb0;
              sym_cop->cipher.data.offset = sizeof (esp_header_t) + IV_SIZE;
              sym_cop->cipher.data.length = payload_len;

              sym_cop->cipher.iv.data = rte_pktmbuf_mtod_offset(mb0, void*,
                       sizeof (esp_header_t));
              sym_cop->cipher.iv.phys_addr = rte_pktmbuf_mtophys_offset(mb0,
                       sizeof (esp_header_t));
              sym_cop->cipher.iv.length = IV_SIZE;

              sym_cop->auth.data.offset = 0;
              sym_cop->auth.data.length = sizeof(esp_header_t) +
                       IV_SIZE + payload_len;

              sym_cop->auth.digest.data = rte_pktmbuf_mtod_offset(mb0, void*,
                       rte_pktmbuf_pkt_len(mb0) - icv_size);
              sym_cop->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(mb0,
                       rte_pktmbuf_pkt_len(mb0) - icv_size);
              sym_cop->auth.digest.length = icv_size;

            }

          if (PREDICT_TRUE(sa0->use_anti_replay))
            {
              if (PREDICT_TRUE(sa0->use_esn))
                esp_replay_advance_esn(sa0, seq);
              else
                esp_replay_advance(sa0, seq);
             }


          /*FIXME Hardcode for successfull packet*/
          next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
trace:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) {
            esp_decrypt_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
            tr->crypto_alg = sa0->crypto_alg;
            tr->integ_alg = sa0->integ_alg;
          }

          if (PREDICT_FALSE(next0 == ESP_DECRYPT_NEXT_DROP))
            rte_pktmbuf_free(mb0);
        }
    }
  vlib_node_increment_counter (vm, dpdk_esp_decrypt_node.index,
                               ESP_DECRYPT_ERROR_RX_PKTS,
                               from_frame->n_vectors);

  for (i = 0; i < lcore_main->n_qps; i++)
    {
      u32 deq = rte_cryptodev_enqueue_burst(
	  lcore_main->qp_data[i].dev_id,
	  lcore_main->qp_data[i].qp_id,
	  cops_to_enq[i] - n_cop_qp[i],
	  n_cop_qp[i]);
      ASSERT(deq == n_cop_qp[i]);
    }

  return from_frame->n_vectors;

}


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

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_decrypt_node, dpdk_esp_decrypt_node_fn)



/*
 * Decrypt Post Node
 */

#define foreach_esp_decrypt_post_error              \
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
  u32 n_left_from, *from, * to_next = 0, next_index;
  ipsec_sa_t * sa0;
  u32 sa_index0 = ~0;
  ipsec_main_t *im = &ipsec_main;
  esp_main_t *em = &esp_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0, next0 = 0;
          vlib_buffer_t * b0 = 0;

          bi0 = from[0];
          from += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          sa_index0 = vnet_buffer(b0)->output_features.ipsec_sad_index;
          sa0 = pool_elt_at_index (im->sad, sa_index0);

          to_next[0] = bi0;
          to_next += 1;

          esp_footer_t * f0;
          const int IV_SIZE = 16;

          int icv_size = em->esp_integ_algs[sa0->integ_alg].trunc_size;


          b0->current_length -= (sizeof (esp_header_t) + IV_SIZE + icv_size + 2);
	  b0->current_data += sizeof (esp_header_t) + IV_SIZE;
	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  f0 = (esp_footer_t *) ((u8 *) vlib_buffer_get_current (b0) + b0->current_length);
	  b0->current_length -= f0->pad_length;
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

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;

trace:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) {
            if (b0) {
              b0->flags |= VLIB_BUFFER_IS_TRACED;
              b0->trace_index = b0->trace_index;
            }
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

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_decrypt_post_node, dpdk_esp_decrypt_post_node_fn)

