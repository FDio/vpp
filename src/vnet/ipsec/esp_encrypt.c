/*
 * esp_encrypt.c : IPSec ESP encrypt node
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
#include <vnet/udp/udp.h>

#include <vnet/crypto/crypto.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>

#define foreach_esp_encrypt_next                   \
_(DROP, "error-drop")                              \
_(HANDOFF, "handoff")                              \
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ESP_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_encrypt_next
#undef _
    ESP_ENCRYPT_N_NEXT,
} esp_encrypt_next_t;

#define foreach_esp_encrypt_error                               \
 _(RX_PKTS, "ESP pkts received")                                \
 _(SEQ_CYCLED, "sequence number cycled (packet dropped)")       \
 _(CRYPTO_ENGINE_ERROR, "crypto engine error (packet dropped)") \
 _(CRYPTO_QUEUE_FULL, "crypto queue full (packet dropped)")     \
 _(CHAINED_BUFFER, "chained buffers (packet dropped)")          \
 _(CHAINED_OP, "mismatch chained modes (packet dropped)")       \
 _(NO_TRAILER_SPACE, "no trailer space (packet dropped)")

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

typedef struct
{
  u32 sa_index;
  u32 spi;
  u32 seq;
  u32 sa_seq_hi;
  u8 udp_encap;
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

  s =
    format (s,
	    "esp: sa-index %d spi %u (0x%08x) seq %u sa-seq-hi %u crypto %U integrity %U%s",
	    t->sa_index, t->spi, t->spi, t->seq, t->sa_seq_hi,
	    format_ipsec_crypto_alg,
	    t->crypto_alg, format_ipsec_integ_alg, t->integ_alg,
	    t->udp_encap ? " udp-encap-enabled" : "");
  return s;
}

/* pad packet in input buffer */
static_always_inline u8 *
esp_add_footer_and_icv (vlib_buffer_t * b, u8 block_size, u8 icv_sz,
			u16 * next, vlib_node_runtime_t * node,
			u16 buffer_data_size)
{
  static const u8 pad_data[ESP_MAX_BLOCK_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00, 0x00,
  };

  u16 min_length = b->current_length + sizeof (esp_footer_t);
  u16 new_length = round_pow2 (min_length, block_size);
  u8 pad_bytes = new_length - min_length;
  esp_footer_t *f = (esp_footer_t *) (vlib_buffer_get_current (b) +
				      new_length - sizeof (esp_footer_t));

  if (b->current_data + new_length + icv_sz > buffer_data_size)
    {
      b->error = node->errors[ESP_ENCRYPT_ERROR_NO_TRAILER_SPACE];
      next[0] = ESP_ENCRYPT_NEXT_DROP;
      return 0;
    }

  if (pad_bytes)
    {
      ASSERT (pad_bytes <= ESP_MAX_BLOCK_SIZE);
      pad_bytes = clib_min (ESP_MAX_BLOCK_SIZE, pad_bytes);
      clib_memcpy_fast ((u8 *) f - pad_bytes, pad_data, pad_bytes);
    }

  f->pad_length = pad_bytes;
  b->current_length = new_length + icv_sz;
  return &f->next_header;
}

static_always_inline void
esp_update_ip4_hdr (ip4_header_t * ip4, u16 len, int is_transport, int is_udp)
{
  ip_csum_t sum;
  u16 old_len;

  len = clib_net_to_host_u16 (len);
  old_len = ip4->length;

  if (is_transport)
    {
      u8 prot = is_udp ? IP_PROTOCOL_UDP : IP_PROTOCOL_IPSEC_ESP;

      sum = ip_csum_update (ip4->checksum, ip4->protocol,
			    prot, ip4_header_t, protocol);
      ip4->protocol = prot;

      sum = ip_csum_update (sum, old_len, len, ip4_header_t, length);
    }
  else
    sum = ip_csum_update (ip4->checksum, old_len, len, ip4_header_t, length);

  ip4->length = len;
  ip4->checksum = ip_csum_fold (sum);
}

static_always_inline void
esp_fill_udp_hdr (ipsec_sa_t * sa, udp_header_t * udp, u16 len)
{
  clib_memcpy_fast (udp, &sa->udp_hdr, sizeof (udp_header_t));
  udp->length = clib_net_to_host_u16 (len);
}

static_always_inline u8
ext_hdr_is_pre_esp (u8 nexthdr)
{
#ifdef CLIB_HAVE_VEC128
  static const u8x16 ext_hdr_types = {
    IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS,
    IP_PROTOCOL_IPV6_ROUTE,
    IP_PROTOCOL_IPV6_FRAGMENTATION,
  };

  return !u8x16_is_all_zero (ext_hdr_types == u8x16_splat (nexthdr));
#else
  return ((nexthdr ^ IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS) |
	  (nexthdr ^ IP_PROTOCOL_IPV6_ROUTE) |
	  (nexthdr ^ IP_PROTOCOL_IPV6_FRAGMENTATION) != 0);
#endif
}

static_always_inline u8
esp_get_ip6_hdr_len (ip6_header_t * ip6, ip6_ext_header_t ** ext_hdr)
{
  /* this code assumes that HbH, route and frag headers will be before
     others, if that is not the case, they will end up encrypted */
  u8 len = sizeof (ip6_header_t);
  ip6_ext_header_t *p;

  /* if next packet doesn't have ext header */
  if (ext_hdr_is_pre_esp (ip6->protocol) == 0)
    {
      *ext_hdr = NULL;
      return len;
    }

  p = (void *) (ip6 + 1);
  len += ip6_ext_header_len (p);

  while (ext_hdr_is_pre_esp (p->next_hdr))
    {
      len += ip6_ext_header_len (p);
      p = ip6_ext_next_header (p);
    }

  *ext_hdr = p;
  return len;
}

#define esp_add_fwd_buf(ptd, bi, next) \
  do { \
      vec_add1 (ptd->bis, bi); \
      vec_add1 (ptd->nexts, next); \
  } while (0)

static_always_inline void
esp_process_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vnet_crypto_op_t * ops, ipsec_per_thread_data_t * ptd)
{
  u32 n_fail, n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

  n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 index = op->user_data;
	  u32 bi = ptd->bis[op->user_data];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  b->error = node->errors[ESP_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR];
	  ptd->nexts[index] = ESP_ENCRYPT_NEXT_DROP;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline void
esp_submit_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
		ipsec_per_thread_data_t * ptd)
{
  u32 n_fail, n_ops = vec_len (ptd->async_ops);
  vnet_crypto_op_t **ops;

  if (n_ops == 0)
    return;

  ops = ptd->async_ops;

  n_fail = n_ops - vnet_crypto_submit_ops (vm, ops, n_ops);
  if (!n_fail)
    return;

  ops += (n_ops - n_fail);
  while (n_fail--)
    {
      u32 bi = ops[0]->bi;
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      b->error = node->errors[ESP_ENCRYPT_ERROR_CRYPTO_QUEUE_FULL];
      esp_add_fwd_buf (ptd, bi, ESP_ENCRYPT_NEXT_DROP);
      vnet_crypto_async_free_op (vm, ops[0]);
      ops++;
    }
}

typedef struct
{
  u32 salt;
  u64 iv;
} __clib_packed esp_gcm_nonce_t;

STATIC_ASSERT_SIZEOF (esp_gcm_nonce_t, 12);


typedef void (esp_enc_crypto_op_post_t) (vnet_crypto_op_t * op,
					 vlib_buffer_t * b,
					 ipsec_per_thread_data_t * ptd,
					 u32 bi, u16 next, u32 post_next);

static_always_inline void
esp_sync_crypto_op_post (vnet_crypto_op_t * op, vlib_buffer_t * b,
			 ipsec_per_thread_data_t * ptd, u32 bi, u16 next,
			 u32 post_next)
{
  /* set user data to index of ptd->bis in case failed crypto later */
  op->user_data = vec_len (ptd->bis);
}

static_always_inline void
esp_async_crypto_op_post (vnet_crypto_op_t * op, vlib_buffer_t * b,
			  ipsec_per_thread_data_t * ptd, u32 bi, u16 next,
			  u32 post_next)
{
  esp_post_data_t *pa = esp_post_data (b);
  op->bi = bi;
  op->next = next;
  pa->next_index = post_next;
}

static esp_get_crypto_op_t *get_op[] = {
  esp_get_sync_op,
  esp_get_async_op
};

static esp_enc_crypto_op_post_t *crypto_op_post[] = {
  esp_sync_crypto_op_post,
  esp_async_crypto_op_post
};

always_inline uword
esp_encrypt_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame, int is_ip6, int is_tun,
		    u32 async_next)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, vm->thread_index);
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  esp_gcm_nonce_t nonces[VLIB_FRAME_SIZE], *nonce = nonces;
  u32 thread_index = vm->thread_index;
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u32 current_sa_index = ~0, current_sa_packets = 0;
  u32 current_sa_bytes = 0, spi = 0;
  u8 block_sz = 0, iv_sz = 0, icv_sz = 0;
  ipsec_sa_t *sa0 = 0;
  vnet_crypto_mode_t crypto_mode = VNET_CRYPTO_MODE_SYNC;

  vlib_get_buffers (vm, from, b, n_left);
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->integ_ops);
  vec_reset_length (ptd->async_ops);
  vec_reset_length (ptd->bis);
  vec_reset_length (ptd->nexts);

  while (n_left > 0)
    {
      u32 sa_index0;
      dpo_id_t *dpo;
      esp_header_t *esp;
      u8 *payload, *next_hdr_ptr;
      u16 payload_len;
      u32 hdr_len, config_index;
      u32 next;
      u32 bi = from[b - bufs];

      if (n_left > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	  p -= CLIB_CACHE_LINE_BYTES;
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      if (is_tun)
	{
	  /* we are on a ipsec tunnel's feature arc */
	  config_index = b[0]->current_config_index;
	  sa_index0 = *(u32 *) vnet_feature_next_with_data (&next, b[0],
							    sizeof
							    (sa_index0));
	  vnet_buffer (b[0])->ipsec.sad_index = sa_index0;
	}
      else
	sa_index0 = vnet_buffer (b[0])->ipsec.sad_index;

      if (sa_index0 != current_sa_index)
	{
	  if (current_sa_packets)
	    vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					     current_sa_index,
					     current_sa_packets,
					     current_sa_bytes);
	  current_sa_packets = current_sa_bytes = 0;

	  sa0 = pool_elt_at_index (im->sad, sa_index0);
	  current_sa_index = sa_index0;
	  spi = clib_net_to_host_u32 (sa0->spi);
	  block_sz = sa0->crypto_block_size;
	  icv_sz = sa0->integ_icv_size;
	  iv_sz = sa0->crypto_iv_size;

	  if (sa0->crypto_enc_op_id)
	    crypto_mode = vnet_crypto_get_mode (sa0->crypto_enc_op_id);

	  if (sa0->integ_op_id)
	    {
	      vnet_crypto_mode_t integ_mode =
		vnet_crypto_get_mode (sa0->integ_op_id);
	      if (sa0->crypto_enc_op_id && crypto_mode != integ_mode)
		{
		  b[0]->error = node->errors[ESP_ENCRYPT_ERROR_CHAINED_OP];
		  esp_add_fwd_buf (ptd, bi, ESP_ENCRYPT_NEXT_DROP);
		  goto trace;
		}
	      else
		crypto_mode = integ_mode;
	    }
	}

      if (PREDICT_FALSE (~0 == sa0->encrypt_thread_index))
	{
	  /* this is the first packet to use this SA, claim the SA
	   * for this thread. this could happen simultaneously on
	   * another thread */
	  clib_atomic_cmp_and_swap (&sa0->encrypt_thread_index, ~0,
				    ipsec_sa_assign_thread (thread_index));
	}

      if (PREDICT_TRUE (thread_index != sa0->encrypt_thread_index))
	{
	  if (is_tun)
	    {
	      b[0]->current_config_index = config_index;
	    }
	  esp_add_fwd_buf (ptd, bi, ESP_ENCRYPT_NEXT_HANDOFF);
	  goto trace;
	}

      if (vlib_buffer_chain_linearize (vm, b[0]) != 1)
	{
	  b[0]->error = node->errors[ESP_ENCRYPT_ERROR_CHAINED_BUFFER];
	  esp_add_fwd_buf (ptd, bi, ESP_ENCRYPT_NEXT_DROP);
	  goto trace;
	}

      if (PREDICT_FALSE (esp_seq_advance (sa0)))
	{
	  b[0]->error = node->errors[ESP_ENCRYPT_ERROR_SEQ_CYCLED];
	  esp_add_fwd_buf (ptd, bi, ESP_ENCRYPT_NEXT_DROP);
	  goto trace;
	}

      /* space for IV */
      hdr_len = iv_sz;

      if (ipsec_sa_is_set_IS_TUNNEL (sa0))
	{
	  payload = vlib_buffer_get_current (b[0]);
	  next_hdr_ptr = esp_add_footer_and_icv (b[0], block_sz, icv_sz,
						 (u16 *) & next, node,
						 buffer_data_size);
	  if (!next_hdr_ptr)
	    {
	      esp_add_fwd_buf (ptd, bi, next);
	      goto trace;
	    }
	  payload_len = b[0]->current_length;

	  /* ESP header */
	  hdr_len += sizeof (*esp);
	  esp = (esp_header_t *) (payload - hdr_len);

	  /* optional UDP header */
	  if (ipsec_sa_is_set_UDP_ENCAP (sa0))
	    {
	      hdr_len += sizeof (udp_header_t);
	      esp_fill_udp_hdr (sa0, (udp_header_t *) (payload - hdr_len),
				payload_len + hdr_len);
	    }

	  /* IP header */
	  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa0))
	    {
	      ip6_header_t *ip6;
	      u16 len = sizeof (ip6_header_t);
	      hdr_len += len;
	      ip6 = (ip6_header_t *) (payload - hdr_len);
	      clib_memcpy_fast (ip6, &sa0->ip6_hdr, len);
	      *next_hdr_ptr = (is_ip6 ?
			       IP_PROTOCOL_IPV6 : IP_PROTOCOL_IP_IN_IP);
	      len = payload_len + hdr_len - len;
	      ip6->payload_length = clib_net_to_host_u16 (len);
	    }
	  else
	    {
	      ip4_header_t *ip4;
	      u16 len = sizeof (ip4_header_t);
	      hdr_len += len;
	      ip4 = (ip4_header_t *) (payload - hdr_len);
	      clib_memcpy_fast (ip4, &sa0->ip4_hdr, len);
	      *next_hdr_ptr = (is_ip6 ?
			       IP_PROTOCOL_IPV6 : IP_PROTOCOL_IP_IN_IP);
	      len = payload_len + hdr_len;
	      esp_update_ip4_hdr (ip4, len, /* is_transport */ 0, 0);
	    }

	  dpo = &sa0->dpo;
	  if (!is_tun)
	    {
	      next = dpo->dpoi_next_node;
	      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo->dpoi_index;
	    }
	}
      else			/* transport mode */
	{
	  u8 *l2_hdr, l2_len, *ip_hdr, ip_len;
	  ip6_ext_header_t *ext_hdr;
	  udp_header_t *udp = 0;
	  u8 *old_ip_hdr = vlib_buffer_get_current (b[0]);

	  ip_len = is_ip6 ?
	    esp_get_ip6_hdr_len ((ip6_header_t *) old_ip_hdr, &ext_hdr) :
	    ip4_header_bytes ((ip4_header_t *) old_ip_hdr);

	  vlib_buffer_advance (b[0], ip_len);
	  payload = vlib_buffer_get_current (b[0]);
	  next_hdr_ptr = esp_add_footer_and_icv (b[0], block_sz, icv_sz,
						 (u16 *) & next, node,
						 buffer_data_size);
	  if (!next_hdr_ptr)
	    {
	      esp_add_fwd_buf (ptd, bi, next);
	      goto trace;
	    }
	  payload_len = b[0]->current_length;

	  /* ESP header */
	  hdr_len += sizeof (*esp);
	  esp = (esp_header_t *) (payload - hdr_len);

	  /* optional UDP header */
	  if (ipsec_sa_is_set_UDP_ENCAP (sa0))
	    {
	      hdr_len += sizeof (udp_header_t);
	      udp = (udp_header_t *) (payload - hdr_len);
	    }

	  /* IP header */
	  hdr_len += ip_len;
	  ip_hdr = payload - hdr_len;

	  /* L2 header */
	  if (!is_tun)
	    {
	      l2_len = vnet_buffer (b[0])->ip.save_rewrite_length;
	      hdr_len += l2_len;
	      l2_hdr = payload - hdr_len;

	      /* copy l2 and ip header */
	      clib_memcpy_le32 (l2_hdr, old_ip_hdr - l2_len, l2_len);
	    }
	  else
	    l2_len = 0;

	  if (is_ip6)
	    {
	      ip6_header_t *ip6 = (ip6_header_t *) (old_ip_hdr);
	      if (PREDICT_TRUE (NULL == ext_hdr))
		{
		  *next_hdr_ptr = ip6->protocol;
		  ip6->protocol = IP_PROTOCOL_IPSEC_ESP;
		}
	      else
		{
		  *next_hdr_ptr = ext_hdr->next_hdr;
		  ext_hdr->next_hdr = IP_PROTOCOL_IPSEC_ESP;
		}
	      ip6->payload_length =
		clib_host_to_net_u16 (payload_len + hdr_len - l2_len -
				      sizeof (ip6_header_t));
	    }
	  else
	    {
	      u16 len;
	      ip4_header_t *ip4 = (ip4_header_t *) (old_ip_hdr);
	      *next_hdr_ptr = ip4->protocol;
	      len = payload_len + hdr_len - l2_len;
	      if (udp)
		{
		  esp_update_ip4_hdr (ip4, len, /* is_transport */ 1, 1);
		  esp_fill_udp_hdr (sa0, udp, len - ip_len);
		}
	      else
		esp_update_ip4_hdr (ip4, len, /* is_transport */ 1, 0);
	    }

	  clib_memcpy_le64 (ip_hdr, old_ip_hdr, ip_len);

	  if (!is_tun)
	    next = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	}

      esp->spi = spi;
      esp->seq = clib_net_to_host_u32 (sa0->seq);

      if (sa0->crypto_enc_op_id)
	{
	  vnet_crypto_op_t *op = (get_op[crypto_mode]) (vm, &ptd->crypto_ops,
							&ptd->async_ops,
							sa0->crypto_enc_op_id);
	  if (PREDICT_FALSE (op == 0))
	    {
	      b[0]->error =
		node->errors[ESP_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR];
	      esp_add_fwd_buf (ptd, bi, ESP_ENCRYPT_NEXT_DROP);
	      goto trace;
	    }
	  op->src = op->dst = payload;
	  op->key_index = sa0->crypto_key_index;
	  op->len = payload_len - icv_sz;

	  if (ipsec_sa_is_set_IS_AEAD (sa0))
	    {
	      /*
	       * construct the AAD in a scratch space in front
	       * of the IP header.
	       */
	      op->aad = payload - hdr_len - sizeof (esp_aead_t);

	      esp_aad_fill (op, esp, sa0);

	      op->tag = payload + op->len;
	      op->tag_len = 16;

	      u64 *iv = (u64 *) (payload - iv_sz);
	      nonce->salt = sa0->salt;
	      nonce->iv = *iv = clib_host_to_net_u64 (sa0->gcm_iv_counter++);
	      op->iv = (u8 *) nonce;
	      nonce++;
	    }
	  else
	    {
	      op->iv = payload - iv_sz;
	      op->flags = VNET_CRYPTO_OP_FLAG_INIT_IV;
	    }
	  (crypto_op_post[crypto_mode]) (op, b[0], ptd, from[b - bufs],
					 async_next, next);
	}

      if (sa0->integ_op_id)
	{
	  vnet_crypto_op_t *op = (get_op[crypto_mode]) (vm, &ptd->integ_ops,
							&ptd->async_ops,
							sa0->integ_op_id);
	  if (PREDICT_FALSE (op == 0))
	    {
	      b[0]->error =
		node->errors[ESP_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR];
	      esp_add_fwd_buf (ptd, bi, ESP_ENCRYPT_NEXT_DROP);
	      goto trace;
	    }
	  op->src = payload - iv_sz - sizeof (esp_header_t);
	  op->digest = payload + payload_len - icv_sz;
	  op->key_index = sa0->integ_key_index;
	  op->digest_len = icv_sz;
	  op->len = payload_len - icv_sz + iv_sz + sizeof (esp_header_t);
	  op->user_data = b - bufs;
	  if (ipsec_sa_is_set_USE_ESN (sa0))
	    {
	      u32 seq_hi = clib_net_to_host_u32 (sa0->seq_hi);
	      clib_memcpy_fast (op->digest, &seq_hi, sizeof (seq_hi));
	      op->len += sizeof (seq_hi);
	    }
	  (crypto_op_post[crypto_mode]) (op, b[0], ptd, from[b - bufs],
					 async_next, next);
	}

      if (crypto_mode == VNET_CRYPTO_MODE_SYNC)
	esp_add_fwd_buf (ptd, bi, next);

      vlib_buffer_advance (b[0], 0LL - hdr_len);

      current_sa_packets += 1;
      current_sa_bytes += payload_len;

    trace:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_encrypt_trace_t *tr = vlib_add_trace (vm, node, b[0],
						    sizeof (*tr));
	  tr->sa_index = sa_index0;
	  tr->spi = sa0->spi;
	  tr->seq = sa0->seq;
	  tr->sa_seq_hi = sa0->seq_hi;
	  tr->udp_encap = ipsec_sa_is_set_UDP_ENCAP (sa0);
	  tr->crypto_alg = sa0->crypto_alg;
	  tr->integ_alg = sa0->integ_alg;
	}
      /* next */
      n_left -= 1;
      b += 1;
    }

  vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				   current_sa_index, current_sa_packets,
				   current_sa_bytes);
  esp_process_ops (vm, node, ptd->crypto_ops, ptd);
  esp_process_ops (vm, node, ptd->integ_ops, ptd);
  esp_submit_ops (vm, node, ptd);

  vlib_node_increment_counter (vm, node->node_index,
			       ESP_ENCRYPT_ERROR_RX_PKTS, frame->n_vectors);

  if (vec_len (ptd->bis))
    vlib_buffer_enqueue_to_next (vm, node, ptd->bis, ptd->nexts,
				 vec_len (ptd->bis));
  return frame->n_vectors;
}


always_inline uword
esp_encrypt_post_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, b, n_left);

  if (n_left >= 4)
    {
      vlib_prefetch_buffer_header (b[0], LOAD);
      vlib_prefetch_buffer_header (b[1], LOAD);
      vlib_prefetch_buffer_header (b[2], LOAD);
      vlib_prefetch_buffer_header (b[3], LOAD);
    }

  while (n_left > 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      next[0] = (esp_post_data (b[0]))->next_index;
      next[1] = (esp_post_data (b[1]))->next_index;
      next[2] = (esp_post_data (b[2]))->next_index;
      next[3] = (esp_post_data (b[3]))->next_index;

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      next[0] = (esp_post_data (b[0]))->next_index;

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (esp4_encrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  esp_encrypt_async_index_t *eit = &esp_encrypt_async_next;
  return esp_encrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ , 0,
			     eit->esp4_encrypt_post_index);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_encrypt_node) = {
  .name = "esp4-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
    [ESP_ENCRYPT_NEXT_DROP] = "ip4-drop",
    [ESP_ENCRYPT_NEXT_HANDOFF] = "esp4-encrypt-handoff",
    [ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp4_encrypt_post_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return esp_encrypt_post_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_encrypt_post_node) = {
  .name = "esp4-encrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp4-encrypt",

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp6_encrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  esp_encrypt_async_index_t *eit = &esp_encrypt_async_next;
  return esp_encrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ , 0,
			     eit->esp6_encrypt_post_index);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_encrypt_node) = {
  .name = "esp6-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
    [ESP_ENCRYPT_NEXT_DROP] = "ip6-drop",
    [ESP_ENCRYPT_NEXT_HANDOFF] = "esp6-encrypt-handoff",
    [ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp6_encrypt_post_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return esp_encrypt_post_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_encrypt_post_node) = {
  .name = "esp6-encrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp6-encrypt",

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp4_encrypt_tun_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  esp_encrypt_async_index_t *eit = &esp_encrypt_async_next;
  return esp_encrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ , 1,
			     eit->esp4_encrypt_tun_post_index);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_encrypt_tun_node) = {
  .name = "esp4-encrypt-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
    [ESP_ENCRYPT_NEXT_DROP] = "ip4-drop",
    [ESP_ENCRYPT_NEXT_HANDOFF] = "esp4-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "error-drop",
  },
};

VLIB_NODE_FN (esp4_encrypt_tun_post_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_encrypt_post_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_encrypt_tun_post_node) = {
  .name = "esp4-encrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp4-encrypt-tun",

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};

VNET_FEATURE_INIT (esp4_encrypt_tun_feat_node, static) =
{
  .arc_name = "ip4-output",
  .node_name = "esp4-encrypt-tun",
  .runs_before = VNET_FEATURES ("adj-midchain-tx"),
};

VNET_FEATURE_INIT (esp6o4_encrypt_tun_feat_node, static) =
{
  .arc_name = "ip6-output",
  .node_name = "esp4-encrypt-tun",
  .runs_before = VNET_FEATURES ("adj-midchain-tx"),
};

VNET_FEATURE_INIT (esp4_ethernet_encrypt_tun_feat_node, static) =
{
  .arc_name = "ethernet-output",
  .node_name = "esp4-encrypt-tun",
  .runs_before = VNET_FEATURES ("adj-midchain-tx", "adj-midchain-tx-no-count"),
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp6_encrypt_tun_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  esp_encrypt_async_index_t *eit = &esp_encrypt_async_next;
  return esp_encrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ , 1,
			     eit->esp6_encrypt_tun_post_index);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_encrypt_tun_node) = {
  .name = "esp6-encrypt-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
    [ESP_ENCRYPT_NEXT_DROP] = "ip6-drop",
    [ESP_ENCRYPT_NEXT_HANDOFF] = "esp6-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp6_encrypt_tun_post_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * from_frame)
{
  return esp_encrypt_post_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_encrypt_tun_post_node) = {
  .name = "esp6-encrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp6-encrypt-tun",

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};

VNET_FEATURE_INIT (esp6_encrypt_tun_feat_node, static) =
{
  .arc_name = "ip6-output",
  .node_name = "esp6-encrypt-tun",
  .runs_before = VNET_FEATURES ("adj-midchain-tx"),
};

VNET_FEATURE_INIT (esp4o6_encrypt_tun_feat_node, static) =
{
  .arc_name = "ip4-output",
  .node_name = "esp6-encrypt-tun",
  .runs_before = VNET_FEATURES ("adj-midchain-tx"),
};

/* *INDENT-ON* */

typedef struct
{
  u32 sa_index;
} esp_no_crypto_trace_t;

static u8 *
format_esp_no_crypto_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_no_crypto_trace_t *t = va_arg (*args, esp_no_crypto_trace_t *);

  s = format (s, "esp-no-crypto: sa-index %u", t->sa_index);

  return s;
}

enum
{
  ESP_NO_CRYPTO_NEXT_DROP,
  ESP_NO_CRYPTO_N_NEXT,
};

enum
{
  ESP_NO_CRYPTO_ERROR_RX_PKTS,
};

static char *esp_no_crypto_error_strings[] = {
  "Outbound ESP packets received",
};

always_inline uword
esp_no_crypto_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, b, n_left);

  while (n_left > 0)
    {
      u32 next0;
      u32 sa_index0;

      /* packets are always going to be dropped, but get the sa_index */
      sa_index0 = *(u32 *) vnet_feature_next_with_data (&next0, b[0],
							sizeof (sa_index0));

      next[0] = ESP_NO_CRYPTO_NEXT_DROP;

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_no_crypto_trace_t *tr = vlib_add_trace (vm, node, b[0],
						      sizeof (*tr));
	  tr->sa_index = sa_index0;
	}

      n_left -= 1;
      next += 1;
      b += 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       ESP_NO_CRYPTO_ERROR_RX_PKTS, frame->n_vectors);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (esp4_no_crypto_tun_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * from_frame)
{
  return esp_no_crypto_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_no_crypto_tun_node) =
{
  .name = "esp4-no-crypto",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_no_crypto_trace,
  .n_errors = ARRAY_LEN(esp_no_crypto_error_strings),
  .error_strings = esp_no_crypto_error_strings,
  .n_next_nodes = ESP_NO_CRYPTO_N_NEXT,
  .next_nodes = {
    [ESP_NO_CRYPTO_NEXT_DROP] = "ip4-drop",
  },
};

VNET_FEATURE_INIT (esp4_no_crypto_tun_feat_node, static) =
{
  .arc_name = "ip4-output",
  .node_name = "esp4-no-crypto",
  .runs_before = VNET_FEATURES ("adj-midchain-tx"),
};

VLIB_NODE_FN (esp6_no_crypto_tun_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * from_frame)
{
  return esp_no_crypto_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_no_crypto_tun_node) =
{
  .name = "esp6-no-crypto",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_no_crypto_trace,
  .n_errors = ARRAY_LEN(esp_no_crypto_error_strings),
  .error_strings = esp_no_crypto_error_strings,
  .n_next_nodes = ESP_NO_CRYPTO_N_NEXT,
  .next_nodes = {
    [ESP_NO_CRYPTO_NEXT_DROP] = "ip6-drop",
  },
};

VNET_FEATURE_INIT (esp6_no_crypto_tun_feat_node, static) =
{
  .arc_name = "ip6-output",
  .node_name = "esp6-no-crypto",
  .runs_before = VNET_FEATURES ("adj-midchain-tx"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
