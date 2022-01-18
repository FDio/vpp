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

#include <vnet/crypto/crypto.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/esp.h>
#include <vnet/tunnel/tunnel_dp.h>

#define foreach_esp_encrypt_next                                              \
  _ (DROP4, "ip4-drop")                                                       \
  _ (DROP6, "ip6-drop")                                                       \
  _ (DROP_MPLS, "mpls-drop")                                                  \
  _ (HANDOFF4, "handoff4")                                                    \
  _ (HANDOFF6, "handoff6")                                                    \
  _ (HANDOFF_MPLS, "handoff-mpls")                                            \
  _ (INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ESP_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_encrypt_next
#undef _
    ESP_ENCRYPT_N_NEXT,
} esp_encrypt_next_t;

#define foreach_esp_encrypt_error                                             \
  _ (RX_PKTS, "ESP pkts received")                                            \
  _ (POST_RX_PKTS, "ESP-post pkts received")                                  \
  _ (HANDOFF, "Hand-off")                                                     \
  _ (SEQ_CYCLED, "sequence number cycled (packet dropped)")                   \
  _ (CRYPTO_ENGINE_ERROR, "crypto engine error (packet dropped)")             \
  _ (CRYPTO_QUEUE_FULL, "crypto queue full (packet dropped)")                 \
  _ (NO_BUFFERS, "no buffers (packet dropped)")                               \
  _ (NO_PROTECTION, "no protecting SA (packet dropped)")                      \
  _ (NO_ENCRYPTION, "no Encrypting SA (packet dropped)")

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

typedef struct
{
  u32 next_index;
} esp_encrypt_post_trace_t;

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

static u8 *
format_esp_post_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_post_trace_t *t = va_arg (*args, esp_encrypt_post_trace_t *);

  s = format (s, "esp-post: next node index %u", t->next_index);
  return s;
}

/* pad packet in input buffer */
static_always_inline u8 *
esp_add_footer_and_icv (vlib_main_t *vm, vlib_buffer_t **last, u8 esp_align,
			u8 icv_sz, vlib_node_runtime_t *node,
			u16 buffer_data_size, uword total_len)
{
  static const u8 pad_data[ESP_MAX_BLOCK_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
  };

  u16 min_length = total_len + sizeof (esp_footer_t);
  u16 new_length = round_pow2 (min_length, esp_align);
  u8 pad_bytes = new_length - min_length;
  esp_footer_t *f = (esp_footer_t *) (vlib_buffer_get_current (last[0]) +
				      last[0]->current_length + pad_bytes);
  u16 tail_sz = sizeof (esp_footer_t) + pad_bytes + icv_sz;

  if (last[0]->current_data + last[0]->current_length + tail_sz >
      buffer_data_size)
    {
      u32 tmp_bi = 0;
      if (vlib_buffer_alloc (vm, &tmp_bi, 1) != 1)
	return 0;

      vlib_buffer_t *tmp = vlib_get_buffer (vm, tmp_bi);
      last[0]->next_buffer = tmp_bi;
      last[0]->flags |= VLIB_BUFFER_NEXT_PRESENT;
      f = (esp_footer_t *) (vlib_buffer_get_current (tmp) + pad_bytes);
      tmp->current_length += tail_sz;
      last[0] = tmp;
    }
  else
    last[0]->current_length += tail_sz;

  f->pad_length = pad_bytes;
  if (pad_bytes)
    {
      ASSERT (pad_bytes <= ESP_MAX_BLOCK_SIZE);
      pad_bytes = clib_min (ESP_MAX_BLOCK_SIZE, pad_bytes);
      clib_memcpy_fast ((u8 *) f - pad_bytes, pad_data, pad_bytes);
    }

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
	  ((nexthdr ^ IP_PROTOCOL_IPV6_FRAGMENTATION) != 0));
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

  p = ip6_next_header (ip6);
  len += ip6_ext_header_len (p);
  while (ext_hdr_is_pre_esp (p->next_hdr))
    {
      len += ip6_ext_header_len (p);
      p = ip6_ext_next_header (p);
    }

  *ext_hdr = p;
  return len;
}

static_always_inline void
esp_process_chained_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vnet_crypto_op_t * ops, vlib_buffer_t * b[],
			 u16 * nexts, vnet_crypto_op_chunk_t * chunks,
			 u16 drop_next)
{
  u32 n_fail, n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

  n_fail = n_ops - vnet_crypto_process_chained_ops (vm, op, chunks, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 bi = op->user_data;
	  b[bi]->error = node->errors[ESP_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR];
	  nexts[bi] = drop_next;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline void
esp_process_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vnet_crypto_op_t * ops, vlib_buffer_t * b[], u16 * nexts,
		 u16 drop_next)
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
	  u32 bi = op->user_data;
	  b[bi]->error = node->errors[ESP_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR];
	  nexts[bi] = drop_next;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline u32
esp_encrypt_chain_crypto (vlib_main_t * vm, ipsec_per_thread_data_t * ptd,
			  ipsec_sa_t * sa0, vlib_buffer_t * b,
			  vlib_buffer_t * lb, u8 icv_sz, u8 * start,
			  u32 start_len, u16 * n_ch)
{
  vnet_crypto_op_chunk_t *ch;
  vlib_buffer_t *cb = b;
  u32 n_chunks = 1;
  u32 total_len;
  vec_add2 (ptd->chunks, ch, 1);
  total_len = ch->len = start_len;
  ch->src = ch->dst = start;
  cb = vlib_get_buffer (vm, cb->next_buffer);

  while (1)
    {
      vec_add2 (ptd->chunks, ch, 1);
      n_chunks += 1;
      if (lb == cb)
	total_len += ch->len = cb->current_length - icv_sz;
      else
	total_len += ch->len = cb->current_length;
      ch->src = ch->dst = vlib_buffer_get_current (cb);

      if (!(cb->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;

      cb = vlib_get_buffer (vm, cb->next_buffer);
    }

  if (n_ch)
    *n_ch = n_chunks;

  return total_len;
}

static_always_inline u32
esp_encrypt_chain_integ (vlib_main_t * vm, ipsec_per_thread_data_t * ptd,
			 ipsec_sa_t * sa0, vlib_buffer_t * b,
			 vlib_buffer_t * lb, u8 icv_sz, u8 * start,
			 u32 start_len, u8 * digest, u16 * n_ch)
{
  vnet_crypto_op_chunk_t *ch;
  vlib_buffer_t *cb = b;
  u32 n_chunks = 1;
  u32 total_len;
  vec_add2 (ptd->chunks, ch, 1);
  total_len = ch->len = start_len;
  ch->src = start;
  cb = vlib_get_buffer (vm, cb->next_buffer);

  while (1)
    {
      vec_add2 (ptd->chunks, ch, 1);
      n_chunks += 1;
      if (lb == cb)
	{
	  total_len += ch->len = cb->current_length - icv_sz;
	  if (ipsec_sa_is_set_USE_ESN (sa0))
	    {
	      u32 seq_hi = clib_net_to_host_u32 (sa0->seq_hi);
	      clib_memcpy_fast (digest, &seq_hi, sizeof (seq_hi));
	      ch->len += sizeof (seq_hi);
	      total_len += sizeof (seq_hi);
	    }
	}
      else
	total_len += ch->len = cb->current_length;
      ch->src = vlib_buffer_get_current (cb);

      if (!(cb->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;

      cb = vlib_get_buffer (vm, cb->next_buffer);
    }

  if (n_ch)
    *n_ch = n_chunks;

  return total_len;
}

always_inline void
esp_prepare_sync_op (vlib_main_t *vm, ipsec_per_thread_data_t *ptd,
		     vnet_crypto_op_t **crypto_ops,
		     vnet_crypto_op_t **integ_ops, ipsec_sa_t *sa0, u32 seq_hi,
		     u8 *payload, u16 payload_len, u8 iv_sz, u8 icv_sz, u32 bi,
		     vlib_buffer_t **b, vlib_buffer_t *lb, u32 hdr_len,
		     esp_header_t *esp)
{
  if (sa0->crypto_enc_op_id)
    {
      vnet_crypto_op_t *op;
      vec_add2_aligned (crypto_ops[0], op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, sa0->crypto_enc_op_id);
      u8 *crypto_start = payload;
      u16 crypto_len = payload_len - icv_sz;

      /* IPsec IV generation: IVs requirements differ depending of the
       * encryption mode: IVs must be unpredictable for AES-CBC whereas it can
       * be predictable but should never be reused with the same key material
       * for CTR and GCM. To avoid reusing the same IVs between multiple VPP
       * instances and between restarts, we use a properly chosen PRNG to
       * generate IVs. To ensure the IV is unpredictable for CBC, it is then
       * encrypted using the same key as the message. You can refer to NIST
       * SP800-38a and NIST SP800-38d for more details. */
      ASSERT (iv_sz >= sizeof (u64));
      u64 *pkt_iv = (u64 *) (payload - iv_sz);
      *pkt_iv = clib_pcg64i_random_r (&ptd->iv_prng);

      op->key_index = sa0->crypto_key_index;
      op->user_data = bi;

      if (ipsec_sa_is_set_IS_CTR (sa0))
	{
	  ASSERT (sizeof (u64) == iv_sz);
	  /* construct nonce in a scratch space in front of the IP header */
	  esp_ctr_nonce_t *nonce =
	    (esp_ctr_nonce_t *) (payload - sizeof (u64) - hdr_len -
				 sizeof (*nonce));
	  if (ipsec_sa_is_set_IS_AEAD (sa0))
	    {
	      /* constuct aad in a scratch space in front of the nonce */
	      op->aad = (u8 *) nonce - sizeof (esp_aead_t);
	      op->aad_len = esp_aad_fill (op->aad, esp, sa0, seq_hi);
	      op->tag = payload + crypto_len;
	      op->tag_len = 16;
	    }
	  else
	    {
	      nonce->ctr = clib_host_to_net_u32 (1);
	    }

	  nonce->salt = sa0->salt;
	  nonce->iv = *pkt_iv;
	  op->iv = (u8 *) nonce;
	}
      else
	{
	  /* construct zero iv in front of the IP header */
	  op->iv = payload - hdr_len - 2 * iv_sz;
	  clib_memset_u8 (op->iv, 0, iv_sz);
	  /* include iv field in crypto */
	  crypto_start -= iv_sz;
	  crypto_len += iv_sz;
	}

      if (PREDICT_FALSE (lb != b[0]))
	{
	  /* is chained */
	  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	  op->chunk_index = vec_len (ptd->chunks);
	  op->tag = vlib_buffer_get_tail (lb) - icv_sz;
	  esp_encrypt_chain_crypto (vm, ptd, sa0, b[0], lb, icv_sz,
				    crypto_start, crypto_len + icv_sz,
				    &op->n_chunks);
	}
      else
	{
	  /* not chained */
	  op->src = op->dst = crypto_start;
	  op->len = crypto_len;
	}
    }

  if (sa0->integ_op_id)
    {
      vnet_crypto_op_t *op;
      vec_add2_aligned (integ_ops[0], op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, sa0->integ_op_id);
      op->src = payload - iv_sz - sizeof (esp_header_t);
      op->digest = payload + payload_len - icv_sz;
      op->key_index = sa0->integ_key_index;
      op->digest_len = icv_sz;
      op->len = payload_len - icv_sz + iv_sz + sizeof (esp_header_t);
      op->user_data = bi;

      if (lb != b[0])
	{
	  /* is chained */
	  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	  op->chunk_index = vec_len (ptd->chunks);
	  op->digest = vlib_buffer_get_tail (lb) - icv_sz;

	  esp_encrypt_chain_integ (vm, ptd, sa0, b[0], lb, icv_sz,
				   payload - iv_sz - sizeof (esp_header_t),
				   payload_len + iv_sz +
				   sizeof (esp_header_t), op->digest,
				   &op->n_chunks);
	}
      else if (ipsec_sa_is_set_USE_ESN (sa0))
	{
	  u32 tmp = clib_net_to_host_u32 (seq_hi);
	  clib_memcpy_fast (op->digest, &tmp, sizeof (seq_hi));
	  op->len += sizeof (seq_hi);
	}
    }
}

static_always_inline void
esp_prepare_async_frame (vlib_main_t *vm, ipsec_per_thread_data_t *ptd,
			 vnet_crypto_async_frame_t *async_frame,
			 ipsec_sa_t *sa, vlib_buffer_t *b, esp_header_t *esp,
			 u8 *payload, u32 payload_len, u8 iv_sz, u8 icv_sz,
			 u32 bi, u16 next, u32 hdr_len, u16 async_next,
			 vlib_buffer_t *lb)
{
  esp_post_data_t *post = esp_post_data (b);
  u8 *tag, *iv, *aad = 0;
  u8 flag = 0;
  u32 key_index;
  i16 crypto_start_offset, integ_start_offset;
  u16 crypto_total_len, integ_total_len;

  post->next_index = next;

  /* crypto */
  crypto_start_offset = integ_start_offset = payload - b->data;
  crypto_total_len = integ_total_len = payload_len - icv_sz;
  tag = payload + crypto_total_len;

  key_index = sa->linked_key_index;

  /* IPsec IV generation: please refer to esp_prepare_sync_op() for more
   * details */
  ASSERT (iv_sz >= sizeof (u64));
  u64 *pkt_iv = (u64 *) (payload - iv_sz);
  *pkt_iv = clib_pcg64i_random_r (&ptd->iv_prng);

  if (ipsec_sa_is_set_IS_CTR (sa))
    {
      ASSERT (sizeof (u64) == iv_sz);
      /* construct nonce in a scratch space in front of the IP header */
      esp_ctr_nonce_t *nonce = (esp_ctr_nonce_t *) (payload - sizeof (u64) -
						    hdr_len - sizeof (*nonce));
      if (ipsec_sa_is_set_IS_AEAD (sa))
	{
	  /* constuct aad in a scratch space in front of the nonce */
	  aad = (u8 *) nonce - sizeof (esp_aead_t);
	  esp_aad_fill (aad, esp, sa, sa->seq_hi);
	  key_index = sa->crypto_key_index;
	}
      else
	{
	  nonce->ctr = clib_host_to_net_u32 (1);
	}

      nonce->salt = sa->salt;
      nonce->iv = *pkt_iv;
      iv = (u8 *) nonce;
    }
  else
    {
      /* construct zero iv in front of the IP header */
      iv = payload - hdr_len - 2 * iv_sz;
      clib_memset_u8 (iv, 0, iv_sz);
      /* include iv field in crypto */
      crypto_start_offset -= iv_sz;
      crypto_total_len += iv_sz;
    }

  if (lb != b)
    {
      /* chain */
      flag |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
      tag = vlib_buffer_get_tail (lb) - icv_sz;
      crypto_total_len = esp_encrypt_chain_crypto (
	vm, ptd, sa, b, lb, icv_sz, b->data + crypto_start_offset,
	crypto_total_len + icv_sz, 0);
    }

  if (sa->integ_op_id)
    {
      integ_start_offset -= iv_sz + sizeof (esp_header_t);
      integ_total_len += iv_sz + sizeof (esp_header_t);

      if (b != lb)
	{
	  integ_total_len = esp_encrypt_chain_integ (
	    vm, ptd, sa, b, lb, icv_sz,
	    payload - iv_sz - sizeof (esp_header_t),
	    payload_len + iv_sz + sizeof (esp_header_t), tag, 0);
	}
      else if (ipsec_sa_is_set_USE_ESN (sa))
	{
	  u32 seq_hi = clib_net_to_host_u32 (sa->seq_hi);
	  clib_memcpy_fast (tag, &seq_hi, sizeof (seq_hi));
	  integ_total_len += sizeof (seq_hi);
	}
    }

  /* this always succeeds because we know the frame is not full */
  vnet_crypto_async_add_to_frame (vm, async_frame, key_index, crypto_total_len,
				  integ_total_len - crypto_total_len,
				  crypto_start_offset, integ_start_offset, bi,
				  async_next, iv, tag, aad, flag);
}

always_inline uword
esp_encrypt_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, vnet_link_t lt, int is_tun,
		    u16 async_next_node)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, vm->thread_index);
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 thread_index = vm->thread_index;
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u32 current_sa_index = ~0, current_sa_packets = 0;
  u32 current_sa_bytes = 0, spi = 0;
  u8 esp_align = 4, iv_sz = 0, icv_sz = 0;
  ipsec_sa_t *sa0 = 0;
  vlib_buffer_t *lb;
  vnet_crypto_op_t **crypto_ops = &ptd->crypto_ops;
  vnet_crypto_op_t **integ_ops = &ptd->integ_ops;
  vnet_crypto_async_frame_t *async_frames[VNET_CRYPTO_ASYNC_OP_N_IDS];
  int is_async = im->async_mode;
  vnet_crypto_async_op_id_t async_op = ~0;
  u16 drop_next =
    (lt == VNET_LINK_IP6 ? ESP_ENCRYPT_NEXT_DROP6 :
			   (lt == VNET_LINK_IP4 ? ESP_ENCRYPT_NEXT_DROP4 :
						  ESP_ENCRYPT_NEXT_DROP_MPLS));
  u16 handoff_next = (lt == VNET_LINK_IP6 ?
			ESP_ENCRYPT_NEXT_HANDOFF6 :
			(lt == VNET_LINK_IP4 ? ESP_ENCRYPT_NEXT_HANDOFF4 :
					       ESP_ENCRYPT_NEXT_HANDOFF_MPLS));
  vlib_buffer_t *sync_bufs[VLIB_FRAME_SIZE];
  u16 sync_nexts[VLIB_FRAME_SIZE], *sync_next = sync_nexts, n_sync = 0;
  u16 async_nexts[VLIB_FRAME_SIZE], *async_next = async_nexts, n_async = 0;
  u16 noop_nexts[VLIB_FRAME_SIZE], *noop_next = noop_nexts, n_noop = 0;
  u32 sync_bi[VLIB_FRAME_SIZE];
  u32 noop_bi[VLIB_FRAME_SIZE];
  esp_encrypt_error_t err;

  vlib_get_buffers (vm, from, b, n_left);

  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->integ_ops);
  vec_reset_length (ptd->chained_crypto_ops);
  vec_reset_length (ptd->chained_integ_ops);
  vec_reset_length (ptd->async_frames);
  vec_reset_length (ptd->chunks);
  clib_memset (async_frames, 0, sizeof (async_frames));

  while (n_left > 0)
    {
      u32 sa_index0;
      dpo_id_t *dpo;
      esp_header_t *esp;
      u8 *payload, *next_hdr_ptr;
      u16 payload_len, payload_len_total, n_bufs;
      u32 hdr_len;

      err = ESP_ENCRYPT_ERROR_RX_PKTS;

      if (n_left > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  clib_prefetch_load (p);
	  p -= CLIB_CACHE_LINE_BYTES;
	  clib_prefetch_load (p);
	  /* speculate that the trailer goes in the first buffer */
	  CLIB_PREFETCH (vlib_buffer_get_tail (b[1]),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	}

      if (is_tun)
	{
	  /* we are on a ipsec tunnel's feature arc */
	  vnet_buffer (b[0])->ipsec.sad_index =
	    sa_index0 = ipsec_tun_protect_get_sa_out
	    (vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);

	  if (PREDICT_FALSE (INDEX_INVALID == sa_index0))
	    {
	      err = ESP_ENCRYPT_ERROR_NO_PROTECTION;
	      esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
				  drop_next);
	      goto trace;
	    }
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

	  sa0 = ipsec_sa_get (sa_index0);

	  if (PREDICT_FALSE ((sa0->crypto_alg == IPSEC_CRYPTO_ALG_NONE &&
			      sa0->integ_alg == IPSEC_INTEG_ALG_NONE) &&
			     !ipsec_sa_is_set_NO_ALGO_NO_DROP (sa0)))
	    {
	      err = ESP_ENCRYPT_ERROR_NO_ENCRYPTION;
	      esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
				  drop_next);
	      goto trace;
	    }
	  /* fetch the second cacheline ASAP */
	  clib_prefetch_load (sa0->cacheline1);

	  current_sa_index = sa_index0;
	  spi = clib_net_to_host_u32 (sa0->spi);
	  esp_align = sa0->esp_block_align;
	  icv_sz = sa0->integ_icv_size;
	  iv_sz = sa0->crypto_iv_size;
	  is_async = im->async_mode | ipsec_sa_is_set_IS_ASYNC (sa0);
	}

      if (PREDICT_FALSE (~0 == sa0->thread_index))
	{
	  /* this is the first packet to use this SA, claim the SA
	   * for this thread. this could happen simultaneously on
	   * another thread */
	  clib_atomic_cmp_and_swap (&sa0->thread_index, ~0,
				    ipsec_sa_assign_thread (thread_index));
	}

      if (PREDICT_FALSE (thread_index != sa0->thread_index))
	{
	  vnet_buffer (b[0])->ipsec.thread_index = sa0->thread_index;
	  err = ESP_ENCRYPT_ERROR_HANDOFF;
	  esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
			      handoff_next);
	  goto trace;
	}

      lb = b[0];
      n_bufs = vlib_buffer_chain_linearize (vm, b[0]);
      if (n_bufs == 0)
	{
	  err = ESP_ENCRYPT_ERROR_NO_BUFFERS;
	  esp_set_next_index (b[0], node, err, n_noop, noop_nexts, drop_next);
	  goto trace;
	}

      if (n_bufs > 1)
	{
	  /* find last buffer in the chain */
	  while (lb->flags & VLIB_BUFFER_NEXT_PRESENT)
	    lb = vlib_get_buffer (vm, lb->next_buffer);
	}

      if (PREDICT_FALSE (esp_seq_advance (sa0)))
	{
	  err = ESP_ENCRYPT_ERROR_SEQ_CYCLED;
	  esp_set_next_index (b[0], node, err, n_noop, noop_nexts, drop_next);
	  goto trace;
	}

      /* space for IV */
      hdr_len = iv_sz;

      if (ipsec_sa_is_set_IS_TUNNEL (sa0))
	{
	  payload = vlib_buffer_get_current (b[0]);
	  next_hdr_ptr = esp_add_footer_and_icv (
	    vm, &lb, esp_align, icv_sz, node, buffer_data_size,
	    vlib_buffer_length_in_chain (vm, b[0]));
	  if (!next_hdr_ptr)
	    {
	      err = ESP_ENCRYPT_ERROR_NO_BUFFERS;
	      esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
				  drop_next);
	      goto trace;
	    }
	  b[0]->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  payload_len = b[0]->current_length;
	  payload_len_total = vlib_buffer_length_in_chain (vm, b[0]);

	  /* ESP header */
	  hdr_len += sizeof (*esp);
	  esp = (esp_header_t *) (payload - hdr_len);

	  /* optional UDP header */
	  if (ipsec_sa_is_set_UDP_ENCAP (sa0))
	    {
	      hdr_len += sizeof (udp_header_t);
	      esp_fill_udp_hdr (sa0, (udp_header_t *) (payload - hdr_len),
				payload_len_total + hdr_len);
	    }

	  /* IP header */
	  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa0))
	    {
	      ip6_header_t *ip6;
	      u16 len = sizeof (ip6_header_t);
	      hdr_len += len;
	      ip6 = (ip6_header_t *) (payload - hdr_len);
	      clib_memcpy_fast (ip6, &sa0->ip6_hdr, sizeof (ip6_header_t));

	      if (VNET_LINK_IP6 == lt)
		{
		  *next_hdr_ptr = IP_PROTOCOL_IPV6;
		  tunnel_encap_fixup_6o6 (sa0->tunnel_flags,
					  (const ip6_header_t *) payload,
					  ip6);
		}
	      else if (VNET_LINK_IP4 == lt)
		{
		  *next_hdr_ptr = IP_PROTOCOL_IP_IN_IP;
		  tunnel_encap_fixup_4o6 (sa0->tunnel_flags, b[0],
					  (const ip4_header_t *) payload, ip6);
		}
	      else if (VNET_LINK_MPLS == lt)
		{
		  *next_hdr_ptr = IP_PROTOCOL_MPLS_IN_IP;
		  tunnel_encap_fixup_mplso6 (
		    sa0->tunnel_flags, b[0],
		    (const mpls_unicast_header_t *) payload, ip6);
		}
	      else
		ASSERT (0);

	      len = payload_len_total + hdr_len - len;
	      ip6->payload_length = clib_net_to_host_u16 (len);
	      b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }
	  else
	    {
	      ip4_header_t *ip4;
	      u16 len = sizeof (ip4_header_t);
	      hdr_len += len;
	      ip4 = (ip4_header_t *) (payload - hdr_len);
	      clib_memcpy_fast (ip4, &sa0->ip4_hdr, sizeof (ip4_header_t));

	      if (VNET_LINK_IP6 == lt)
		{
		  *next_hdr_ptr = IP_PROTOCOL_IPV6;
		  tunnel_encap_fixup_6o4_w_chksum (sa0->tunnel_flags,
						   (const ip6_header_t *)
						   payload, ip4);
		}
	      else if (VNET_LINK_IP4 == lt)
		{
		  *next_hdr_ptr = IP_PROTOCOL_IP_IN_IP;
		  tunnel_encap_fixup_4o4_w_chksum (sa0->tunnel_flags,
						   (const ip4_header_t *)
						   payload, ip4);
		}
	      else if (VNET_LINK_MPLS == lt)
		{
		  *next_hdr_ptr = IP_PROTOCOL_MPLS_IN_IP;
		  tunnel_encap_fixup_mplso4_w_chksum (
		    sa0->tunnel_flags, (const mpls_unicast_header_t *) payload,
		    ip4);
		}
	      else
		ASSERT (0);

	      len = payload_len_total + hdr_len;
	      esp_update_ip4_hdr (ip4, len, /* is_transport */ 0, 0);
	    }

	  dpo = &sa0->dpo;
	  if (!is_tun)
	    {
	      sync_next[0] = dpo->dpoi_next_node;
	      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo->dpoi_index;
	    }
	  else
	    sync_next[0] = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	  b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	}
      else			/* transport mode */
	{
	  u8 *l2_hdr, l2_len, *ip_hdr;
	  u16 ip_len;
	  ip6_ext_header_t *ext_hdr;
	  udp_header_t *udp = 0;
	  u16 udp_len = 0;
	  u8 *old_ip_hdr = vlib_buffer_get_current (b[0]);

	  /*
	   * Get extension header chain length. It might be longer than the
	   * buffer's pre_data area.
	   */
	  ip_len =
	    (VNET_LINK_IP6 == lt ?
	       esp_get_ip6_hdr_len ((ip6_header_t *) old_ip_hdr, &ext_hdr) :
	       ip4_header_bytes ((ip4_header_t *) old_ip_hdr));
	  if ((old_ip_hdr - ip_len) < &b[0]->pre_data[0])
	    {
	      err = ESP_ENCRYPT_ERROR_NO_BUFFERS;
	      esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
				  drop_next);
	      goto trace;
	    }

	  vlib_buffer_advance (b[0], ip_len);
	  payload = vlib_buffer_get_current (b[0]);
	  next_hdr_ptr = esp_add_footer_and_icv (
	    vm, &lb, esp_align, icv_sz, node, buffer_data_size,
	    vlib_buffer_length_in_chain (vm, b[0]));
	  if (!next_hdr_ptr)
	    {
	      err = ESP_ENCRYPT_ERROR_NO_BUFFERS;
	      esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
				  drop_next);
	      goto trace;
	    }

	  b[0]->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  payload_len = b[0]->current_length;
	  payload_len_total = vlib_buffer_length_in_chain (vm, b[0]);

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

	  if (VNET_LINK_IP6 == lt)
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
		clib_host_to_net_u16 (payload_len_total + hdr_len - l2_len -
				      sizeof (ip6_header_t));
	    }
	  else if (VNET_LINK_IP4 == lt)
	    {
	      u16 len;
	      ip4_header_t *ip4 = (ip4_header_t *) (old_ip_hdr);
	      *next_hdr_ptr = ip4->protocol;
	      len = payload_len_total + hdr_len - l2_len;
	      if (udp)
		{
		  esp_update_ip4_hdr (ip4, len, /* is_transport */ 1, 1);
		  udp_len = len - ip_len;
		}
	      else
		esp_update_ip4_hdr (ip4, len, /* is_transport */ 1, 0);
	    }

	  clib_memcpy_le64 (ip_hdr, old_ip_hdr, ip_len);

	  if (udp)
	    {
	      esp_fill_udp_hdr (sa0, udp, udp_len);
	    }

	  sync_next[0] = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	}

      if (lb != b[0])
	{
	  crypto_ops = &ptd->chained_crypto_ops;
	  integ_ops = &ptd->chained_integ_ops;
	}
      else
	{
	  crypto_ops = &ptd->crypto_ops;
	  integ_ops = &ptd->integ_ops;
	}

      esp->spi = spi;
      esp->seq = clib_net_to_host_u32 (sa0->seq);

      if (is_async)
	{
	  async_op = sa0->crypto_async_enc_op_id;

	  /* get a frame for this op if we don't yet have one or it's full
	   */
	  if (NULL == async_frames[async_op] ||
	      vnet_crypto_async_frame_is_full (async_frames[async_op]))
	    {
	      async_frames[async_op] =
		vnet_crypto_async_get_frame (vm, async_op);
	      /* Save the frame to the list we'll submit at the end */
	      vec_add1 (ptd->async_frames, async_frames[async_op]);
	    }

	  esp_prepare_async_frame (vm, ptd, async_frames[async_op], sa0, b[0],
				   esp, payload, payload_len, iv_sz, icv_sz,
				   from[b - bufs], sync_next[0], hdr_len,
				   async_next_node, lb);
	}
      else
	esp_prepare_sync_op (vm, ptd, crypto_ops, integ_ops, sa0, sa0->seq_hi,
			     payload, payload_len, iv_sz, icv_sz, n_sync, b,
			     lb, hdr_len, esp);

      vlib_buffer_advance (b[0], 0LL - hdr_len);

      current_sa_packets += 1;
      current_sa_bytes += payload_len_total;

    trace:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_encrypt_trace_t *tr = vlib_add_trace (vm, node, b[0],
						    sizeof (*tr));
	  if (INDEX_INVALID == sa_index0)
	    clib_memset_u8 (tr, 0xff, sizeof (*tr));
	  else
	    {
	      tr->sa_index = sa_index0;
	      tr->spi = sa0->spi;
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq;
	      tr->sa_seq_hi = sa0->seq_hi;
	      tr->udp_encap = ipsec_sa_is_set_UDP_ENCAP (sa0);
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }
	}

      /* next */
      if (ESP_ENCRYPT_ERROR_RX_PKTS != err)
	{
	  noop_bi[n_noop] = from[b - bufs];
	  n_noop++;
	  noop_next++;
	}
      else if (!is_async)
	{
	  sync_bi[n_sync] = from[b - bufs];
	  sync_bufs[n_sync] = b[0];
	  n_sync++;
	  sync_next++;
	}
      else
	{
	  n_async++;
	  async_next++;
	}
      n_left -= 1;
      b += 1;
    }

  if (INDEX_INVALID != current_sa_index)
    vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				     current_sa_index, current_sa_packets,
				     current_sa_bytes);
  if (n_sync)
    {
      esp_process_ops (vm, node, ptd->crypto_ops, sync_bufs, sync_nexts,
		       drop_next);
      esp_process_chained_ops (vm, node, ptd->chained_crypto_ops, sync_bufs,
			       sync_nexts, ptd->chunks, drop_next);

      esp_process_ops (vm, node, ptd->integ_ops, sync_bufs, sync_nexts,
		       drop_next);
      esp_process_chained_ops (vm, node, ptd->chained_integ_ops, sync_bufs,
			       sync_nexts, ptd->chunks, drop_next);

      vlib_buffer_enqueue_to_next (vm, node, sync_bi, sync_nexts, n_sync);
    }
  if (n_async)
    {
      /* submit all of the open frames */
      vnet_crypto_async_frame_t **async_frame;

      vec_foreach (async_frame, ptd->async_frames)
	{
	  if (vnet_crypto_async_submit_open_frame (vm, *async_frame) < 0)
	    {
	      n_noop += esp_async_recycle_failed_submit (
		vm, *async_frame, node, ESP_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR,
		n_noop, noop_bi, noop_nexts, drop_next);
	      vnet_crypto_async_reset_frame (*async_frame);
	      vnet_crypto_async_free_frame (vm, *async_frame);
	    }
	}
    }
  if (n_noop)
    vlib_buffer_enqueue_to_next (vm, node, noop_bi, noop_nexts, n_noop);

  vlib_node_increment_counter (vm, node->node_index, ESP_ENCRYPT_ERROR_RX_PKTS,
			       frame->n_vectors);

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

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      esp_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[0],
							     sizeof (*tr));
	      tr->next_index = next[0];
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      esp_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[1],
							     sizeof (*tr));
	      tr->next_index = next[1];
	    }
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      esp_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[2],
							     sizeof (*tr));
	      tr->next_index = next[2];
	    }
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      esp_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[3],
							     sizeof (*tr));
	      tr->next_index = next[3];
	    }
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      next[0] = (esp_post_data (b[0]))->next_index;
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_encrypt_post_trace_t *tr = vlib_add_trace (vm, node, b[0],
							 sizeof (*tr));
	  tr->next_index = next[0];
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       ESP_ENCRYPT_ERROR_POST_RX_PKTS,
			       frame->n_vectors);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (esp4_encrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_encrypt_inline (vm, node, from_frame, VNET_LINK_IP4, 0,
			     esp_encrypt_async_next.esp4_post_next);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_encrypt_node) = {
  .name = "esp4-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = { [ESP_ENCRYPT_NEXT_DROP4] = "ip4-drop",
		  [ESP_ENCRYPT_NEXT_DROP6] = "ip6-drop",
		  [ESP_ENCRYPT_NEXT_DROP_MPLS] = "mpls-drop",
		  [ESP_ENCRYPT_NEXT_HANDOFF4] = "esp4-encrypt-handoff",
		  [ESP_ENCRYPT_NEXT_HANDOFF6] = "esp6-encrypt-handoff",
		  [ESP_ENCRYPT_NEXT_HANDOFF_MPLS] = "error-drop",
		  [ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "interface-output" },
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
  .format_trace = format_esp_post_encrypt_trace,
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
  return esp_encrypt_inline (vm, node, from_frame, VNET_LINK_IP6, 0,
			     esp_encrypt_async_next.esp6_post_next);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_encrypt_node) = {
  .name = "esp6-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp4-encrypt",

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
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
  .format_trace = format_esp_post_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp4-encrypt",

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp4_encrypt_tun_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return esp_encrypt_inline (vm, node, from_frame, VNET_LINK_IP4, 1,
			     esp_encrypt_async_next.esp4_tun_post_next);
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
    [ESP_ENCRYPT_NEXT_DROP4] = "ip4-drop",
    [ESP_ENCRYPT_NEXT_DROP6] = "ip6-drop",
    [ESP_ENCRYPT_NEXT_DROP_MPLS] = "mpls-drop",
    [ESP_ENCRYPT_NEXT_HANDOFF4] = "esp4-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_HANDOFF6] = "esp6-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_HANDOFF_MPLS] = "esp-mpls-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
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
  .format_trace = format_esp_post_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp4-encrypt-tun",

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp6_encrypt_tun_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return esp_encrypt_inline (vm, node, from_frame, VNET_LINK_IP6, 1,
			     esp_encrypt_async_next.esp6_tun_post_next);
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
    [ESP_ENCRYPT_NEXT_DROP4] = "ip4-drop",
    [ESP_ENCRYPT_NEXT_DROP6] = "ip6-drop",
    [ESP_ENCRYPT_NEXT_DROP_MPLS] = "mpls-drop",
    [ESP_ENCRYPT_NEXT_HANDOFF4] = "esp4-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_HANDOFF6] = "esp6-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_HANDOFF_MPLS] = "esp-mpls-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
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
  .format_trace = format_esp_post_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp-mpls-encrypt-tun",

  .n_errors = ARRAY_LEN (esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp_mpls_encrypt_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return esp_encrypt_inline (vm, node, from_frame, VNET_LINK_MPLS, 1,
			     esp_encrypt_async_next.esp_mpls_tun_post_next);
}

VLIB_REGISTER_NODE (esp_mpls_encrypt_tun_node) = {
  .name = "esp-mpls-encrypt-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
    [ESP_ENCRYPT_NEXT_DROP4] = "ip4-drop",
    [ESP_ENCRYPT_NEXT_DROP6] = "ip6-drop",
    [ESP_ENCRYPT_NEXT_DROP_MPLS] = "mpls-drop",
    [ESP_ENCRYPT_NEXT_HANDOFF4] = "esp4-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_HANDOFF6] = "esp6-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_HANDOFF_MPLS] = "esp-mpls-encrypt-tun-handoff",
    [ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
  },
};

VLIB_NODE_FN (esp_mpls_encrypt_tun_post_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return esp_encrypt_post_inline (vm, node, from_frame);
}

VLIB_REGISTER_NODE (esp_mpls_encrypt_tun_post_node) = {
  .name = "esp-mpls-encrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_post_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "esp-mpls-encrypt-tun",

  .n_errors = ARRAY_LEN (esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
};

#ifndef CLIB_MARCH_VARIANT

static clib_error_t *
esp_encrypt_init (vlib_main_t *vm)
{
  ipsec_main_t *im = &ipsec_main;

  im->esp4_enc_fq_index =
    vlib_frame_queue_main_init (esp4_encrypt_node.index, 0);
  im->esp6_enc_fq_index =
    vlib_frame_queue_main_init (esp6_encrypt_node.index, 0);
  im->esp4_enc_tun_fq_index =
    vlib_frame_queue_main_init (esp4_encrypt_tun_node.index, 0);
  im->esp6_enc_tun_fq_index =
    vlib_frame_queue_main_init (esp6_encrypt_tun_node.index, 0);
  im->esp_mpls_enc_tun_fq_index =
    vlib_frame_queue_main_init (esp_mpls_encrypt_tun_node.index, 0);

  return 0;
}

VLIB_INIT_FUNCTION (esp_encrypt_init);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
