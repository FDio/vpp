/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2026 Cisco and/or its affiliates.
 */

/* esp_decrypt.c : IPSec ESP decrypt node */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ipsec_io.h>
#include <vnet/ipsec/ipsec_tun.h>

#include <vnet/gre/packet.h>

#define foreach_esp_decrypt_next                                                                   \
  _ (DROP, "error-drop")                                                                           \
  _ (IP4_INPUT, "ip4-input-no-checksum")                                                           \
  _ (IP6_INPUT, "ip6-input")                                                                       \
  _ (L2_INPUT, "l2-input")                                                                         \
  _ (MPLS_INPUT, "mpls-input")                                                                     \
  _ (CRYPTO_ENQ, "crypto-enq")                                                                     \
  _ (HANDOFF, "handoff")

#define _(v, s) ESP_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_decrypt_next
#undef _
    ESP_DECRYPT_N_NEXT,
} esp_decrypt_next_t;

#define foreach_esp_decrypt_post_next                                         \
  _ (DROP, "error-drop")                                                      \
  _ (IP4_INPUT, "ip4-input-no-checksum")                                      \
  _ (IP6_INPUT, "ip6-input")                                                  \
  _ (MPLS_INPUT, "mpls-input")                                                \
  _ (L2_INPUT, "l2-input")

#define _(v, s) ESP_DECRYPT_POST_NEXT_##v,
typedef enum
{
  foreach_esp_decrypt_post_next
#undef _
    ESP_DECRYPT_POST_N_NEXT,
} esp_decrypt_post_next_t;

typedef vl_counter_esp_decrypt_enum_t esp_decrypt_error_t;

/* The number of bytes in the hi sequence number */
#define N_HI_ESN_BYTES 4

#define ESP_ENCRYPT_PD_F_FD_TRANSPORT (1 << 2)

static_always_inline void
esp_process_ops (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_crypto_op_t *ops,
		 vlib_buffer_t *b[], u16 *nexts, vnet_crypto_op_chunk_t *chunks, int e)
{

  vnet_crypto_op_t *op = ops;
  u32 n_fail, n_ops = vec_len (ops);

  if (PREDICT_TRUE (n_ops == 0))
    return;

  n_fail = n_ops - vnet_crypto_process_ops (vm, op, chunks, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);
      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 err, bi = op->user_data;
	  if (op->status == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	    err = op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK ?
		    ESP_DECRYPT_ERROR_INTEG_ERROR :
		    e;
	  else
	    err = ESP_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR;
	  esp_decrypt_set_next_index (b[bi], node, vm->thread_index, err, bi,
				      nexts, ESP_DECRYPT_NEXT_DROP,
				      vnet_buffer (b[bi])->ipsec.sad_index);
	  n_fail--;
	}
      op++;
    }
}

always_inline void
esp_remove_tail (vlib_main_t * vm, vlib_buffer_t * b, vlib_buffer_t * last,
		 u16 tail)
{
  vlib_buffer_t *before_last = b;

  if (b != last)
    b->total_length_not_including_first_buffer -= tail;

  if (last->current_length >= tail)
    {
      last->current_length -= tail;
      return;
    }
  ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);

  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      before_last = b;
      b = vlib_get_buffer (vm, b->next_buffer);
    }
  before_last->current_length -= tail - last->current_length;
  vlib_buffer_free_one (vm, before_last->next_buffer);
  before_last->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
}

always_inline void
esp_remove_tail_and_tfc_padding (vlib_main_t *vm, vlib_node_runtime_t *node,
				 const esp_decrypt_packet_data_t *pd,
				 vlib_buffer_t *b, vlib_buffer_t *last,
				 u16 *next, u16 tail, int is_ip6)
{
  const u16 total_buffer_length = vlib_buffer_length_in_chain (vm, b);
  u16 ip_packet_length;
  if (is_ip6)
    {
      const ip6_header_t *ip6 = vlib_buffer_get_current (b);
      ip_packet_length =
	clib_net_to_host_u16 (ip6->payload_length) + sizeof (ip6_header_t);
    }
  else
    {
      const ip4_header_t *ip4 = vlib_buffer_get_current (b);
      ip_packet_length = clib_net_to_host_u16 (ip4->length);
    }
  /* In case of TFC padding, the size of the buffer data needs to be adjusted
   * to the ip packet length */
  if (PREDICT_FALSE (total_buffer_length < ip_packet_length + tail))
    {
      esp_decrypt_set_next_index (b, node, vm->thread_index,
				  ESP_DECRYPT_ERROR_NO_TAIL_SPACE, 0, next,
				  ESP_DECRYPT_NEXT_DROP, pd->sa_index);
      return;
    }
  esp_remove_tail (vm, b, last, total_buffer_length - ip_packet_length);
}

/*
 * The decrypt path wants a stable tail layout before it starts touching
 * ICV/ESN data. Chained packets may end with a short last buffer, which makes
 * the final trailer bytes straddle the buffer boundary and forces the rest of
 * the code to carry split-tail special cases.
 *
 * Normalize that once here:
 * - ensure the last 32 bytes are contiguous in the last buffer
 * - ensure there is enough tailroom in that same buffer for any extra bytes
 *   we need to stage there
 *
 * The packet byte stream is preserved; only the buffer partitioning changes.
 */

#define ESP_DECRYPT_NORMALIZE_SIZE 32

static_always_inline vlib_buffer_t *
esp_buffer_normalize (vlib_main_t *vm, vlib_buffer_t *first, u16 n_bytes)
{
  const u32 sz = ESP_DECRYPT_NORMALIZE_SIZE;
  vlib_buffer_t *before_last = first;
  vlib_buffer_t *bp = first;
  vlib_buffer_t *lb;
  vlib_buffer_t *tmp_b;
  u32 tmp_bi = 0;
  u16 n_from_prev;

  while (bp->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      before_last = bp;
      bp = vlib_get_buffer (vm, bp->next_buffer);
    }
  lb = bp;

  if (lb == first)
    ASSERT (lb->current_length >= sz);
  else if (lb->current_length < sz)
    {
      n_from_prev = sz - lb->current_length;
      ASSERT (before_last->current_length >= n_from_prev);
      lb->current_data -= n_from_prev;
      lb->current_length += n_from_prev;
      clib_memcpy_fast (vlib_buffer_get_current (lb),
			vlib_buffer_get_tail (before_last) - n_from_prev, n_from_prev);
      before_last->current_length -= n_from_prev;
      if (before_last == first)
	first->total_length_not_including_first_buffer += n_from_prev;
    }

  if (vlib_buffer_space_left_at_end (vm, lb) >= n_bytes)
    return lb;

  ASSERT (lb->current_length >= sz);
  if (vlib_buffer_alloc (vm, &tmp_bi, 1) != 1)
    return 0;
  tmp_b = vlib_get_buffer (vm, tmp_bi);
  clib_memcpy_fast (tmp_b->data, vlib_buffer_get_tail (lb) - sz, sz);
  tmp_b->current_length = sz;
  lb->current_length -= sz;
  if (lb == first)
    first->total_length_not_including_first_buffer += sz;
  lb->next_buffer = tmp_bi;
  lb->flags |= VLIB_BUFFER_NEXT_PRESENT;
  return tmp_b;
}

static_always_inline u16
esp_insert_esn (ipsec_sa_inb_rt_t *irt, esp_decrypt_packet_data_t *pd, u32 *data_len, u8 **digest,
		u16 *len, u8 *payload)
{
  if (!irt->use_esn)
    return 0;
  /* shift ICV by 4 bytes to insert ESN */
  u32 seq_hi = clib_host_to_net_u32 (pd->seq_hi);
  u8 tmp[ESP_MAX_ICV_SIZE];

  clib_memcpy_fast (tmp, payload + len[0], ESP_MAX_ICV_SIZE);
  clib_memcpy_fast (payload + len[0], &seq_hi, N_HI_ESN_BYTES);
  clib_memcpy_fast (payload + len[0] + N_HI_ESN_BYTES, tmp, ESP_MAX_ICV_SIZE);
  *data_len += N_HI_ESN_BYTES;
  *digest += N_HI_ESN_BYTES;
  return N_HI_ESN_BYTES;
}

static_always_inline int
esp_decrypt_chain_integ (vlib_main_t *vm, ipsec_per_thread_data_t *ptd,
			 const esp_decrypt_packet_data_t *pd, ipsec_sa_inb_rt_t *irt,
			 vlib_buffer_t *b, u8 icv_sz, u8 *start_src, u32 start_len, u8 **digest,
			 u16 *n_ch, u32 *integ_total_len)
{
  vnet_crypto_op_chunk_t *ch;
  vlib_buffer_t *cb = vlib_get_buffer (vm, b->next_buffer);
  u16 n_chunks = 1;
  u32 total_len;
  vec_add2 (ptd->chunks, ch, 1);
  total_len = ch->len = start_len;
  ch->src = start_src;

  while (1)
    {
      vec_add2 (ptd->chunks, ch, 1);
      n_chunks += 1;
      ch->src = vlib_buffer_get_current (cb);
      if (pd->lb == cb)
	{
	  ch->len = cb->current_length - icv_sz;
	  if (irt->use_esn)
	    {
	      u32 seq_hi = clib_host_to_net_u32 (pd->seq_hi);
	      u8 tmp[ESP_MAX_ICV_SIZE];

	      ASSERT (vlib_buffer_space_left_at_end (vm, pd->lb) >= N_HI_ESN_BYTES);
	      clib_memcpy_fast (tmp, *digest, ESP_MAX_ICV_SIZE);
	      clib_memcpy_fast (*digest, &seq_hi, N_HI_ESN_BYTES);
	      clib_memcpy_fast (*digest + N_HI_ESN_BYTES, tmp, ESP_MAX_ICV_SIZE);
	      *digest += N_HI_ESN_BYTES;
	      ch->len += N_HI_ESN_BYTES;
	    }
	  total_len += ch->len;
	  break;
	}
      else
	total_len += ch->len = cb->current_length;

      if (!(cb->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;

      cb = vlib_get_buffer (vm, cb->next_buffer);
    }

  if (n_ch)
    *n_ch = n_chunks;
  if (integ_total_len)
    *integ_total_len = total_len;

  return 0;
}

static_always_inline u32
esp_decrypt_chain_crypto (vlib_main_t *vm, ipsec_per_thread_data_t *ptd,
			  esp_decrypt_packet_data_t *pd, ipsec_sa_inb_rt_t *irt, vlib_buffer_t *b,
			  u8 icv_sz, u8 *start, u32 start_len, u8 **tag, u16 *n_ch)
{
  vnet_crypto_op_chunk_t *ch;
  vlib_buffer_t *cb = b;
  u16 n_chunks = 1;
  u32 total_len;
  vec_add2 (ptd->chunks, ch, 1);
  total_len = ch->len = start_len;
  ch->src = ch->dst = start;
  cb = vlib_get_buffer (vm, cb->next_buffer);
  n_chunks = 1;

  while (1)
    {
      vec_add2 (ptd->chunks, ch, 1);
      n_chunks += 1;
      ch->src = ch->dst = vlib_buffer_get_current (cb);
      if (pd->lb == cb)
	{
	  if (irt->is_aead)
	    *tag = vlib_buffer_get_tail (pd->lb) - icv_sz;

	  total_len += ch->len = cb->current_length - icv_sz;
	}
      else
	total_len += ch->len = cb->current_length;

      if (!(cb->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;

      cb = vlib_get_buffer (vm, cb->next_buffer);
    }

  if (n_ch)
    *n_ch = n_chunks;

  return total_len;
}

static_always_inline esp_decrypt_error_t
esp_decrypt_prepare_sync_op (vlib_main_t *vm, ipsec_per_thread_data_t *ptd, ipsec_sa_inb_rt_t *irt,
			     u8 *payload, u16 len, u8 icv_sz, u8 iv_sz,
			     esp_decrypt_packet_data_t *pd, vlib_buffer_t *b, u32 index)
{
  vnet_crypto_op_t **ops;
  vnet_crypto_op_t _op, *op = &_op;
  const u8 esp_sz = sizeof (esp_header_t);
  const vnet_crypto_op_t *tmpl = &irt->op_tmpl;

  if (!irt->ctx)
    return ESP_DECRYPT_ERROR_RX_PKTS;

  *op = *tmpl;
  op->user_data = index;

  if (irt->integ_icv_size && !irt->is_aead)
    {
      u32 integ_len = len;
      ops = &ptd->crypto_ops;

      if (pd->is_chain)
	{
	  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	  ops = &ptd->chained_crypto_ops;
	  integ_len = b->current_length;
	}

      op->flags = VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
      op->auth = payload + len;
      op->auth_src = payload;

      if (pd->is_chain)
	{
	  op->auth = vlib_buffer_get_tail (pd->lb) - icv_sz;

	  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	  op->auth_chunk_index = vec_len (ptd->chunks);
	  if (esp_decrypt_chain_integ (vm, ptd, pd, irt, b, icv_sz, payload, b->current_length,
				       &op->auth, &op->auth_n_chunks, 0) < 0)
	    return ESP_DECRYPT_ERROR_NO_BUFFERS;
	}
      else
	{
	  esp_insert_esn (irt, pd, &integ_len, &op->auth, &len, payload);
	  op->auth_src_len = (u16) integ_len;
	}

      if (!irt->cipher_iv_size)
	{
	  vec_add_aligned (*ops, op, 1, CLIB_CACHE_LINE_BYTES);
	  return ESP_DECRYPT_ERROR_RX_PKTS;
	}
    }
  if (irt->cipher_iv_size)
    {
      op->iv = payload + esp_sz;

      payload += esp_sz;
      len -= esp_sz;

      if (irt->is_ctr)
	{
	  /* construct nonce in a scratch space in front of the IP header */
	  esp_ctr_nonce_t *nonce =
	    (esp_ctr_nonce_t *) (payload - esp_sz - pd->hdr_sz -
				 sizeof (*nonce));
	  if (irt->is_aead)
	    {
	      /* constuct aad in a scratch space in front of the nonce */
	      esp_header_t *esp0 = (esp_header_t *) (payload - esp_sz);
	      op->aad = (u8 *) nonce - sizeof (esp_aead_t);
	      esp_aad_fill (op->aad, esp0, irt->use_esn, pd->seq_hi);
	      op->auth = payload + len;
	      if (PREDICT_FALSE (irt->is_null_gmac))
		{
		  /* RFC-4543 ENCR_NULL_AUTH_AES_GMAC: IV is part of AAD */
		  payload -= iv_sz;
		  len += iv_sz;
		}
	    }
	  else
	    {
	      nonce->ctr = clib_host_to_net_u32 (1);
	    }
	  nonce->salt = irt->salt;
	  ASSERT (sizeof (u64) == iv_sz);
	  nonce->iv = *(u64 *) op->iv;
	  op->iv = (u8 *) nonce;
	}

      payload += iv_sz;

      if (pd->is_chain && (pd->lb != b))
	{
	  /* buffer is chained */
	  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	  op->chunk_index = vec_len (ptd->chunks);
	  esp_decrypt_chain_crypto (vm, ptd, pd, irt, b, icv_sz, payload, len - iv_sz + icv_sz,
				    &op->auth, &op->n_chunks);
	  ops = &ptd->chained_crypto_ops;
	}
      else
	{
	  op->src = op->dst = payload;
	  op->len = len - iv_sz;
	  op->user_data = index;
	  ops = &ptd->crypto_ops;
	}

      vec_add_aligned (*ops, op, 1, CLIB_CACHE_LINE_BYTES);
    }

  return ESP_DECRYPT_ERROR_RX_PKTS;
}

static_always_inline esp_decrypt_error_t
esp_decrypt_prepare_async_frame (vlib_main_t *vm, ipsec_per_thread_data_t *ptd,
				 ipsec_sa_inb_rt_t *irt, u8 *payload, u16 len, u8 icv_sz, u8 iv_sz,
				 esp_decrypt_packet_data_t *pd, u32 bi, vlib_buffer_t *b,
				 u16 async_next)
{
  const u8 esp_sz = sizeof (esp_header_t);
  esp_decrypt_packet_data_t *async_pd = &(esp_post_data (b))->decrypt_data;
  u8 *tag = payload + len, *iv = payload + esp_sz, *aad = 0;
  u8 *current = vlib_buffer_get_current (b);
  u32 crypto_len, integ_len = 0;
  i16 crypto_start_offset, integ_start_offset = 0;
  i16 iv_off, aad_off = 0;

  if (!irt->is_aead)
    {
      /* combined algs */
      integ_start_offset = payload - b->data;
      integ_len = len;

      if (pd->is_chain)
	{
	  /* buffer is chained */
	  integ_len = b->current_length;
	  tag = vlib_buffer_get_tail (pd->lb) - icv_sz;

	  if (esp_decrypt_chain_integ (vm, ptd, pd, irt, b, icv_sz, payload, b->current_length,
				       &tag, 0, &integ_len) < 0)
	    {
	      /* allocate buffer failed, will not add to frame and drop */
	      return (ESP_DECRYPT_ERROR_NO_BUFFERS);
	    }
	}
      else
	esp_insert_esn (irt, pd, &integ_len, &tag, &len, payload);
    }

  /* crypto */
  payload += esp_sz;
  len -= esp_sz;
  iv = payload;
  iv_off = payload - current;

  if (irt->is_ctr)
    {
      iv_off = payload - current - esp_sz - pd->hdr_sz - sizeof (esp_ctr_nonce_t);
      /* construct nonce in a scratch space in front of the IP header */
      esp_ctr_nonce_t *nonce =
	(esp_ctr_nonce_t *) (payload - esp_sz - pd->hdr_sz - sizeof (*nonce));
      if (irt->is_aead)
	{
	  /* constuct aad in a scratch space in front of the nonce */
	  esp_header_t *esp0 = (esp_header_t *) (payload - esp_sz);
	  aad = (u8 *) nonce - sizeof (esp_aead_t);
	  aad_off = iv_off - sizeof (esp_aead_t);
	  esp_aad_fill (aad, esp0, irt->use_esn, pd->seq_hi);
	  tag = payload + len;
	  if (PREDICT_FALSE (irt->is_null_gmac))
	    {
	      /* RFC-4543 ENCR_NULL_AUTH_AES_GMAC: IV is part of AAD */
	      payload -= iv_sz;
	      len += iv_sz;
	    }
	}
      else
	{
	  nonce->ctr = clib_host_to_net_u32 (1);
	}
      nonce->salt = irt->salt;
      ASSERT (sizeof (u64) == iv_sz);
      nonce->iv = *(u64 *) iv;
      iv = (u8 *) nonce;
    }

  crypto_start_offset = (payload += iv_sz) - b->data;
  crypto_len = len - iv_sz;

  if (pd->is_chain && (pd->lb != b))
    {
      /* buffer is chained */
      crypto_len = esp_decrypt_chain_crypto (vm, ptd, pd, irt, b, icv_sz, payload,
					     len - iv_sz + icv_sz, &tag, 0);
    }

  *async_pd = *pd;

  vnet_crypto_buffer_metadata_t md = irt->async_op_data_tmpl;

  md.cipher_data_len = crypto_len;
  md.auth_data_len = integ_len;
  md.cipher_data_start_off = crypto_start_offset - b->current_data;
  md.auth_data_start_off = integ_start_offset - b->current_data;
  md.iv_off = iv_off;
  md.icv_off = irt->is_aead ? crypto_start_offset - b->current_data + crypto_len :
			      integ_start_offset - b->current_data + integ_len;
  md.aad_off = aad_off;
  md.is_chained_buffers = pd->is_chain;
  *vnet_crypto_buffer_get_metadata (b) = md;

  return (ESP_DECRYPT_ERROR_RX_PKTS);
}

static_always_inline void
esp_decrypt_post_crypto (vlib_main_t *vm, vlib_node_runtime_t *node, const u16 *next_by_next_header,
			 const esp_decrypt_packet_data_t *pd, vlib_buffer_t *b, u16 *next,
			 int is_ip6, int is_tun, int is_async)
{
  ipsec_sa_inb_rt_t *irt = ipsec_sa_get_inb_rt_by_index (pd->sa_index);
  vlib_buffer_t *lb = b;
  u8 pad_length = 0, next_header = 0;
  u16 icv_sz;
  u16 tail_adjust = 0;
  u16 tail_base = irt->tail_base;
  i16 current_data = b->current_data;
  i16 current_length = b->current_length;
  u64 n_lost;

  /*
   * redo the anti-reply check
   * in this frame say we have sequence numbers, s, s+1, s+1, s+1
   * and s and s+1 are in the window. When we did the anti-replay
   * check above we did so against the state of the window (W),
   * after packet s-1. So each of the packets in the sequence will be
   * accepted.
   * This time s will be cheked against Ws-1, s+1 checked against Ws
   * (i.e. the window state is updated/advanced)
   * so this time the successive s+1 packet will be dropped.
   * This is a consequence of batching the decrypts. If the
   * check-decrypt-advance process was done for each packet it would
   * be fine. But we batch the decrypts because it's much more efficient
   * to do so in SW and if we offload to HW and the process is async.
   *
   * You're probably thinking, but this means an attacker can send the
   * above sequence and cause VPP to perform decrypts that will fail,
   * and that's true. But if the attacker can determine s (a valid
   * sequence number in the window) which is non-trivial, it can generate
   * a sequence s, s+1, s+2, s+3, ... s+n and nothing will prevent any
   * implementation, sequential or batching, from decrypting these.
   */
  if (ipsec_sa_anti_replay_and_sn_advance (irt, pd->seq, pd->seq_hi, true,
					   NULL))
    {
      esp_decrypt_set_next_index (b, node, vm->thread_index,
				  ESP_DECRYPT_ERROR_REPLAY, 0, next,
				  ESP_DECRYPT_NEXT_DROP, pd->sa_index);
      return;
    }
  n_lost =
    ipsec_sa_anti_replay_advance (irt, vm->thread_index, pd->seq, pd->seq_hi);

  vlib_prefetch_simple_counter (&ipsec_sa_err_counters[IPSEC_SA_ERROR_LOST],
				vm->thread_index, pd->sa_index);

  if (pd->is_chain)
    {
      lb = pd->lb;
      icv_sz = irt->integ_icv_size;
      if (lb->current_length < sizeof (esp_footer_t) + icv_sz)
	{
	  /* esp footer is either splitted in two buffers or in the before
	   * last buffer */

	  vlib_buffer_t *before_last = b, *bp = b;
	  while (bp->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      before_last = bp;
	      bp = vlib_get_buffer (vm, bp->next_buffer);
	    }
	  u8 *bt = vlib_buffer_get_tail (before_last);

	  if (lb->current_length == icv_sz)
	    {
	      esp_footer_t *f = (esp_footer_t *) (bt - sizeof (*f));
	      pad_length = f->pad_length;
	      next_header = f->next_header;
	    }
	  else
	    {
	      pad_length = (bt - 1)[0];
	      next_header = ((u8 *) vlib_buffer_get_current (lb))[0];
	    }
	}
      else
	{
	  esp_footer_t *f =
	    (esp_footer_t *) (lb->data + lb->current_data +
			      lb->current_length - sizeof (esp_footer_t) -
			      icv_sz);
	  pad_length = f->pad_length;
	  next_header = f->next_header;
	}
    }
  else
    {
      icv_sz = irt->integ_icv_size;
      esp_footer_t *f =
	(esp_footer_t *) (lb->data + lb->current_data + lb->current_length -
			  sizeof (esp_footer_t) - icv_sz);
      pad_length = f->pad_length;
      next_header = f->next_header;
    }

  u16 adv = irt->esp_advance;
  u16 tail = pad_length + tail_base - tail_adjust;
  u16 tail_orig = pad_length + tail_base;
  b->flags &=
    ~(VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

  if (irt->is_transport && !is_tun) /* transport mode */
    {
      u8 udp_sz = is_ip6 ? 0 : irt->udp_sz;
      u16 ip_hdr_sz = pd->hdr_sz - udp_sz;
      u8 *old_ip = b->data + current_data - ip_hdr_sz - udp_sz;
      u8 *ip = old_ip + adv + udp_sz;

      if (is_ip6 && ip_hdr_sz > 64)
	memmove (ip, old_ip, ip_hdr_sz);
      else
	clib_memcpy_le64 (ip, old_ip, ip_hdr_sz);

      b->current_data = current_data + adv - ip_hdr_sz;
      b->current_length += ip_hdr_sz - adv;
      esp_remove_tail (vm, b, lb, tail);

      if (is_ip6)
	{
	  ip6_header_t *ip6 = (ip6_header_t *) ip;
	  u16 len = clib_net_to_host_u16 (ip6->payload_length);
	  len -= adv + tail_orig;
	  ip6->payload_length = clib_host_to_net_u16 (len);
	  ip6->protocol = next_header;
	  next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
	}
      else
	{
	  ip4_header_t *ip4 = (ip4_header_t *) ip;
	  ip_csum_t sum = ip4->checksum;
	  u16 len = clib_net_to_host_u16 (ip4->length);
	  len = clib_host_to_net_u16 (len - adv - tail_orig - udp_sz);
	  sum = ip_csum_update (sum, ip4->protocol, next_header,
				ip4_header_t, protocol);
	  sum = ip_csum_update (sum, ip4->length, len, ip4_header_t, length);
	  ip4->checksum = ip_csum_fold (sum);
	  if (ip4->checksum == 0xffff)
	    ip4->checksum = 0;
	  ip4->protocol = next_header;
	  ip4->length = len;
	  next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
	}
    }
  else
    {
      if (PREDICT_TRUE (next_header == IP_PROTOCOL_IP_IN_IP))
	{
	  next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
	  b->current_data = current_data + adv;
	  b->current_length = current_length - adv;
	  esp_remove_tail_and_tfc_padding (vm, node, pd, b, lb, next, tail,
					   false);
	}
      else if (next_header == IP_PROTOCOL_IPV6)
	{
	  next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
	  b->current_data = current_data + adv;
	  b->current_length = current_length - adv;
	  esp_remove_tail_and_tfc_padding (vm, node, pd, b, lb, next, tail,
					   true);
	}
      else if (next_header == IP_PROTOCOL_MPLS_IN_IP)
	{
	  next[0] = ESP_DECRYPT_NEXT_MPLS_INPUT;
	  b->current_data = current_data + adv;
	  b->current_length = current_length - adv;
	  esp_remove_tail (vm, b, lb, tail);
	}
      else if (is_tun && next_header == IP_PROTOCOL_GRE)
	{
	  gre_header_t *gre;

	  b->current_data = current_data + adv;
	  b->current_length = current_length - adv - tail;

	  gre = vlib_buffer_get_current (b);

	  vlib_buffer_advance (b, sizeof (*gre));

	  switch (clib_net_to_host_u16 (gre->protocol))
	    {
	    case GRE_PROTOCOL_teb:
	      vnet_update_l2_len (b);
	      next[0] = ESP_DECRYPT_NEXT_L2_INPUT;
	      break;
	    case GRE_PROTOCOL_ip4:
	      next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
	      break;
	    case GRE_PROTOCOL_ip6:
	      next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
	      break;
	    default:
	      esp_decrypt_set_next_index (
		b, node, vm->thread_index, ESP_DECRYPT_ERROR_UNSUP_PAYLOAD, 0,
		next, ESP_DECRYPT_NEXT_DROP, pd->sa_index);
	      break;
	    }
	}
      else if ((next[0] = vec_elt (next_by_next_header, next_header)) !=
	       (u16) ~0)
	{
	  b->current_data = current_data + adv;
	  b->current_length = current_length - adv;
	  esp_remove_tail (vm, b, lb, tail);
	}
      else
	{
	  esp_decrypt_set_next_index (b, node, vm->thread_index,
				      ESP_DECRYPT_ERROR_UNSUP_PAYLOAD, 0, next,
				      ESP_DECRYPT_NEXT_DROP, pd->sa_index);
	  return;
	}

      if (is_tun)
	{
	  if (irt->is_protect)
	    {
	      /*
	       * There are two encap possibilities
	       * 1) the tunnel and ths SA are prodiving encap, i.e. it's
	       *   MAC | SA-IP | TUN-IP | ESP | PAYLOAD
	       * implying the SA is in tunnel mode (on a tunnel interface)
	       * 2) only the tunnel provides encap
	       *   MAC | TUN-IP | ESP | PAYLOAD
	       * implying the SA is in transport mode.
	       *
	       * For 2) we need only strip the tunnel encap and we're good.
	       *  since the tunnel and crypto ecnap (int the tun=protect
	       * object) are the same and we verified above that these match
	       * for 1) we need to strip the SA-IP outer headers, to
	       * reveal the tunnel IP and then check that this matches
	       * the configured tunnel.
	       */
	      const ipsec_tun_protect_t *itp;

	      itp =
		ipsec_tun_protect_get (vnet_buffer (b)->ipsec.protect_index);

	      if (irt->is_tunnel) // IPSec tunnel mode
		{
		  next[0] = is_ip6 ? ESP_DECRYPT_NEXT_IP6_INPUT :
				     ESP_DECRYPT_NEXT_IP4_INPUT;
		}
	      else if (next_header == IP_PROTOCOL_IP_IN_IP) // IPIP tunnel
		{
		  const ip4_header_t *ip4;

		  ip4 = vlib_buffer_get_current (b);

		  if (!ip46_address_is_equal_v4 (&itp->itp_tun.src,
						 &ip4->dst_address) ||
		      !ip46_address_is_equal_v4 (&itp->itp_tun.dst,
						 &ip4->src_address))
		    {
		      esp_decrypt_set_next_index (
			b, node, vm->thread_index,
			ESP_DECRYPT_ERROR_TUN_NO_PROTO, 0, next,
			ESP_DECRYPT_NEXT_DROP, pd->sa_index);
		    }
		}
	      else if (next_header == IP_PROTOCOL_IPV6)
		{
		  const ip6_header_t *ip6;

		  ip6 = vlib_buffer_get_current (b);

		  if (!ip46_address_is_equal_v6 (&itp->itp_tun.src,
						 &ip6->dst_address) ||
		      !ip46_address_is_equal_v6 (&itp->itp_tun.dst,
						 &ip6->src_address))
		    {
		      esp_decrypt_set_next_index (
			b, node, vm->thread_index,
			ESP_DECRYPT_ERROR_TUN_NO_PROTO, 0, next,
			ESP_DECRYPT_NEXT_DROP, pd->sa_index);
		    }
		}
	    }
	}
    }

  if (PREDICT_FALSE (n_lost))
    vlib_increment_simple_counter (&ipsec_sa_err_counters[IPSEC_SA_ERROR_LOST],
				   vm->thread_index, pd->sa_index, n_lost);
}

always_inline uword
esp_decrypt_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *from_frame, int is_ip6, int is_tun,
		    u16 async_next_node)
{
  ipsec_main_t *im = &ipsec_main;
  const u16 *next_by_next_header = im->next_header_registrations;
  clib_thread_index_t thread_index = vm->thread_index;
  u16 len;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, thread_index);
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left = from_frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_buffer_t *sync_bufs[VLIB_FRAME_SIZE];
  u16 sync_nexts[VLIB_FRAME_SIZE], *sync_next = sync_nexts, n_sync = 0;
  u16 noop_nexts[VLIB_FRAME_SIZE], n_noop = 0;
  u32 sync_bi[VLIB_FRAME_SIZE];
  u32 noop_bi[VLIB_FRAME_SIZE];
  esp_decrypt_packet_data_t pkt_data[VLIB_FRAME_SIZE], *pd = pkt_data;
  u32 current_sa_index = ~0, current_sa_bytes = 0, current_sa_pkts = 0;
  const u8 esp_sz = sizeof (esp_header_t);
  ipsec_sa_inb_rt_t *irt = 0;
  bool anti_replay_result;
  int is_async = 0;
  u16 n_async = 0;
  u32 async_bi[VLIB_FRAME_SIZE];
  u64 async_ctx[VLIB_FRAME_SIZE];
  esp_decrypt_error_t err;

  vlib_get_buffers (vm, from, b, n_left);
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->chained_crypto_ops);
  vec_reset_length (ptd->chunks);
  clib_memset (sync_nexts, -1, sizeof (sync_nexts));

  while (n_left > 0)
    {
      u8 *payload;

      err = ESP_DECRYPT_ERROR_RX_PKTS;
      if (n_left > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  clib_prefetch_load (p);
	  p -= CLIB_CACHE_LINE_BYTES;
	  clib_prefetch_load (p);
	}

      u32 n_bufs = vlib_buffer_chain_linearize (vm, b[0]);
      if (n_bufs == 0)
	{
	  err = ESP_DECRYPT_ERROR_NO_BUFFERS;
	  esp_decrypt_set_next_index (b[0], node, thread_index, err, n_noop,
				      noop_nexts, ESP_DECRYPT_NEXT_DROP,
				      vnet_buffer (b[0])->ipsec.sad_index);
	  goto next;
	}

      if (vnet_buffer (b[0])->ipsec.sad_index != current_sa_index)
	{
	  if (current_sa_pkts)
	    vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					     current_sa_index, current_sa_pkts,
					     current_sa_bytes);
	  current_sa_bytes = current_sa_pkts = 0;

	  current_sa_index = vnet_buffer (b[0])->ipsec.sad_index;
	  vlib_prefetch_combined_counter (&ipsec_sa_counters, thread_index,
					  current_sa_index);
	  irt = ipsec_sa_get_inb_rt_by_index (current_sa_index);

	  is_async = irt->is_async;
	}

      if (PREDICT_FALSE ((u16) ~0 == irt->thread_index))
	{
	  /* this is the first packet to use this SA, claim the SA
	   * for this thread. this could happen simultaneously on
	   * another thread */
	  clib_atomic_cmp_and_swap (&irt->thread_index, ~0,
				    ipsec_sa_assign_thread (thread_index));
	}

      if (PREDICT_FALSE (thread_index != irt->thread_index))
	{
	  vnet_buffer (b[0])->ipsec.thread_index = irt->thread_index;
	  err = ESP_DECRYPT_ERROR_HANDOFF;
	  esp_decrypt_set_next_index (b[0], node, thread_index, err, n_noop,
				      noop_nexts, ESP_DECRYPT_NEXT_HANDOFF,
				      current_sa_index);
	  goto next;
	}

      /* store packet data for next round for easier prefetch */
      pd->sa_index = current_sa_index;
      pd->hdr_sz = b[0]->current_data - vnet_buffer (b[0])->l3_hdr_offset;
      payload = b[0]->data + b[0]->current_data;
      pd->seq = clib_host_to_net_u32 (((esp_header_t *) payload)->seq);
      pd->is_chain = 0;
      pd->lb = b[0];

      if (n_bufs > 1)
	{
	  pd->is_chain = 1;
	  /* find last buffer in the chain */
	  while (pd->lb->flags & VLIB_BUFFER_NEXT_PRESENT)
	    pd->lb = vlib_get_buffer (vm, pd->lb->next_buffer);
	}

      /* anti-reply check */
      anti_replay_result = ipsec_sa_anti_replay_and_sn_advance (
	irt, pd->seq, ~0, false, &pd->seq_hi);

      if (anti_replay_result)
	{
	  err = ESP_DECRYPT_ERROR_REPLAY;
	  esp_decrypt_set_next_index (b[0], node, thread_index, err, n_noop,
				      noop_nexts, ESP_DECRYPT_NEXT_DROP,
				      current_sa_index);
	  goto next;
	}

      if (b[0]->current_length < irt->integ_icv_size + esp_sz + irt->cipher_iv_size)
	{
	  err = ESP_DECRYPT_ERROR_RUNT;
	  esp_decrypt_set_next_index (b[0], node, thread_index, err, n_noop,
				      noop_nexts, ESP_DECRYPT_NEXT_DROP,
				      current_sa_index);
	  goto next;
	}

      if (pd->is_chain || irt->use_esn)
	{
	  pd->lb = esp_buffer_normalize (vm, b[0], irt->use_esn ? N_HI_ESN_BYTES : 0);
	  if (!pd->lb)
	    {
	      err = ESP_DECRYPT_ERROR_NO_BUFFERS;
	      esp_decrypt_set_next_index (b[0], node, thread_index, err, n_noop, noop_nexts,
					  ESP_DECRYPT_NEXT_DROP, current_sa_index);
	      goto next;
	    }
	  pd->is_chain = pd->lb != b[0];
	}

      len = b[0]->current_length - irt->integ_icv_size;
      current_sa_pkts += 1;
      current_sa_bytes += vlib_buffer_length_in_chain (vm, b[0]);

      if (is_async)
	{
	  err = esp_decrypt_prepare_async_frame (vm, ptd, irt, payload, len, irt->integ_icv_size,
						 irt->cipher_iv_size, pd, from[b - bufs], b[0],
						 async_next_node);
	  if (ESP_DECRYPT_ERROR_RX_PKTS != err)
	    {
	      esp_decrypt_set_next_index (
		b[0], node, thread_index, err, n_noop, noop_nexts,
		ESP_DECRYPT_NEXT_DROP, current_sa_index);
	    }
	}
      else
	{
	  err = esp_decrypt_prepare_sync_op (vm, ptd, irt, payload, len, irt->integ_icv_size,
					     irt->cipher_iv_size, pd, b[0], n_sync);
	  if (err != ESP_DECRYPT_ERROR_RX_PKTS)
	    {
	      esp_decrypt_set_next_index (b[0], node, thread_index, err, 0,
					  sync_next, ESP_DECRYPT_NEXT_DROP,
					  current_sa_index);
	    }
	}
      /* next */
    next:
      if (ESP_DECRYPT_ERROR_RX_PKTS != err)
	{
	  noop_bi[n_noop] = from[b - bufs];
	  n_noop++;
	}
      else if (!is_async)
	{
	  sync_bi[n_sync] = from[b - bufs];
	  sync_bufs[n_sync] = b[0];
	  n_sync++;
	  sync_next++;
	  pd += 1;
	}
      else
	{
	  async_bi[n_async] = from[b - bufs];
	  async_ctx[n_async] = pointer_to_uword (irt->ctx);
	  n_async++;
	}

      n_left -= 1;
      b += 1;
    }

  if (PREDICT_TRUE (~0 != current_sa_index))
    vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				     current_sa_index, current_sa_pkts,
				     current_sa_bytes);

  if (n_async)
    {
      vnet_crypto_deq_scalar_data_t scalar = {
	.next_node_index = async_next_node,
	.op_type = VNET_CRYPTO_OP_TYPE_DECRYPT,
      };
      vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar (
	vm, node, async_bi, async_ctx, ESP_DECRYPT_NEXT_CRYPTO_ENQ, n_async, &scalar);
    }

  if (n_sync)
    {
      esp_process_ops (vm, node, ptd->chained_crypto_ops, sync_bufs, sync_nexts, ptd->chunks,
		       ESP_DECRYPT_ERROR_DECRYPTION_FAILED);
      esp_process_ops (vm, node, ptd->crypto_ops, sync_bufs, sync_nexts, 0,
		       ESP_DECRYPT_ERROR_DECRYPTION_FAILED);
    }

  /* Post decryption ronud - adjust packet data start and length and next
     node */

  n_left = n_sync;
  sync_next = sync_nexts;
  pd = pkt_data;
  b = sync_bufs;

  while (n_left)
    {
      if (n_left >= 2)
	{
	  void *data = b[1]->data + b[1]->current_data;
	  u16 icv_sz = ipsec_sa_get_inb_rt_by_index (pd[1].sa_index)->integ_icv_size;

	  /* buffer metadata */
	  vlib_prefetch_buffer_header (b[1], LOAD);

	  /* esp_footer_t */
	  CLIB_PREFETCH (data + b[1]->current_length - icv_sz - 2, CLIB_CACHE_LINE_BYTES, LOAD);

	  /* packet headers */
	  CLIB_PREFETCH (data - CLIB_CACHE_LINE_BYTES,
			 CLIB_CACHE_LINE_BYTES * 2, LOAD);
	}

      /* save the sa_index as GRE_teb post_crypto changes L2 opaque */
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	current_sa_index = vnet_buffer (b[0])->ipsec.sad_index;

      if (sync_next[0] >= ESP_DECRYPT_N_NEXT)
	esp_decrypt_post_crypto (vm, node, next_by_next_header, pd, b[0], sync_next, is_ip6, is_tun,
				 0);

      /* trace: */
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_decrypt_trace_t *tr;
	  tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  ipsec_sa_t *sa = ipsec_sa_get (current_sa_index);
	  ipsec_sa_inb_rt_t *irt =
	    ipsec_sa_get_inb_rt_by_index (current_sa_index);
	  tr->crypto_alg = sa->crypto_alg;
	  tr->integ_alg = sa->integ_alg;
	  tr->seq = pd->seq;
	  tr->sa_seq64 = irt->seq64;
	  tr->pkt_seq_hi = pd->seq_hi;
	}

      /* next */
      n_left -= 1;
      sync_next += 1;
      pd += 1;
      b += 1;
    }

  vlib_node_increment_counter (vm, node->node_index, ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  if (n_sync)
    vlib_buffer_enqueue_to_next (vm, node, sync_bi, sync_nexts, n_sync);

  if (n_noop)
    vlib_buffer_enqueue_to_next (vm, node, noop_bi, noop_nexts, n_noop);

  return (from_frame->n_vectors);
}

always_inline uword
esp_decrypt_post_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame, int is_ip6, int is_tun)
{
  const ipsec_main_t *im = &ipsec_main;
  const u16 *next_by_next_header = im->next_header_registrations;
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left = from_frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left);

  while (n_left > 0)
    {
      esp_decrypt_packet_data_t *pd = &(esp_post_data (b[0]))->decrypt_data;

      if (n_left > 2)
	{
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	}

      esp_decrypt_post_crypto (vm, node, next_by_next_header, pd, b[0], next, is_ip6, is_tun, 1);

      /*trace: */
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsec_sa_t *sa;
	  ipsec_sa_inb_rt_t *irt;
	  esp_decrypt_trace_t *tr;
	  esp_decrypt_packet_data_t *async_pd =
	    &(esp_post_data (b[0]))->decrypt_data;
	  tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  sa = ipsec_sa_get (async_pd->sa_index);
	  irt = ipsec_sa_get_inb_rt_by_index (async_pd->sa_index);

	  tr->crypto_alg = sa->crypto_alg;
	  tr->integ_alg = sa->integ_alg;
	  tr->seq = pd->seq;
	  tr->sa_seq64 = irt->seq64;
	  tr->pkt_seq_hi = pd->seq_hi;
	}

      n_left--;
      next++;
      b++;
    }

  n_left = from_frame->n_vectors;
  vlib_node_increment_counter (vm, node->node_index,
			       ESP_DECRYPT_ERROR_RX_POST_PKTS, n_left);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);

  return n_left;
}

VLIB_NODE_FN (esp4_decrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 0, 0,
			     esp_decrypt_async_next.esp4_post_next);
}

VLIB_NODE_FN (esp4_decrypt_post_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return esp_decrypt_post_inline (vm, node, from_frame, 0, 0);
}

VLIB_NODE_FN (esp4_decrypt_tun_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 0, 1,
			     esp_decrypt_async_next.esp4_tun_post_next);
}

VLIB_NODE_FN (esp4_decrypt_tun_post_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * from_frame)
{
  return esp_decrypt_post_inline (vm, node, from_frame, 0, 1);
}

VLIB_NODE_FN (esp6_decrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 1, 0,
			     esp_decrypt_async_next.esp6_post_next);
}

VLIB_NODE_FN (esp6_decrypt_post_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return esp_decrypt_post_inline (vm, node, from_frame, 1, 0);
}

VLIB_NODE_FN (esp6_decrypt_tun_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 1, 1,
			     esp_decrypt_async_next.esp6_tun_post_next);
}

VLIB_NODE_FN (esp6_decrypt_tun_post_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * from_frame)
{
  return esp_decrypt_post_inline (vm, node, from_frame, 1, 1);
}

VLIB_REGISTER_NODE (esp4_decrypt_node) = {
  .name = "esp4-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ESP_DECRYPT_N_ERROR,
  .error_counters = esp_decrypt_error_counters,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ESP_DECRYPT_NEXT_DROP] = "ip4-drop",
    [ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-drop",
    [ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
    [ESP_DECRYPT_NEXT_CRYPTO_ENQ] = "crypto-enq",
    [ESP_DECRYPT_NEXT_HANDOFF] = "esp4-decrypt-handoff",
  },
};

VLIB_REGISTER_NODE (esp4_decrypt_post_node) = {
  .name = "esp4-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ESP_DECRYPT_N_ERROR,
  .error_counters = esp_decrypt_error_counters,

  .sibling_of = "esp4-decrypt",
};

VLIB_REGISTER_NODE (esp6_decrypt_node) = {
  .name = "esp6-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ESP_DECRYPT_N_ERROR,
  .error_counters = esp_decrypt_error_counters,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ESP_DECRYPT_NEXT_DROP] = "ip6-drop",
    [ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-drop",
    [ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
    [ESP_DECRYPT_NEXT_CRYPTO_ENQ] = "crypto-enq",
    [ESP_DECRYPT_NEXT_HANDOFF]=  "esp6-decrypt-handoff",
  },
};

VLIB_REGISTER_NODE (esp6_decrypt_post_node) = {
  .name = "esp6-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ESP_DECRYPT_N_ERROR,
  .error_counters = esp_decrypt_error_counters,

  .sibling_of = "esp6-decrypt",
};

VLIB_REGISTER_NODE (esp4_decrypt_tun_node) = {
  .name = "esp4-decrypt-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ESP_DECRYPT_N_ERROR,
  .error_counters = esp_decrypt_error_counters,
  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ESP_DECRYPT_NEXT_DROP] = "ip4-drop",
    [ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-input",
    [ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
    [ESP_DECRYPT_NEXT_CRYPTO_ENQ] = "crypto-enq",
    [ESP_DECRYPT_NEXT_HANDOFF] = "esp4-decrypt-tun-handoff",
  },
};

VLIB_REGISTER_NODE (esp4_decrypt_tun_post_node) = {
  .name = "esp4-decrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ESP_DECRYPT_N_ERROR,
  .error_counters = esp_decrypt_error_counters,

  .sibling_of = "esp4-decrypt-tun",
};

VLIB_REGISTER_NODE (esp6_decrypt_tun_node) = {
  .name = "esp6-decrypt-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ESP_DECRYPT_N_ERROR,
  .error_counters = esp_decrypt_error_counters,
  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ESP_DECRYPT_NEXT_DROP] = "ip6-drop",
    [ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-input",
    [ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
    [ESP_DECRYPT_NEXT_CRYPTO_ENQ] = "crypto-enq",
    [ESP_DECRYPT_NEXT_HANDOFF]=  "esp6-decrypt-tun-handoff",
  },
};

VLIB_REGISTER_NODE (esp6_decrypt_tun_post_node) = {
  .name = "esp6-decrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ESP_DECRYPT_N_ERROR,
  .error_counters = esp_decrypt_error_counters,

  .sibling_of = "esp6-decrypt-tun",
};

#ifndef CLIB_MARCH_VARIANT

static clib_error_t *
esp_decrypt_init (vlib_main_t *vm)
{
  ipsec_main_t *im = &ipsec_main;

  im->esp4_dec_fq_index = vlib_frame_queue_main_init (esp4_decrypt_node.index,
						      im->handoff_queue_size);
  im->esp6_dec_fq_index = vlib_frame_queue_main_init (esp6_decrypt_node.index,
						      im->handoff_queue_size);
  im->esp4_dec_tun_fq_index = vlib_frame_queue_main_init (
    esp4_decrypt_tun_node.index, im->handoff_queue_size);
  im->esp6_dec_tun_fq_index = vlib_frame_queue_main_init (
    esp6_decrypt_tun_node.index, im->handoff_queue_size);

  return 0;
}

VLIB_INIT_FUNCTION (esp_decrypt_init);

#endif
