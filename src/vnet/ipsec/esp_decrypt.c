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
#include <vnet/l2/l2_input.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ipsec_io.h>
#include <vnet/ipsec/ipsec_tun.h>

#include <vnet/gre/packet.h>

#define foreach_esp_decrypt_next                                              \
  _ (DROP, "error-drop")                                                      \
  _ (IP4_INPUT, "ip4-input-no-checksum")                                      \
  _ (IP6_INPUT, "ip6-input")                                                  \
  _ (L2_INPUT, "l2-input")                                                    \
  _ (MPLS_INPUT, "mpls-input")                                                \
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

#define foreach_esp_decrypt_error                                             \
  _ (RX_PKTS, "ESP pkts received")                                            \
  _ (RX_POST_PKTS, "ESP-POST pkts received")                                  \
  _ (HANDOFF, "hand-off")                                                     \
  _ (DECRYPTION_FAILED, "ESP decryption failed")                              \
  _ (INTEG_ERROR, "Integrity check failed")                                   \
  _ (CRYPTO_ENGINE_ERROR, "crypto engine error (packet dropped)")             \
  _ (REPLAY, "SA replayed packet")                                            \
  _ (RUNT, "undersized packet")                                               \
  _ (NO_BUFFERS, "no buffers (packet dropped)")                               \
  _ (OVERSIZED_HEADER, "buffer with oversized header (dropped)")              \
  _ (NO_TAIL_SPACE, "no enough buffer tail space (dropped)")                  \
  _ (TUN_NO_PROTO, "no tunnel protocol")                                      \
  _ (UNSUP_PAYLOAD, "unsupported payload")

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
  u32 seq;
  u32 sa_seq;
  u32 sa_seq_hi;
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

  s =
    format (s,
	    "esp: crypto %U integrity %U pkt-seq %d sa-seq %u sa-seq-hi %u",
	    format_ipsec_crypto_alg, t->crypto_alg, format_ipsec_integ_alg,
	    t->integ_alg, t->seq, t->sa_seq, t->sa_seq_hi);
  return s;
}

#define ESP_ENCRYPT_PD_F_FD_TRANSPORT (1 << 2)

static_always_inline void
esp_process_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vnet_crypto_op_t * ops, vlib_buffer_t * b[], u16 * nexts,
		 int e)
{
  vnet_crypto_op_t *op = ops;
  u32 n_fail, n_ops = vec_len (ops);

  if (n_ops == 0)
    return;

  n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);
      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 err, bi = op->user_data;
	  if (op->status == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	    err = e;
	  else
	    err = ESP_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR;
	  b[bi]->error = node->errors[err];
	  nexts[bi] = ESP_DECRYPT_NEXT_DROP;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline void
esp_process_chained_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vnet_crypto_op_t * ops, vlib_buffer_t * b[],
			 u16 * nexts, vnet_crypto_op_chunk_t * chunks, int e)
{

  vnet_crypto_op_t *op = ops;
  u32 n_fail, n_ops = vec_len (ops);

  if (PREDICT_TRUE (n_ops == 0))
    return;

  n_fail = n_ops - vnet_crypto_process_chained_ops (vm, op, chunks, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);
      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 err, bi = op->user_data;
	  if (op->status == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	    err = e;
	  else
	    err = ESP_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR;
	  b[bi]->error = node->errors[err];
	  nexts[bi] = ESP_DECRYPT_NEXT_DROP;
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

  if (last->current_length > tail)
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

/* ICV is splitted in last two buffers so move it to the last buffer and
   return pointer to it */
static_always_inline u8 *
esp_move_icv (vlib_main_t * vm, vlib_buffer_t * first,
	      esp_decrypt_packet_data_t * pd,
	      esp_decrypt_packet_data2_t * pd2, u16 icv_sz, u16 * dif)
{
  vlib_buffer_t *before_last, *bp;
  u16 last_sz = pd2->lb->current_length;
  u16 first_sz = icv_sz - last_sz;

  bp = before_last = first;
  while (bp->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      before_last = bp;
      bp = vlib_get_buffer (vm, bp->next_buffer);
    }

  u8 *lb_curr = vlib_buffer_get_current (pd2->lb);
  memmove (lb_curr + first_sz, lb_curr, last_sz);
  clib_memcpy_fast (lb_curr, vlib_buffer_get_tail (before_last) - first_sz,
		    first_sz);
  before_last->current_length -= first_sz;
  if (before_last == first)
    pd->current_length -= first_sz;
  clib_memset (vlib_buffer_get_tail (before_last), 0, first_sz);
  if (dif)
    dif[0] = first_sz;
  pd2->lb = before_last;
  pd2->icv_removed = 1;
  pd2->free_buffer_index = before_last->next_buffer;
  before_last->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
  return lb_curr;
}

static_always_inline i16
esp_insert_esn (vlib_main_t * vm, ipsec_sa_t * sa,
		esp_decrypt_packet_data2_t * pd2, u32 * data_len,
		u8 ** digest, u16 * len, vlib_buffer_t * b, u8 * payload)
{
  if (!ipsec_sa_is_set_USE_ESN (sa))
    return 0;

  /* shift ICV by 4 bytes to insert ESN */
  u32 seq_hi = clib_host_to_net_u32 (sa->seq_hi);
  u8 tmp[ESP_MAX_ICV_SIZE], sz = sizeof (sa->seq_hi);

  if (pd2->icv_removed)
    {
      u16 space_left = vlib_buffer_space_left_at_end (vm, pd2->lb);
      if (space_left >= sz)
	{
	  clib_memcpy_fast (vlib_buffer_get_tail (pd2->lb), &seq_hi, sz);
	  *data_len += sz;
	}
      else
	return sz;

      len[0] = b->current_length;
    }
  else
    {
      clib_memcpy_fast (tmp, payload + len[0], ESP_MAX_ICV_SIZE);
      clib_memcpy_fast (payload + len[0], &seq_hi, sz);
      clib_memcpy_fast (payload + len[0] + sz, tmp, ESP_MAX_ICV_SIZE);
      *data_len += sz;
      *digest += sz;
    }
  return sz;
}

static_always_inline u8 *
esp_move_icv_esn (vlib_main_t * vm, vlib_buffer_t * first,
		  esp_decrypt_packet_data_t * pd,
		  esp_decrypt_packet_data2_t * pd2, u16 icv_sz,
		  ipsec_sa_t * sa, u8 * extra_esn, u32 * len)
{
  u16 dif = 0;
  u8 *digest = esp_move_icv (vm, first, pd, pd2, icv_sz, &dif);
  if (dif)
    *len -= dif;

  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      u8 sz = sizeof (sa->seq_hi);
      u32 seq_hi = clib_host_to_net_u32 (sa->seq_hi);
      u16 space_left = vlib_buffer_space_left_at_end (vm, pd2->lb);

      if (space_left >= sz)
	{
	  clib_memcpy_fast (vlib_buffer_get_tail (pd2->lb), &seq_hi, sz);
	  *len += sz;
	}
      else
	{
	  /* no space for ESN at the tail, use the next buffer
	   * (with ICV data) */
	  ASSERT (pd2->icv_removed);
	  vlib_buffer_t *tmp = vlib_get_buffer (vm, pd2->free_buffer_index);
	  clib_memcpy_fast (vlib_buffer_get_current (tmp) - sz, &seq_hi, sz);
	  extra_esn[0] = 1;
	}
    }
  return digest;
}

static_always_inline int
esp_decrypt_chain_integ (vlib_main_t * vm, ipsec_per_thread_data_t * ptd,
			 esp_decrypt_packet_data2_t * pd2,
			 ipsec_sa_t * sa0, vlib_buffer_t * b, u8 icv_sz,
			 u8 * start_src, u32 start_len,
			 u8 ** digest, u16 * n_ch, u32 * integ_total_len)
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
      if (pd2->lb == cb)
	{
	  if (pd2->icv_removed)
	    ch->len = cb->current_length;
	  else
	    ch->len = cb->current_length - icv_sz;
	  if (ipsec_sa_is_set_USE_ESN (sa0))
	    {
	      u32 seq_hi = clib_host_to_net_u32 (sa0->seq_hi);
	      u8 tmp[ESP_MAX_ICV_SIZE], sz = sizeof (sa0->seq_hi);
	      u8 *esn;
	      vlib_buffer_t *tmp_b;
	      u16 space_left = vlib_buffer_space_left_at_end (vm, pd2->lb);
	      if (space_left < sz)
		{
		  if (pd2->icv_removed)
		    {
		      /* use pre-data area from the last bufer
		         that was removed from the chain */
		      tmp_b = vlib_get_buffer (vm, pd2->free_buffer_index);
		      esn = tmp_b->data - sz;
		    }
		  else
		    {
		      /* no space, need to allocate new buffer */
		      u32 tmp_bi = 0;
		      if (vlib_buffer_alloc (vm, &tmp_bi, 1) != 1)
			return -1;
		      tmp_b = vlib_get_buffer (vm, tmp_bi);
		      esn = tmp_b->data;
		      pd2->free_buffer_index = tmp_bi;
		    }
		  clib_memcpy_fast (esn, &seq_hi, sz);

		  vec_add2 (ptd->chunks, ch, 1);
		  n_chunks += 1;
		  ch->src = esn;
		  ch->len = sz;
		}
	      else
		{
		  if (pd2->icv_removed)
		    {
		      clib_memcpy_fast (vlib_buffer_get_tail
					(pd2->lb), &seq_hi, sz);
		    }
		  else
		    {
		      clib_memcpy_fast (tmp, *digest, ESP_MAX_ICV_SIZE);
		      clib_memcpy_fast (*digest, &seq_hi, sz);
		      clib_memcpy_fast (*digest + sz, tmp, ESP_MAX_ICV_SIZE);
		      *digest += sz;
		    }
		  ch->len += sz;
		}
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
esp_decrypt_chain_crypto (vlib_main_t * vm, ipsec_per_thread_data_t * ptd,
			  esp_decrypt_packet_data_t * pd,
			  esp_decrypt_packet_data2_t * pd2,
			  ipsec_sa_t * sa0, vlib_buffer_t * b, u8 icv_sz,
			  u8 * start, u32 start_len, u8 ** tag, u16 * n_ch)
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
      if (pd2->lb == cb)
	{
	  if (ipsec_sa_is_set_IS_AEAD (sa0))
	    {
	      if (pd2->lb->current_length < icv_sz)
		{
		  u16 dif = 0;
		  *tag = esp_move_icv (vm, b, pd, pd2, icv_sz, &dif);

		  /* this chunk does not contain crypto data */
		  n_chunks -= 1;
		  /* and fix previous chunk's length as it might have
		     been changed */
		  ASSERT (n_chunks > 0);
		  if (pd2->lb == b)
		    {
		      total_len -= dif;
		      ch[-1].len -= dif;
		    }
		  else
		    {
		      total_len = total_len + pd2->lb->current_length -
			ch[-1].len;
		      ch[-1].len = pd2->lb->current_length;
		    }
		  break;
		}
	      else
		*tag = vlib_buffer_get_tail (pd2->lb) - icv_sz;
	    }

	  if (pd2->icv_removed)
	    total_len += ch->len = cb->current_length;
	  else
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

static_always_inline void
esp_decrypt_prepare_sync_op (vlib_main_t * vm, vlib_node_runtime_t * node,
			     ipsec_per_thread_data_t * ptd,
			     vnet_crypto_op_t *** crypto_ops,
			     vnet_crypto_op_t *** integ_ops,
			     vnet_crypto_op_t * op,
			     ipsec_sa_t * sa0, u8 * payload,
			     u16 len, u8 icv_sz, u8 iv_sz,
			     esp_decrypt_packet_data_t * pd,
			     esp_decrypt_packet_data2_t * pd2,
			     vlib_buffer_t * b, u16 * next, u32 index)
{
  const u8 esp_sz = sizeof (esp_header_t);

  if (PREDICT_TRUE (sa0->integ_op_id != VNET_CRYPTO_OP_NONE))
    {
      vnet_crypto_op_init (op, sa0->integ_op_id);
      op->key_index = sa0->integ_key_index;
      op->src = payload;
      op->flags = VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
      op->user_data = index;
      op->digest = payload + len;
      op->digest_len = icv_sz;
      op->len = len;

      if (pd->is_chain)
	{
	  /* buffer is chained */
	  op->len = pd->current_length;

	  /* special case when ICV is splitted and needs to be reassembled
	   * first -> move it to the last buffer. Also take into account
	   * that ESN needs to be added after encrypted data and may or
	   * may not fit in the tail.*/
	  if (pd2->lb->current_length < icv_sz)
	    {
	      u8 extra_esn = 0;
	      op->digest =
		esp_move_icv_esn (vm, b, pd, pd2, icv_sz, sa0,
				  &extra_esn, &op->len);

	      if (extra_esn)
		{
		  /* esn is in the last buffer, that was unlinked from
		   * the chain */
		  op->len = b->current_length;
		}
	      else
		{
		  if (pd2->lb == b)
		    {
		      /* we now have a single buffer of crypto data, adjust
		       * the length (second buffer contains only ICV) */
		      *integ_ops = &ptd->integ_ops;
		      *crypto_ops = &ptd->crypto_ops;
		      len = b->current_length;
		      goto out;
		    }
		}
	    }
	  else
	    op->digest = vlib_buffer_get_tail (pd2->lb) - icv_sz;

	  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	  op->chunk_index = vec_len (ptd->chunks);
	  if (esp_decrypt_chain_integ (vm, ptd, pd2, sa0, b, icv_sz,
				       payload, pd->current_length,
				       &op->digest, &op->n_chunks, 0) < 0)
	    {
	      b->error = node->errors[ESP_DECRYPT_ERROR_NO_BUFFERS];
	      next[0] = ESP_DECRYPT_NEXT_DROP;
	      return;
	    }
	}
      else
	esp_insert_esn (vm, sa0, pd2, &op->len, &op->digest, &len, b,
			payload);
    out:
      vec_add_aligned (*(integ_ops[0]), op, 1, CLIB_CACHE_LINE_BYTES);
    }

  payload += esp_sz;
  len -= esp_sz;

  if (sa0->crypto_dec_op_id != VNET_CRYPTO_OP_NONE)
    {
      vnet_crypto_op_init (op, sa0->crypto_dec_op_id);
      op->key_index = sa0->crypto_key_index;
      op->iv = payload;

      if (ipsec_sa_is_set_IS_CTR (sa0))
	{
	  /* construct nonce in a scratch space in front of the IP header */
	  esp_ctr_nonce_t *nonce =
	    (esp_ctr_nonce_t *) (payload - esp_sz - pd->hdr_sz -
				 sizeof (*nonce));
	  if (ipsec_sa_is_set_IS_AEAD (sa0))
	    {
	      /* constuct aad in a scratch space in front of the nonce */
	      esp_header_t *esp0 = (esp_header_t *) (payload - esp_sz);
	      op->aad = (u8 *) nonce - sizeof (esp_aead_t);
	      op->aad_len = esp_aad_fill (op->aad, esp0, sa0);
	      op->tag = payload + len;
	      op->tag_len = 16;
	    }
	  else
	    {
	      nonce->ctr = clib_host_to_net_u32 (1);
	    }
	  nonce->salt = sa0->salt;
	  ASSERT (sizeof (u64) == iv_sz);
	  nonce->iv = *(u64 *) op->iv;
	  op->iv = (u8 *) nonce;
	}
      op->src = op->dst = payload += iv_sz;
      op->len = len - iv_sz;
      op->user_data = index;

      if (pd->is_chain && (pd2->lb != b))
	{
	  /* buffer is chained */
	  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	  op->chunk_index = vec_len (ptd->chunks);
	  esp_decrypt_chain_crypto (vm, ptd, pd, pd2, sa0, b, icv_sz,
				    payload, len - pd->iv_sz + pd->icv_sz,
				    &op->tag, &op->n_chunks);
	}

      vec_add_aligned (*(crypto_ops[0]), op, 1, CLIB_CACHE_LINE_BYTES);
    }
}

static_always_inline esp_decrypt_error_t
esp_decrypt_prepare_async_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
				 ipsec_per_thread_data_t *ptd,
				 vnet_crypto_async_frame_t *f, ipsec_sa_t *sa0,
				 u8 *payload, u16 len, u8 icv_sz, u8 iv_sz,
				 esp_decrypt_packet_data_t *pd,
				 esp_decrypt_packet_data2_t *pd2, u32 bi,
				 vlib_buffer_t *b, u16 *next, u16 async_next)
{
  const u8 esp_sz = sizeof (esp_header_t);
  u32 current_protect_index = vnet_buffer (b)->ipsec.protect_index;
  esp_decrypt_packet_data_t *async_pd = &(esp_post_data (b))->decrypt_data;
  esp_decrypt_packet_data2_t *async_pd2 = esp_post_data2 (b);
  u8 *tag = payload + len, *iv = payload + esp_sz, *aad = 0;
  u32 key_index;
  u32 crypto_len, integ_len = 0;
  i16 crypto_start_offset, integ_start_offset = 0;
  u8 flags = 0;

  if (!ipsec_sa_is_set_IS_AEAD (sa0))
    {
      /* linked algs */
      key_index = sa0->linked_key_index;
      integ_start_offset = payload - b->data;
      integ_len = len;
      if (PREDICT_TRUE (sa0->integ_op_id != VNET_CRYPTO_OP_NONE))
	flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;

      if (pd->is_chain)
	{
	  /* buffer is chained */
	  integ_len = pd->current_length;

	  /* special case when ICV is splitted and needs to be reassembled
	   * first -> move it to the last buffer. Also take into account
	   * that ESN needs to be added after encrypted data and may or
	   * may not fit in the tail.*/
	  if (pd2->lb->current_length < icv_sz)
	    {
	      u8 extra_esn = 0;
	      tag = esp_move_icv_esn (vm, b, pd, pd2, icv_sz, sa0,
				      &extra_esn, &integ_len);

	      if (extra_esn)
		{
		  /* esn is in the last buffer, that was unlinked from
		   * the chain */
		  integ_len = b->current_length;
		}
	      else
		{
		  if (pd2->lb == b)
		    {
		      /* we now have a single buffer of crypto data, adjust
		       * the length (second buffer contains only ICV) */
		      len = b->current_length;
		      goto out;
		    }
		}
	    }
	  else
	    tag = vlib_buffer_get_tail (pd2->lb) - icv_sz;

	  flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	  if (esp_decrypt_chain_integ (vm, ptd, pd2, sa0, b, icv_sz, payload,
				       pd->current_length, &tag,
				       0, &integ_len) < 0)
	    {
	      /* allocate buffer failed, will not add to frame and drop */
	      return (ESP_DECRYPT_ERROR_NO_BUFFERS);
	    }
	}
      else
	esp_insert_esn (vm, sa0, pd2, &integ_len, &tag, &len, b, payload);
    }
  else
    key_index = sa0->crypto_key_index;

out:
  /* crypto */
  payload += esp_sz;
  len -= esp_sz;
  iv = payload;

  if (ipsec_sa_is_set_IS_CTR (sa0))
    {
      /* construct nonce in a scratch space in front of the IP header */
      esp_ctr_nonce_t *nonce =
	(esp_ctr_nonce_t *) (payload - esp_sz - pd->hdr_sz - sizeof (*nonce));
      if (ipsec_sa_is_set_IS_AEAD (sa0))
	{
	  /* constuct aad in a scratch space in front of the nonce */
	  esp_header_t *esp0 = (esp_header_t *) (payload - esp_sz);
	  aad = (u8 *) nonce - sizeof (esp_aead_t);
	  esp_aad_fill (aad, esp0, sa0);
	  tag = payload + len;
	}
      else
	{
	  nonce->ctr = clib_host_to_net_u32 (1);
	}
      nonce->salt = sa0->salt;
      ASSERT (sizeof (u64) == iv_sz);
      nonce->iv = *(u64 *) iv;
      iv = (u8 *) nonce;
    }

  crypto_start_offset = (payload += iv_sz) - b->data;
  crypto_len = len - iv_sz;

  if (pd->is_chain && (pd2->lb != b))
    {
      /* buffer is chained */
      flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;

      crypto_len = esp_decrypt_chain_crypto (vm, ptd, pd, pd2, sa0, b, icv_sz,
					     payload,
					     len - pd->iv_sz + pd->icv_sz,
					     &tag, 0);
    }

  *async_pd = *pd;
  *async_pd2 = *pd2;
  pd->protect_index = current_protect_index;

  /* for AEAD integ_len - crypto_len will be negative, it is ok since it
   * is ignored by the engine. */
  vnet_crypto_async_add_to_frame (
    vm, f, key_index, crypto_len, integ_len - crypto_len, crypto_start_offset,
    integ_start_offset, bi, async_next, iv, tag, aad, flags);

  return (ESP_DECRYPT_ERROR_RX_PKTS);
}

static_always_inline void
esp_decrypt_post_crypto (vlib_main_t * vm, vlib_node_runtime_t * node,
			 esp_decrypt_packet_data_t * pd,
			 esp_decrypt_packet_data2_t * pd2, vlib_buffer_t * b,
			 u16 * next, int is_ip6, int is_tun, int is_async)
{
  ipsec_sa_t *sa0 = ipsec_sa_get (pd->sa_index);
  vlib_buffer_t *lb = b;
  const u8 esp_sz = sizeof (esp_header_t);
  const u8 tun_flags = IPSEC_SA_FLAG_IS_TUNNEL | IPSEC_SA_FLAG_IS_TUNNEL_V6;
  u8 pad_length = 0, next_header = 0;
  u16 icv_sz;

  /*
   * redo the anti-reply check
   * in this frame say we have sequence numbers, s, s+1, s+1, s+1
   * and s and s+1 are in the window. When we did the anti-replay
   * check above we did so against the state of the window (W),
   * after packet s-1. So each of the packets in the sequence will be
   * accepted.
   * This time s will be cheked against Ws-1, s+1 chceked against Ws
   * (i.e. the window state is updated/advnaced)
   * so this time the successive s+! packet will be dropped.
   * This is a consequence of batching the decrypts. If the
   * check-dcrypt-advance process was done for each packet it would
   * be fine. But we batch the decrypts because it's much more efficient
   * to do so in SW and if we offload to HW and the process is async.
   *
   * You're probably thinking, but this means an attacker can send the
   * above sequence and cause VPP to perform decrpyts that will fail,
   * and that's true. But if the attacker can determine s (a valid
   * sequence number in the window) which is non-trivial, it can generate
   * a sequence s, s+1, s+2, s+3, ... s+n and nothing will prevent any
   * implementation, sequential or batching, from decrypting these.
   */
  if (ipsec_sa_anti_replay_check (sa0, pd->seq))
    {
      b->error = node->errors[ESP_DECRYPT_ERROR_REPLAY];
      next[0] = ESP_DECRYPT_NEXT_DROP;
      return;
    }

  ipsec_sa_anti_replay_advance (sa0, pd->seq);

  if (pd->is_chain)
    {
      lb = pd2->lb;
      icv_sz = pd2->icv_removed ? 0 : pd->icv_sz;
      if (pd2->free_buffer_index)
	{
	  vlib_buffer_free_one (vm, pd2->free_buffer_index);
	  lb->next_buffer = 0;
	}
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
      icv_sz = pd->icv_sz;
      esp_footer_t *f =
	(esp_footer_t *) (lb->data + lb->current_data + lb->current_length -
			  sizeof (esp_footer_t) - icv_sz);
      pad_length = f->pad_length;
      next_header = f->next_header;
    }

  u16 adv = pd->iv_sz + esp_sz;
  u16 tail = sizeof (esp_footer_t) + pad_length + icv_sz;
  u16 tail_orig = sizeof (esp_footer_t) + pad_length + pd->icv_sz;
  b->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;

  if ((pd->flags & tun_flags) == 0 && !is_tun)	/* transport mode */
    {
      u8 udp_sz = (is_ip6 == 0 && pd->flags & IPSEC_SA_FLAG_UDP_ENCAP) ?
	sizeof (udp_header_t) : 0;
      u16 ip_hdr_sz = pd->hdr_sz - udp_sz;
      u8 *old_ip = b->data + pd->current_data - ip_hdr_sz - udp_sz;
      u8 *ip = old_ip + adv + udp_sz;

      if (is_ip6 && ip_hdr_sz > 64)
	memmove (ip, old_ip, ip_hdr_sz);
      else
	clib_memcpy_le64 (ip, old_ip, ip_hdr_sz);

      b->current_data = pd->current_data + adv - ip_hdr_sz;
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
	  b->current_data = pd->current_data + adv;
	  b->current_length = pd->current_length - adv;
	  esp_remove_tail (vm, b, lb, tail);
	}
      else if (next_header == IP_PROTOCOL_IPV6)
	{
	  next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
	  b->current_data = pd->current_data + adv;
	  b->current_length = pd->current_length - adv;
	  esp_remove_tail (vm, b, lb, tail);
	}
      else if (next_header == IP_PROTOCOL_MPLS_IN_IP)
	{
	  next[0] = ESP_DECRYPT_NEXT_MPLS_INPUT;
	  b->current_data = pd->current_data + adv;
	  b->current_length = pd->current_length - adv;
	  esp_remove_tail (vm, b, lb, tail);
	}
      else
	{
	  if (is_tun && next_header == IP_PROTOCOL_GRE)
	    {
	      gre_header_t *gre;

	      b->current_data = pd->current_data + adv;
	      b->current_length = pd->current_length - adv - tail;

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
		  b->error = node->errors[ESP_DECRYPT_ERROR_UNSUP_PAYLOAD];
		  next[0] = ESP_DECRYPT_NEXT_DROP;
		  break;
		}
	    }
	  else
	    {
	      next[0] = ESP_DECRYPT_NEXT_DROP;
	      b->error = node->errors[ESP_DECRYPT_ERROR_UNSUP_PAYLOAD];
	      return;
	    }
	}
      if (is_tun)
	{
	  if (ipsec_sa_is_set_IS_PROTECT (sa0))
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

	      if (is_async)
		itp = ipsec_tun_protect_get (pd->protect_index);
	      else
		itp =
		  ipsec_tun_protect_get (vnet_buffer (b)->
					 ipsec.protect_index);

	      if (PREDICT_TRUE (next_header == IP_PROTOCOL_IP_IN_IP))
		{
		  const ip4_header_t *ip4;

		  ip4 = vlib_buffer_get_current (b);

		  if (!ip46_address_is_equal_v4 (&itp->itp_tun.src,
						 &ip4->dst_address) ||
		      !ip46_address_is_equal_v4 (&itp->itp_tun.dst,
						 &ip4->src_address))
		    {
		      next[0] = ESP_DECRYPT_NEXT_DROP;
		      b->error = node->errors[ESP_DECRYPT_ERROR_TUN_NO_PROTO];
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
		      next[0] = ESP_DECRYPT_NEXT_DROP;
		      b->error = node->errors[ESP_DECRYPT_ERROR_TUN_NO_PROTO];
		    }
		}
	    }
	}
    }
}

always_inline uword
esp_decrypt_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *from_frame, int is_ip6, int is_tun,
		    u16 async_next_node)
{
  ipsec_main_t *im = &ipsec_main;
  u32 thread_index = vm->thread_index;
  u16 len;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, thread_index);
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left = from_frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_buffer_t *sync_bufs[VLIB_FRAME_SIZE];
  u16 sync_nexts[VLIB_FRAME_SIZE], *sync_next = sync_nexts, n_sync = 0;
  u16 async_nexts[VLIB_FRAME_SIZE], *async_next = async_nexts, n_async = 0;
  u16 noop_nexts[VLIB_FRAME_SIZE], *noop_next = noop_nexts, n_noop = 0;
  u32 sync_bi[VLIB_FRAME_SIZE];
  u32 noop_bi[VLIB_FRAME_SIZE];
  esp_decrypt_packet_data_t pkt_data[VLIB_FRAME_SIZE], *pd = pkt_data;
  esp_decrypt_packet_data2_t pkt_data2[VLIB_FRAME_SIZE], *pd2 = pkt_data2;
  esp_decrypt_packet_data_t cpd = { };
  u32 current_sa_index = ~0, current_sa_bytes = 0, current_sa_pkts = 0;
  const u8 esp_sz = sizeof (esp_header_t);
  ipsec_sa_t *sa0 = 0;
  vnet_crypto_op_t _op, *op = &_op;
  vnet_crypto_op_t **crypto_ops = &ptd->crypto_ops;
  vnet_crypto_op_t **integ_ops = &ptd->integ_ops;
  int is_async = im->async_mode;
  vnet_crypto_async_op_id_t async_op = ~0;
  vnet_crypto_async_frame_t *async_frames[VNET_CRYPTO_ASYNC_OP_N_IDS];
  esp_decrypt_error_t err;

  vlib_get_buffers (vm, from, b, n_left);
  if (!is_async)
    {
      vec_reset_length (ptd->crypto_ops);
      vec_reset_length (ptd->integ_ops);
      vec_reset_length (ptd->chained_crypto_ops);
      vec_reset_length (ptd->chained_integ_ops);
    }
  vec_reset_length (ptd->async_frames);
  vec_reset_length (ptd->chunks);
  clib_memset (sync_nexts, -1, sizeof (sync_nexts));
  clib_memset (async_frames, 0, sizeof (async_frames));

  while (n_left > 0)
    {
      u8 *payload;

      err = ESP_DECRYPT_ERROR_RX_PKTS;
      if (n_left > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	  p -= CLIB_CACHE_LINE_BYTES;
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      u32 n_bufs = vlib_buffer_chain_linearize (vm, b[0]);
      if (n_bufs == 0)
	{
	  err = ESP_DECRYPT_ERROR_NO_BUFFERS;
	  esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
			      ESP_DECRYPT_NEXT_DROP);
	  goto next;
	}

      if (vnet_buffer (b[0])->ipsec.sad_index != current_sa_index)
	{
	  if (current_sa_pkts)
	    vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					     current_sa_index,
					     current_sa_pkts,
					     current_sa_bytes);
	  current_sa_bytes = current_sa_pkts = 0;

	  current_sa_index = vnet_buffer (b[0])->ipsec.sad_index;
	  sa0 = ipsec_sa_get (current_sa_index);

	  /* fetch the second cacheline ASAP */
	  CLIB_PREFETCH (sa0->cacheline1, CLIB_CACHE_LINE_BYTES, LOAD);
	  cpd.icv_sz = sa0->integ_icv_size;
	  cpd.iv_sz = sa0->crypto_iv_size;
	  cpd.flags = sa0->flags;
	  cpd.sa_index = current_sa_index;
	  is_async = im->async_mode | ipsec_sa_is_set_IS_ASYNC (sa0);
	}

      if (is_async)
	{
	  async_op = sa0->crypto_async_dec_op_id;

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
	  err = ESP_DECRYPT_ERROR_HANDOFF;
	  esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
			      ESP_DECRYPT_NEXT_HANDOFF);
	  goto next;
	}

      /* store packet data for next round for easier prefetch */
      pd->sa_data = cpd.sa_data;
      pd->current_data = b[0]->current_data;
      pd->hdr_sz = pd->current_data - vnet_buffer (b[0])->l3_hdr_offset;
      payload = b[0]->data + pd->current_data;
      pd->seq = clib_host_to_net_u32 (((esp_header_t *) payload)->seq);
      pd->is_chain = 0;
      pd2->lb = b[0];
      pd2->free_buffer_index = 0;
      pd2->icv_removed = 0;

      if (n_bufs > 1)
	{
	  pd->is_chain = 1;
	  /* find last buffer in the chain */
	  while (pd2->lb->flags & VLIB_BUFFER_NEXT_PRESENT)
	    pd2->lb = vlib_get_buffer (vm, pd2->lb->next_buffer);

	  crypto_ops = &ptd->chained_crypto_ops;
	  integ_ops = &ptd->chained_integ_ops;
	}

      pd->current_length = b[0]->current_length;

      /* anti-reply check */
      if (ipsec_sa_anti_replay_check (sa0, pd->seq))
	{
	  err = ESP_DECRYPT_ERROR_REPLAY;
	  esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
			      ESP_DECRYPT_NEXT_DROP);
	  goto next;
	}

      if (pd->current_length < cpd.icv_sz + esp_sz + cpd.iv_sz)
	{
	  err = ESP_DECRYPT_ERROR_RUNT;
	  esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
			      ESP_DECRYPT_NEXT_DROP);
	  goto next;
	}

      len = pd->current_length - cpd.icv_sz;
      current_sa_pkts += 1;
      current_sa_bytes += vlib_buffer_length_in_chain (vm, b[0]);

      if (is_async)
	{

	  err = esp_decrypt_prepare_async_frame (
	    vm, node, ptd, async_frames[async_op], sa0, payload, len,
	    cpd.icv_sz, cpd.iv_sz, pd, pd2, from[b - bufs], b[0], async_next,
	    async_next_node);
	  if (ESP_DECRYPT_ERROR_RX_PKTS != err)
	    {
	      esp_set_next_index (b[0], node, err, n_noop, noop_nexts,
				  ESP_DECRYPT_NEXT_DROP);
	    }
	}
      else
	esp_decrypt_prepare_sync_op (
	  vm, node, ptd, &crypto_ops, &integ_ops, op, sa0, payload, len,
	  cpd.icv_sz, cpd.iv_sz, pd, pd2, b[0], sync_next, b - bufs);
      /* next */
    next:
      if (ESP_DECRYPT_ERROR_RX_PKTS != err)
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
	  pd += 1;
	  pd2 += 1;
	}
      else
	{
	  n_async++;
	  async_next++;
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
      /* submit all of the open frames */
      vnet_crypto_async_frame_t **async_frame;

      vec_foreach (async_frame, ptd->async_frames)
	{
	  if (vnet_crypto_async_submit_open_frame (vm, *async_frame) < 0)
	    {
	      n_noop += esp_async_recycle_failed_submit (
		vm, *async_frame, node, ESP_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR,
		n_sync, noop_bi, noop_nexts, ESP_DECRYPT_NEXT_DROP);
	      vnet_crypto_async_reset_frame (*async_frame);
	      vnet_crypto_async_free_frame (vm, *async_frame);
	    }
	}
    }

  if (n_sync)
    {
      esp_process_ops (vm, node, ptd->integ_ops, sync_bufs, sync_nexts,
		       ESP_DECRYPT_ERROR_INTEG_ERROR);
      esp_process_chained_ops (vm, node, ptd->chained_integ_ops, sync_bufs,
			       sync_nexts, ptd->chunks,
			       ESP_DECRYPT_ERROR_INTEG_ERROR);

      esp_process_ops (vm, node, ptd->crypto_ops, sync_bufs, sync_nexts,
		       ESP_DECRYPT_ERROR_DECRYPTION_FAILED);
      esp_process_chained_ops (vm, node, ptd->chained_crypto_ops, sync_bufs,
			       sync_nexts, ptd->chunks,
			       ESP_DECRYPT_ERROR_DECRYPTION_FAILED);
    }

  /* Post decryption ronud - adjust packet data start and length and next
     node */

  n_left = n_sync;
  sync_next = sync_nexts;
  pd = pkt_data;
  pd2 = pkt_data2;
  b = sync_bufs;

  while (n_left)
    {
      if (n_left >= 2)
	{
	  void *data = b[1]->data + pd[1].current_data;

	  /* buffer metadata */
	  vlib_prefetch_buffer_header (b[1], LOAD);

	  /* esp_footer_t */
	  CLIB_PREFETCH (data + pd[1].current_length - pd[1].icv_sz - 2,
			 CLIB_CACHE_LINE_BYTES, LOAD);

	  /* packet headers */
	  CLIB_PREFETCH (data - CLIB_CACHE_LINE_BYTES,
			 CLIB_CACHE_LINE_BYTES * 2, LOAD);
	}

      /* save the sa_index as GRE_teb post_crypto changes L2 opaque */
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	current_sa_index = vnet_buffer (b[0])->ipsec.sad_index;

      if (sync_next[0] >= ESP_DECRYPT_N_NEXT)
	esp_decrypt_post_crypto (vm, node, pd, pd2, b[0], sync_next, is_ip6,
				 is_tun, 0);

      /* trace: */
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_decrypt_trace_t *tr;
	  tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  sa0 = ipsec_sa_get (current_sa_index);
	  tr->crypto_alg = sa0->crypto_alg;
	  tr->integ_alg = sa0->integ_alg;
	  tr->seq = pd->seq;
	  tr->sa_seq = sa0->last_seq;
	  tr->sa_seq_hi = sa0->seq_hi;
	}

      /* next */
      n_left -= 1;
      sync_next += 1;
      pd += 1;
      pd2 += 1;
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

      if (!pd->is_chain)
	esp_decrypt_post_crypto (vm, node, pd, 0, b[0], next, is_ip6, is_tun,
				 1);
      else
	{
	  esp_decrypt_packet_data2_t *pd2 = esp_post_data2 (b[0]);
	  esp_decrypt_post_crypto (vm, node, pd, pd2, b[0], next, is_ip6,
				   is_tun, 1);
	}

      /*trace: */
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsec_sa_t *sa0 = ipsec_sa_get (pd->sa_index);
	  esp_decrypt_trace_t *tr;
	  esp_decrypt_packet_data_t *async_pd =
	    &(esp_post_data (b[0]))->decrypt_data;
	  tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  sa0 = ipsec_sa_get (async_pd->sa_index);

	  tr->crypto_alg = sa0->crypto_alg;
	  tr->integ_alg = sa0->integ_alg;
	  tr->seq = pd->seq;
	  tr->sa_seq = sa0->last_seq;
	  tr->sa_seq_hi = sa0->seq_hi;
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
    [ESP_DECRYPT_NEXT_DROP] = "ip4-drop",
    [ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-drop",
    [ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
    [ESP_DECRYPT_NEXT_HANDOFF] = "esp4-decrypt-handoff",
  },
};

VLIB_REGISTER_NODE (esp4_decrypt_post_node) = {
  .name = "esp4-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .sibling_of = "esp4-decrypt",
};

VLIB_REGISTER_NODE (esp6_decrypt_node) = {
  .name = "esp6-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ESP_DECRYPT_NEXT_DROP] = "ip6-drop",
    [ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-drop",
    [ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
    [ESP_DECRYPT_NEXT_HANDOFF]=  "esp6-decrypt-handoff",
  },
};

VLIB_REGISTER_NODE (esp6_decrypt_post_node) = {
  .name = "esp6-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .sibling_of = "esp6-decrypt",
};

VLIB_REGISTER_NODE (esp4_decrypt_tun_node) = {
  .name = "esp4-decrypt-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,
  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ESP_DECRYPT_NEXT_DROP] = "ip4-drop",
    [ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-input",
    [ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
    [ESP_DECRYPT_NEXT_HANDOFF] = "esp4-decrypt-tun-handoff",
  },
};

VLIB_REGISTER_NODE (esp4_decrypt_tun_post_node) = {
  .name = "esp4-decrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .sibling_of = "esp4-decrypt-tun",
};

VLIB_REGISTER_NODE (esp6_decrypt_tun_node) = {
  .name = "esp6-decrypt-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,
  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ESP_DECRYPT_NEXT_DROP] = "ip6-drop",
    [ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-input",
    [ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
    [ESP_DECRYPT_NEXT_HANDOFF]=  "esp6-decrypt-tun-handoff",
  },
};

VLIB_REGISTER_NODE (esp6_decrypt_tun_post_node) = {
  .name = "esp6-decrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .sibling_of = "esp6-decrypt-tun",
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT

static clib_error_t *
esp_decrypt_init (vlib_main_t *vm)
{
  ipsec_main_t *im = &ipsec_main;

  im->esp4_dec_fq_index =
    vlib_frame_queue_main_init (esp4_decrypt_node.index, 0);
  im->esp6_dec_fq_index =
    vlib_frame_queue_main_init (esp6_decrypt_node.index, 0);
  im->esp4_dec_tun_fq_index =
    vlib_frame_queue_main_init (esp4_decrypt_tun_node.index, 0);
  im->esp6_dec_tun_fq_index =
    vlib_frame_queue_main_init (esp6_decrypt_tun_node.index, 0);

  return 0;
}

VLIB_INIT_FUNCTION (esp_decrypt_init);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
