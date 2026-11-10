/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/dev/dev.h>
#include <octeon_common.h>
#include <crypto.h>

#define OCT_SG_MAX_PTRS (OCT_SG_MAX_COMP * OCT_SG_PER_COMP)

typedef struct
{
  oct_sg_comp_t *comp;
  u32 n;
} oct_sg_t;

#ifdef PLATFORM_OCTEON9
static_always_inline void
oct_cpt_inst_submit (struct cpt_inst_s *inst, u64 lmtline, u64 io_addr)
{
  /* the LMTST is retried until the hardware accepts it */
  for (u64 accepted = 0; accepted == 0;)
    {
      roc_lmt_mov64 ((void *) lmtline, inst);
      asm volatile ("dmb oshst" ::: "memory");
      accepted = roc_lmt_submit_ldeor (io_addr);
    }
}
#endif

static_always_inline void
oct_crypto_burst_submit (oct_crypto_queue_t *q, struct cpt_inst_s *inst, u32 n_left)
{
#ifdef PLATFORM_OCTEON9
  for (u32 i = 0; i < n_left; i++)
    oct_cpt_inst_submit (inst + i, q->lf->lmt_base, q->lf->io_addr);
#else
  u64 lmt_base = q->lmtline.lmt_base, lmt_id;

  ROC_LMT_CPT_BASE_ID_GET (lmt_base, lmt_id);

  while (n_left)
    {
      /* 16 LMT lines per core, one instruction per line */
      u32 n = clib_min (n_left, 16);

      /* LMT lines may still be in use by the previous submit */
      asm volatile ("dmb oshst" ::: "memory");

      for (u32 i = 0; i < n; i++)
	roc_lmt_mov_seg ((void *) (lmt_base + ((u64) i << ROC_LMT_LINE_SIZE_LOG2)), inst + i,
			 sizeof (inst[0]) / 16);

      roc_lmt_submit_steorl (ROC_CN10K_CPT_LMT_ARG | (u64) (n - 1) << 12 | lmt_id,
			     q->lmtline.io_addr);
      inst += n;
      n_left -= n;
    }
#endif
}

static_always_inline u32
oct_sg_n_comp (oct_sg_t *sg)
{
  return (sg->n + OCT_SG_PER_COMP - 1) / OCT_SG_PER_COMP;
}

static_always_inline void
oct_sg_add (oct_sg_t *sg, void *p, u32 len)
{
  oct_sg_comp_t *c = sg->comp + sg->n / OCT_SG_PER_COMP;
  u32 i = sg->n % OCT_SG_PER_COMP;

#ifdef PLATFORM_OCTEON9
  c->u.s.len[i] = clib_host_to_net_u16 (len);
  c->ptr[i] = clib_host_to_net_u64 (pointer_to_uword (p));
#else
  c->u.s.len[i] = len;
  c->ptr[i] = pointer_to_uword (p);
  c->u.s.valid_segs = i + 1;
#endif
  sg->n++;
}

/* adds len bytes starting at p in buffer b, following the chain */
static_always_inline int
oct_sg_add_data (vlib_main_t *vm, oct_sg_t *sg, vlib_buffer_t *b, u8 *p, u32 len)
{
  while (1)
    {
      u32 n = clib_min (len, (u8 *) vlib_buffer_get_tail (b) - p);

      oct_sg_add (sg, p, n);
      len -= n;
      if (len == 0)
	return 0;

      /* keep one entry for the MAC */
      if ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0 || sg->n >= OCT_SG_MAX_PTRS - 1)
	return -1;

      b = vlib_get_buffer (vm, b->next_buffer);
      p = vlib_buffer_get_current (b);
    }
}

static_always_inline int
oct_crypto_inst_prep (vlib_main_t *vm, oct_crypto_key_t *ckey, struct cpt_inst_s *inst,
		      vlib_buffer_t *b, vnet_crypto_buffer_metadata_t *md, oct_crypto_meta_t *m,
		      const u8 is_aead, const u8 aad_len, const u8 is_enc)
{
  union cpt_inst_w4 w4 = { .u64 = is_enc ? ckey->enc_inst_w4 : ckey->dec_inst_w4 };
  u8 *iv = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->iv_off);
  u8 *icv = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->icv_off);
  u8 *c = b->data + md->cipher_data_start_off, *start;
  u32 iv_len = 16, mac_len = ckey->mac_len, cl = md->cipher_data_len;
  u32 *iv_d = (u32 *) m->iv;
  u32 enc_off, auth_off, auth_len, data_len;
#ifdef PLATFORM_OCTEON9
  oct_sg_t g = { .comp = m->sg }, s;
  u16 *hdr = m->sg_hdr;
#else
  oct_sg_t g = { .comp = m->gather }, s;
#endif

  if (is_aead)
    {
      start = c;
      auth_off = iv_len;
      enc_off = iv_len + aad_len;
      auth_len = aad_len + cl;
      data_len = cl;
    }
  else
    {
      u8 *a = b->data + md->auth_data_start_off;
      u32 enc_len = cl;

      start = a < c ? a : c;
      enc_off = c - start + iv_len;
      auth_off = a - start + iv_len;
      auth_len = md->auth_data_len;
      if (is_enc && (cl & 0xf) && ckey->cbc_pad)
	enc_len = round_pow2 (cl, 8);
      data_len = clib_max (enc_off + enc_len, auth_off + auth_len) - iv_len;
    }

  if (PREDICT_FALSE (enc_off > CLIB_U16_MAX || auth_off > CLIB_U8_MAX))
    return -1;

  m->offset_ctrl = clib_host_to_net_u64 (((u64) enc_off << 16) | auth_off);

  clib_memcpy_fast (iv_d, iv, 12);
  /* hardware takes a 16 byte IV, a 12 byte nonce is followed by the counter */
  iv_d[3] = ckey->iv_length == 16 ? ((u32u *) iv)[3] : clib_host_to_net_u32 (1);

  /* AAD follows the IV so the offset control word, IV and AAD take one entry */
  if (aad_len)
    clib_memcpy_fast (m->aad, vnet_crypto_buffer_metadata_get_ptr (vm, b, md->aad_off), aad_len);

  oct_sg_add (&g, m, ROC_SE_OFF_CTRL_LEN + iv_len + aad_len);
  if (data_len && oct_sg_add_data (vm, &g, b, start, data_len))
    return -1;
  if (is_enc == 0 && mac_len)
    oct_sg_add (&g, icv, mac_len);

#ifdef PLATFORM_OCTEON9
  s.comp = g.comp + oct_sg_n_comp (&g);
#else
  s.comp = m->scatter;
#endif
  s.n = 0;

  oct_sg_add (&s, m->iv, iv_len + aad_len);
  if (data_len && oct_sg_add_data (vm, &s, b, start, data_len))
    return -1;
  if (is_enc && mac_len)
    oct_sg_add (&s, icv, mac_len);

  w4.s.param1 = cl;
  w4.s.param2 = auth_len;

#ifdef PLATFORM_OCTEON9
  hdr[0] = 0;
  hdr[1] = 0;
  hdr[2] = clib_host_to_net_u16 (g.n);
  hdr[3] = clib_host_to_net_u16 (s.n);
  w4.s.dlen = (u8 *) (s.comp + oct_sg_n_comp (&s)) - (u8 *) hdr;
  inst->dptr = pointer_to_uword (hdr);
#else
  w4.s.dlen = ROC_SE_OFF_CTRL_LEN + iv_len + aad_len + data_len + (is_enc ? 0 : mac_len);
  inst->w5 = (union cpt_inst_w5) {
    .s.dptr = pointer_to_uword (g.comp),
    .s.gather_sz = oct_sg_n_comp (&g),
  };
  inst->w6 = (union cpt_inst_w6) {
    .s.rptr = pointer_to_uword (s.comp),
    .s.scatter_sz = oct_sg_n_comp (&s),
  };
#endif
  inst->w4 = w4;

  return 0;
}

static_always_inline void
oct_crypto_frame_fail (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
		       vnet_dev_crypto_error_t error)
{
  vlib_error_drop_buffers (vm, node, vlib_frame_vector_args (frame), 0, frame->n_vectors, 0,
			   node->node_index, error);
  vlib_frame_free (vm, frame);
}

static void
oct_crypto_enq_trace (vlib_main_t *vm, vlib_node_runtime_t *node, oct_crypto_queue_t *q,
		      vlib_frame_t *frame, struct cpt_inst_s *inst)
{
  u32 *bi = vlib_frame_vector_args (frame);

  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[i]);
      oct_crypto_enq_trace_t *t;

      if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
	continue;

      t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->lf_id = q->lf->lf_id;
      t->slot = (u16) (q->elt_tail + i) & (q->n_desc - 1);
      t->inst = inst[i];
    }
}

static_always_inline void
oct_crypto_enq_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_crypto_queue_t *cq,
		      vlib_frame_t *frame, const u8 is_aead, u8 aad_len, const u8 is_enc)
{
  oct_crypto_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  struct cpt_inst_s inst[VLIB_FRAME_SIZE];
  vnet_crypto_ctx_t **ctxs = vlib_frame_aux_args (frame);
  u32 *bi = vlib_frame_vector_args (frame);
  u32 i, nb_infl_allowed, n_elts = frame->n_vectors;
  vnet_crypto_buffer_metadata_t *md;
  u16 elt_tail, slot, mask;
  oct_crypto_key_t *ckey;
  u64 n_bytes = 0;
  vlib_buffer_t *b;
  oct_crypto_meta_t *meta;

  nb_infl_allowed = q->n_desc - (u16) (q->elt_tail - q->elt_head);
  if (PREDICT_FALSE (nb_infl_allowed < n_elts))
    {
      cq->enq_full += n_elts;
      oct_crypto_frame_fail (vm, node, frame, VNET_DEV_CRYPTO_ERROR_QUEUE_FULL);
      return;
    }

  meta = q->meta;
  elt_tail = q->elt_tail;
  mask = q->n_desc - 1;

  for (i = 0; i < n_elts; i++)
    {
      slot = elt_tail & mask;
      ckey = (oct_crypto_key_t *) vnet_crypto_get_async_key_data (ctxs[i]);

      if (PREDICT_FALSE (ckey->enc_ctx == 0))
	goto error;

      b = vlib_get_buffer (vm, bi[i]);
      md = vnet_crypto_buffer_get_metadata (b);
      n_bytes += clib_max (md->cipher_data_len, md->auth_data_len);

      inst[i] = (struct cpt_inst_s) {};
      if (PREDICT_FALSE (oct_crypto_inst_prep (vm, ckey, inst + i, b, md, meta + slot, is_aead,
					       aad_len, is_enc)))
	goto error;

      inst[i].w7.u64 = is_enc ? ckey->enc_inst_w7 : ckey->dec_inst_w7;
      inst[i].res_addr = pointer_to_uword (&meta[slot].res);
      elt_tail++;
    }

  oct_crypto_burst_submit (q, inst, n_elts);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    oct_crypto_enq_trace (vm, node, q, frame, inst);

  q->elt_tail = elt_tail;
  q->frames[q->frame_tail++ & mask] = frame;
  cq->enq_req += n_elts;
  cq->enq_bytes += n_bytes;
  return;

error:
  cq->enq_err += n_elts;
  oct_crypto_frame_fail (vm, node, frame, VNET_DEV_CRYPTO_ERROR_ENGINE_ERROR);
}

#define _(n, s, is_aead, aad_len, is_enc)                                                          \
  static_always_inline void oct_crypto_enqueue_##n (                                               \
    vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_crypto_queue_t *cq, vlib_frame_t *frame)  \
  {                                                                                                \
    oct_crypto_enq_queue (vm, node, cq, frame, is_aead, aad_len, is_enc);                          \
  }                                                                                                \
                                                                                                   \
  VNET_DEV_NODE_FN (oct_crypto_enq_##n##_node)                                                     \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)                             \
  {                                                                                                \
    return vnet_dev_crypto_enq_node_inline (vm, node, frame, oct_crypto_enqueue_##n);              \
  }
foreach_oct_crypto_enqueue_node
#undef _
