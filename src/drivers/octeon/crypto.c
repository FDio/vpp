/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <octeon.h>
#include <crypto.h>
#include <base/roc_api.h>
#include "common.h"

oct_crypto_main_t oct_crypto_main;
oct_crypto_dev_t oct_crypto_dev;

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "crypto",
};

static_always_inline void
oct_map_keyindex_to_session (oct_crypto_sess_t *sess, u32 key_index, u8 type)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  oct_crypto_key_t *ckey;

  ckey = vec_elt_at_index (ocm->keys[type], key_index);

  ckey->sess = sess;
  sess->key_index = key_index;
}

static_always_inline oct_crypto_sess_t *
oct_crypto_session_alloc (vlib_main_t *vm, u8 type)
{
  extern oct_plt_init_param_t oct_plt_init_param;
  oct_crypto_sess_t *addr = NULL;
  oct_crypto_main_t *ocm;
  oct_crypto_dev_t *ocd;
  u32 size;

  ocm = &oct_crypto_main;
  ocd = ocm->crypto_dev[type];

  size = sizeof (oct_crypto_sess_t);

  addr = oct_plt_init_param.oct_plt_zmalloc (size, CLIB_CACHE_LINE_BYTES);
  if (addr == NULL)
    {
      log_err (ocd->dev, "Failed to allocate crypto session memory");
      return NULL;
    }

  return addr;
}

static_always_inline i32
oct_crypto_session_create (vlib_main_t *vm, vnet_crypto_key_index_t key_index,
			   int op_type)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  oct_crypto_sess_t *session;
  vnet_crypto_key_t *key;
  oct_crypto_key_t *ckey;
  oct_crypto_dev_t *ocd;

  ocd = ocm->crypto_dev[op_type];

  key = vnet_crypto_get_key (key_index);

  if (key->is_link)
    {
      /*
       * Read crypto or integ key session. And map link key index to same.
       */
      if (key->index_crypto != UINT32_MAX)
	{
	  ckey = vec_elt_at_index (ocm->keys[op_type], key->index_crypto);
	  session = ckey->sess;
	}
      else if (key->index_integ != UINT32_MAX)
	{
	  ckey = vec_elt_at_index (ocm->keys[op_type], key->index_integ);
	  session = ckey->sess;
	}
      else
	return -1;
    }
  else
    {
      session = oct_crypto_session_alloc (vm, op_type);
      if (session == NULL)
	return -1;
      session->crypto_dev = ocd;
    }

  oct_map_keyindex_to_session (session, key_index, op_type);
  return 0;
}

void
oct_crypto_key_del_handler (vlib_main_t *vm, vnet_crypto_key_index_t key_index)
{
  extern oct_plt_init_param_t oct_plt_init_param;
  oct_crypto_main_t *ocm = &oct_crypto_main;
  oct_crypto_key_t *ckey_linked;
  oct_crypto_key_t *ckey;

  vec_validate (ocm->keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], key_index);

  ckey = vec_elt_at_index (ocm->keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  if (ckey->sess)
    {
      /*
       * If in case link algo is pointing to same sesison, reset the pointer.
       */
      if (ckey->sess->key_index != key_index)
	{
	  ckey_linked = vec_elt_at_index (
	    ocm->keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], ckey->sess->key_index);
	  ckey_linked->sess = NULL;
	}

      /* Trigger CTX flush + invalidate to remove from CTX_CACHE */
      if (oct_hw_ctx_cache_enable ())
	roc_cpt_lf_ctx_flush (&ckey->sess->crypto_dev->lf,
			      &ckey->sess->cpt_ctx.se_ctx, true);

      oct_plt_init_param.oct_plt_free (ckey->sess);
      ckey->sess = NULL;
    }

  ckey = vec_elt_at_index (ocm->keys[VNET_CRYPTO_OP_TYPE_DECRYPT], key_index);
  if (ckey->sess)
    {
      /*
       * If in case link algo is pointing to same sesison, reset the pointer.
       */
      if (ckey->sess->key_index != key_index)
	{
	  ckey_linked = vec_elt_at_index (
	    ocm->keys[VNET_CRYPTO_OP_TYPE_DECRYPT], ckey->sess->key_index);
	  ckey_linked->sess = NULL;
	}

      /* Trigger CTX flush + invalidate to remove from CTX_CACHE */
      if (oct_hw_ctx_cache_enable ())
	roc_cpt_lf_ctx_flush (&ckey->sess->crypto_dev->lf,
			      &ckey->sess->cpt_ctx.se_ctx, true);

      oct_plt_init_param.oct_plt_free (ckey->sess);
      ckey->sess = NULL;
    }
}

void
oct_crypto_key_add_handler (vlib_main_t *vm, vnet_crypto_key_index_t key_index)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  oct_crypto_key_t *ckey;
  oct_crypto_dev_t *ocd = &oct_crypto_dev;

  vec_validate (ocm->keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  ckey = vec_elt_at_index (ocm->keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  if (ckey->sess == NULL)
    {
      if (oct_crypto_session_create (vm, key_index,
				     VNET_CRYPTO_OP_TYPE_ENCRYPT))
	{
	  log_err (ocd->dev, "Unable to create crypto session");
	  return;
	}
    }

  vec_validate (ocm->keys[VNET_CRYPTO_OP_TYPE_DECRYPT], key_index);
  ckey = vec_elt_at_index (ocm->keys[VNET_CRYPTO_OP_TYPE_DECRYPT], key_index);
  if (ckey->sess == NULL)
    {
      if (oct_crypto_session_create (vm, key_index,
				     VNET_CRYPTO_OP_TYPE_DECRYPT))
	{
	  log_err (ocd->dev, "Unable to create crypto session");
	  return;
	}
    }
}

void
oct_crypto_key_handler (vnet_crypto_key_op_t kop, void *key_data, vnet_crypto_alg_t alg,
			const u8 *data, u16 length)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  vnet_crypto_key_index_t idx = (vnet_crypto_key_index_t) (uword) key_data;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      oct_crypto_key_del_handler (vlib_get_main (), idx);
      return;
    }

  /* For ADD/MODIFY, (re)create sessions based on key_index */
  oct_crypto_key_add_handler (vlib_get_main (), idx);

  ocm->started = 1;
}

static_always_inline void
oct_crypto_session_free (vlib_main_t *vm, oct_crypto_sess_t *sess)
{
  extern oct_plt_init_param_t oct_plt_init_param;

  oct_plt_init_param.oct_plt_free (sess);
  return;
}

#ifdef PLATFORM_OCTEON9
static inline void
oct_cpt_inst_submit (struct cpt_inst_s *inst, uint64_t lmtline,
		     uint64_t io_addr)
{
  uint64_t lmt_status;

  do
    {
      /* Copy CPT command to LMTLINE */
      roc_lmt_mov64 ((void *) lmtline, inst);

      /*
       * Make sure compiler does not reorder memcpy and ldeor.
       * LMTST transactions are always flushed from the write
       * buffer immediately, a DMB is not required to push out
       * LMTSTs.
       */
      asm volatile ("dmb oshst" : : : "memory");
      lmt_status = roc_lmt_submit_ldeor (io_addr);
    }
  while (lmt_status == 0);
}
#endif

static_always_inline void
oct_crypto_burst_submit (oct_crypto_dev_t *crypto_dev, struct cpt_inst_s *inst,
			 u32 n_left)
{
  u64 lmt_base;
  u64 io_addr;
  u32 count;

#ifdef PLATFORM_OCTEON9
  lmt_base = crypto_dev->lf.lmt_base;
  io_addr = crypto_dev->lf.io_addr;

  for (count = 0; count < n_left; count++)
    oct_cpt_inst_submit (inst + count, lmt_base, io_addr);
#else
  u64 *lmt_line[OCT_MAX_LMT_SZ];
  u64 lmt_arg, core_lmt_id;

  lmt_base = crypto_dev->lmtline.lmt_base;
  io_addr = crypto_dev->lmtline.io_addr;

  ROC_LMT_CPT_BASE_ID_GET (lmt_base, core_lmt_id);

  for (count = 0; count < 16; count++)
    {
      lmt_line[count] = OCT_CPT_LMT_GET_LINE_ADDR (lmt_base, count);
    }

  while (n_left > OCT_MAX_LMT_SZ)
    {

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      asm volatile ("dmb oshst" ::: "memory");

      lmt_arg = ROC_CN10K_CPT_LMT_ARG | (u64) core_lmt_id;

      for (count = 0; count < 16; count++)
	{
	  roc_lmt_mov_seg ((void *) lmt_line[count], inst + count,
			   CPT_LMT_SIZE_COPY);
	}

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (OCT_MAX_LMT_SZ - 1) << 12;

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      inst += OCT_MAX_LMT_SZ;
      n_left -= OCT_MAX_LMT_SZ;
    }

  if (n_left > 0)
    {
      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      asm volatile ("dmb oshst" ::: "memory");

      lmt_arg = ROC_CN10K_CPT_LMT_ARG | (u64) core_lmt_id;

      for (count = 0; count < n_left; count++)
	{
	  roc_lmt_mov_seg ((void *) lmt_line[count], inst + count,
			   CPT_LMT_SIZE_COPY);
	}

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (n_left - 1) << 12;

      roc_lmt_submit_steorl (lmt_arg, io_addr);
    }
#endif
}

static_always_inline uint32_t
oct_crypto_fill_sg_comp_from_iov (struct roc_sglist_comp *list, uint32_t i,
				  struct roc_se_iov_ptr *from,
				  uint32_t from_offset, uint32_t *psize,
				  struct roc_se_buf_ptr *extra_buf,
				  uint32_t extra_offset)
{
  uint32_t extra_len = extra_buf ? extra_buf->size : 0;
  uint32_t size = *psize;
  int32_t j;

  for (j = 0; j < from->buf_cnt; j++)
    {
      struct roc_sglist_comp *to = &list[i >> 2];
      uint32_t buf_sz = from->bufs[j].size;
      void *vaddr = from->bufs[j].vaddr;
      uint64_t e_vaddr;
      uint32_t e_len;

      if (PREDICT_FALSE (from_offset))
	{
	  if (from_offset >= buf_sz)
	    {
	      from_offset -= buf_sz;
	      continue;
	    }
	  e_vaddr = (uint64_t) vaddr + from_offset;
	  e_len = clib_min ((buf_sz - from_offset), size);
	  from_offset = 0;
	}
      else
	{
	  e_vaddr = (uint64_t) vaddr;
	  e_len = clib_min (buf_sz, size);
	}

      to->u.s.len[i % 4] = clib_host_to_net_u16 (e_len);
      to->ptr[i % 4] = clib_host_to_net_u64 (e_vaddr);

      if (extra_len && (e_len >= extra_offset))
	{
	  /* Break the data at given offset */
	  uint32_t next_len = e_len - extra_offset;
	  uint64_t next_vaddr = e_vaddr + extra_offset;

	  if (!extra_offset)
	    {
	      i--;
	    }
	  else
	    {
	      e_len = extra_offset;
	      size -= e_len;
	      to->u.s.len[i % 4] = clib_host_to_net_u16 (e_len);
	    }

	  extra_len = clib_min (extra_len, size);
	  /* Insert extra data ptr */
	  if (extra_len)
	    {
	      i++;
	      to = &list[i >> 2];
	      to->u.s.len[i % 4] = clib_host_to_net_u16 (extra_len);
	      to->ptr[i % 4] =
		clib_host_to_net_u64 ((uint64_t) extra_buf->vaddr);
	      size -= extra_len;
	    }

	  next_len = clib_min (next_len, size);
	  /* insert the rest of the data */
	  if (next_len)
	    {
	      i++;
	      to = &list[i >> 2];
	      to->u.s.len[i % 4] = clib_host_to_net_u16 (next_len);
	      to->ptr[i % 4] = clib_host_to_net_u64 (next_vaddr);
	      size -= next_len;
	    }
	  extra_len = 0;
	}
      else
	{
	  size -= e_len;
	}
      if (extra_offset)
	extra_offset -= size;
      i++;

      if (PREDICT_FALSE (!size))
	break;
    }

  *psize = size;
  return (uint32_t) i;
}

static_always_inline u32
oct_crypto_fill_sg2_comp_from_iov (struct roc_sg2list_comp *list, u32 i,
				   struct roc_se_iov_ptr *from,
				   u32 from_offset, u32 *psize,
				   struct roc_se_buf_ptr *extra_buf,
				   u32 extra_offset)
{
  u32 extra_len = extra_buf ? extra_buf->size : 0;
  u32 size = *psize, buf_sz, e_len, next_len;
  struct roc_sg2list_comp *to;
  u64 e_vaddr, next_vaddr;
  void *vaddr;
  i32 j;

  for (j = 0; j < from->buf_cnt; j++)
    {
      to = &list[i / 3];
      buf_sz = from->bufs[j].size;
      vaddr = from->bufs[j].vaddr;

      if (PREDICT_FALSE (from_offset))
	{
	  if (from_offset >= buf_sz)
	    {
	      from_offset -= buf_sz;
	      continue;
	    }
	  e_vaddr = (u64) vaddr + from_offset;
	  e_len = clib_min ((buf_sz - from_offset), size);
	  from_offset = 0;
	}
      else
	{
	  e_vaddr = (u64) vaddr;
	  e_len = clib_min (buf_sz, size);
	}

      to->u.s.len[i % 3] = (e_len);
      to->ptr[i % 3] = (e_vaddr);
      to->u.s.valid_segs = (i % 3) + 1;

      if (extra_len && (e_len >= extra_offset))
	{
	  /* Break the data at given offset */
	  next_len = e_len - extra_offset;
	  next_vaddr = e_vaddr + extra_offset;

	  if (!extra_offset)
	    i--;
	  else
	    {
	      e_len = extra_offset;
	      size -= e_len;
	      to->u.s.len[i % 3] = (e_len);
	    }

	  extra_len = clib_min (extra_len, size);
	  /* Insert extra data ptr */
	  if (extra_len)
	    {
	      i++;
	      to = &list[i / 3];
	      to->u.s.len[i % 3] = (extra_len);
	      to->ptr[i % 3] = ((u64) extra_buf->vaddr);
	      to->u.s.valid_segs = (i % 3) + 1;
	      size -= extra_len;
	    }

	  next_len = clib_min (next_len, size);
	  /* insert the rest of the data */
	  if (next_len)
	    {
	      i++;
	      to = &list[i / 3];
	      to->u.s.len[i % 3] = (next_len);
	      to->ptr[i % 3] = (next_vaddr);
	      to->u.s.valid_segs = (i % 3) + 1;
	      size -= next_len;
	    }
	  extra_len = 0;
	}
      else
	size -= e_len;

      if (extra_offset)
	extra_offset -= size;

      i++;

      if (PREDICT_FALSE (!size))
	break;
    }

  *psize = size;
  return (u32) i;
}

static_always_inline uint32_t
oct_crypto_fill_sg_comp_from_buf (struct roc_sglist_comp *list, uint32_t i,
				  struct roc_se_buf_ptr *from)
{
  struct roc_sglist_comp *to = &list[i >> 2];

  to->u.s.len[i % 4] = clib_host_to_net_u16 (from->size);
  to->ptr[i % 4] = clib_host_to_net_u64 ((uint64_t) from->vaddr);
  return ++i;
}

static_always_inline uint32_t
oct_crypto_fill_sg_comp (struct roc_sglist_comp *list, uint32_t i,
			 uint64_t dma_addr, uint32_t size)
{
  struct roc_sglist_comp *to = &list[i >> 2];

  to->u.s.len[i % 4] = clib_host_to_net_u16 (size);
  to->ptr[i % 4] = clib_host_to_net_u64 (dma_addr);
  return ++i;
}

static_always_inline u32
oct_crypto_fill_sg2_comp (struct roc_sg2list_comp *list, u32 index,
			  u64 dma_addr, u32 size)
{
  struct roc_sg2list_comp *to = &list[index / 3];

  to->u.s.len[index % 3] = (size);
  to->ptr[index % 3] = (dma_addr);
  to->u.s.valid_segs = (index % 3) + 1;
  return ++index;
}

static_always_inline u32
oct_crypto_fill_sg2_comp_from_buf (struct roc_sg2list_comp *list, u32 index,
				   struct roc_se_buf_ptr *from)
{
  struct roc_sg2list_comp *to = &list[index / 3];

  to->u.s.len[index % 3] = (from->size);
  to->ptr[index % 3] = ((u64) from->vaddr);
  to->u.s.valid_segs = (index % 3) + 1;
  return ++index;
}

static_always_inline int __attribute__ ((unused))
oct_crypto_sg_inst_prep (struct roc_se_fc_params *params,
			 struct cpt_inst_s *inst, uint64_t offset_ctrl,
			 const uint8_t *iv_s, int iv_len, uint8_t pack_iv,
			 uint8_t pdcp_alg_type, int32_t inputlen,
			 int32_t outputlen, uint32_t passthrough_len,
			 uint32_t req_flags, int pdcp_flag, int decrypt)
{
  struct roc_sglist_comp *gather_comp, *scatter_comp;
  void *m_vaddr = params->meta_buf.vaddr;
  struct roc_se_buf_ptr *aad_buf = NULL;
  uint32_t mac_len = 0, aad_len = 0;
  struct roc_se_ctx *se_ctx;
  uint32_t i, g_size_bytes;
  uint64_t *offset_vaddr;
  uint32_t s_size_bytes;
  uint8_t *in_buffer;
  uint32_t size;
  uint8_t *iv_d;
  int ret = 0;

  se_ctx = params->ctx;
  mac_len = se_ctx->mac_len;

  if (PREDICT_FALSE (req_flags & ROC_SE_VALID_AAD_BUF))
    {
      /* We don't support both AAD and auth data separately */
      aad_len = params->aad_buf.size;
      aad_buf = &params->aad_buf;
    }

  /* save space for iv */
  offset_vaddr = m_vaddr;

  m_vaddr =
    (uint8_t *) m_vaddr + ROC_SE_OFF_CTRL_LEN + PLT_ALIGN_CEIL (iv_len, 8);

  inst->w4.s.opcode_major |= (uint64_t) ROC_DMA_MODE_SG;

  /* iv offset is 0 */
  *offset_vaddr = offset_ctrl;

  iv_d = ((uint8_t *) offset_vaddr + ROC_SE_OFF_CTRL_LEN);

  if (PREDICT_TRUE (iv_len))
    memcpy (iv_d, iv_s, iv_len);

  /* DPTR has SG list */

  /* TODO Add error check if space will be sufficient */
  gather_comp = (struct roc_sglist_comp *) ((uint8_t *) m_vaddr + 8);

  /*
   * Input Gather List
   */
  i = 0;

  /* Offset control word followed by iv */

  i = oct_crypto_fill_sg_comp (gather_comp, i, (uint64_t) offset_vaddr,
			       ROC_SE_OFF_CTRL_LEN + iv_len);

  /* Add input data */
  if (decrypt && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = inputlen - iv_len - mac_len;

      if (PREDICT_TRUE (size))
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;
	  i = oct_crypto_fill_sg_comp_from_iov (
	    gather_comp, i, params->src_iov, 0, &size, aad_buf, aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      clib_warning ("Cryptodev: Insufficient buffer"
			    " space, size %d needed",
			    size);
	      return -1;
	    }
	}

      if (mac_len)
	i =
	  oct_crypto_fill_sg_comp_from_buf (gather_comp, i, &params->mac_buf);
    }
  else
    {
      /* input data */
      size = inputlen - iv_len;
      if (size)
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;
	  i = oct_crypto_fill_sg_comp_from_iov (
	    gather_comp, i, params->src_iov, 0, &size, aad_buf, aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      clib_warning ("Cryptodev: Insufficient buffer space,"
			    " size %d needed",
			    size);
	      return -1;
	    }
	}
    }

  in_buffer = m_vaddr;
  ((uint16_t *) in_buffer)[0] = 0;
  ((uint16_t *) in_buffer)[1] = 0;
  ((uint16_t *) in_buffer)[2] = clib_host_to_net_u16 (i);

  g_size_bytes = ((i + 3) / 4) * sizeof (struct roc_sglist_comp);
  /*
   * Output Scatter List
   */

  i = 0;
  scatter_comp =
    (struct roc_sglist_comp *) ((uint8_t *) gather_comp + g_size_bytes);

  i = oct_crypto_fill_sg_comp (
    scatter_comp, i, (uint64_t) offset_vaddr + ROC_SE_OFF_CTRL_LEN, iv_len);

  /* Add output data */
  if ((!decrypt) && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = outputlen - iv_len - mac_len;
      if (size)
	{

	  uint32_t aad_offset = aad_len ? passthrough_len : 0;

	  i = oct_crypto_fill_sg_comp_from_iov (
	    scatter_comp, i, params->dst_iov, 0, &size, aad_buf, aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      clib_warning ("Cryptodev: Insufficient buffer space,"
			    " size %d needed",
			    size);
	      return -1;
	    }
	}

      /* mac data */
      if (mac_len)
	i =
	  oct_crypto_fill_sg_comp_from_buf (scatter_comp, i, &params->mac_buf);
    }
  else
    {
      /* Output including mac */
      size = outputlen - iv_len;

      if (size)
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;

	  i = oct_crypto_fill_sg_comp_from_iov (
	    scatter_comp, i, params->dst_iov, 0, &size, aad_buf, aad_offset);

	  if (PREDICT_FALSE (size))
	    {
	      clib_warning ("Cryptodev: Insufficient buffer space,"
			    " size %d needed",
			    size);
	      return -1;
	    }
	}
    }
  ((uint16_t *) in_buffer)[3] = clib_host_to_net_u16 (i);
  s_size_bytes = ((i + 3) / 4) * sizeof (struct roc_sglist_comp);

  size = g_size_bytes + s_size_bytes + ROC_SG_LIST_HDR_SIZE;

  /* This is DPTR len in case of SG mode */
  inst->w4.s.dlen = size;

  if (PREDICT_FALSE (size > ROC_SG_MAX_DLEN_SIZE))
    {
      clib_warning (
	"Cryptodev: Exceeds max supported components. Reduce segments");
      ret = -1;
    }

  inst->dptr = (uint64_t) in_buffer;
  return ret;
}

static_always_inline int __attribute__ ((unused))
oct_crypto_sg2_inst_prep (struct roc_se_fc_params *params,
			  struct cpt_inst_s *inst, u64 offset_ctrl,
			  const u8 *iv_s, int iv_len, u8 pack_iv,
			  u8 pdcp_alg_type, i32 inputlen, i32 outputlen,
			  u32 passthrough_len, u32 req_flags, int pdcp_flag,
			  int decrypt)
{
  u32 mac_len = 0, aad_len = 0, size, index, g_size_bytes;
  struct roc_sg2list_comp *gather_comp, *scatter_comp;
  void *m_vaddr = params->meta_buf.vaddr;
  struct roc_se_buf_ptr *aad_buf = NULL;
  union cpt_inst_w5 cpt_inst_w5;
  union cpt_inst_w6 cpt_inst_w6;
  u16 scatter_sz, gather_sz;
  struct roc_se_ctx *se_ctx;
  u64 *offset_vaddr;
  int ret = 0;
  u8 *iv_d;

  se_ctx = params->ctx;
  mac_len = se_ctx->mac_len;

  if (PREDICT_FALSE (req_flags & ROC_SE_VALID_AAD_BUF))
    {
      /* We don't support both AAD and auth data separately */
      aad_len = params->aad_buf.size;
      aad_buf = &params->aad_buf;
    }

  /* save space for iv */
  offset_vaddr = m_vaddr;

  m_vaddr = (u8 *) m_vaddr + ROC_SE_OFF_CTRL_LEN + PLT_ALIGN_CEIL (iv_len, 8);

  inst->w4.s.opcode_major |= (u64) ROC_DMA_MODE_SG;

  /* This is DPTR len in case of SG mode */
  inst->w4.s.dlen = inputlen + ROC_SE_OFF_CTRL_LEN;

  /* iv offset is 0 */
  *offset_vaddr = offset_ctrl;
  iv_d = ((u8 *) offset_vaddr + ROC_SE_OFF_CTRL_LEN);

  if (PREDICT_TRUE (iv_len))
    clib_memcpy (iv_d, iv_s, iv_len);

  /* DPTR has SG list */

  gather_comp = (struct roc_sg2list_comp *) ((u8 *) m_vaddr);

  /*
   * Input Gather List
   */
  index = 0;

  /* Offset control word followed by iv */

  index = oct_crypto_fill_sg2_comp (gather_comp, index, (u64) offset_vaddr,
				    ROC_SE_OFF_CTRL_LEN + iv_len);

  /* Add input data */
  if (decrypt && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = inputlen - iv_len - mac_len;
      if (size)
	{
	  /* input data only */
	  u32 aad_offset = aad_len ? passthrough_len : 0;

	  index = oct_crypto_fill_sg2_comp_from_iov (gather_comp, index,
						     params->src_iov, 0, &size,
						     aad_buf, aad_offset);

	  if (PREDICT_FALSE (size))
	    {
	      clib_warning ("Cryptodev: Insufficient buffer"
			    " space, size %d needed",
			    size);
	      return -1;
	    }
	}

      /* mac data */
      if (mac_len)
	index = oct_crypto_fill_sg2_comp_from_buf (gather_comp, index,
						   &params->mac_buf);
    }
  else
    {
      /* input data */
      size = inputlen - iv_len;
      if (size)
	{
	  u32 aad_offset = aad_len ? passthrough_len : 0;

	  index = oct_crypto_fill_sg2_comp_from_iov (gather_comp, index,
						     params->src_iov, 0, &size,
						     aad_buf, aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      clib_warning ("Cryptodev: Insufficient buffer space,"
			    " size %d needed",
			    size);
	      return -1;
	    }
	}
    }

  gather_sz = (index + 2) / 3;
  g_size_bytes = gather_sz * sizeof (struct roc_sg2list_comp);

  /*
   * Output Scatter List
   */

  index = 0;
  scatter_comp =
    (struct roc_sg2list_comp *) ((u8 *) gather_comp + g_size_bytes);

  index = oct_crypto_fill_sg2_comp (
    scatter_comp, index, (u64) offset_vaddr + ROC_SE_OFF_CTRL_LEN, iv_len);

  /* Add output data */
  if ((!decrypt) && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = outputlen - iv_len - mac_len;
      if (size)
	{

	  u32 aad_offset = aad_len ? passthrough_len : 0;

	  index = oct_crypto_fill_sg2_comp_from_iov (scatter_comp, index,
						     params->dst_iov, 0, &size,
						     aad_buf, aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      clib_warning ("Cryptodev: Insufficient buffer space,"
			    " size %d needed",
			    size);
	      return -1;
	    }
	}

      /* mac data */
      if (mac_len)
	index = oct_crypto_fill_sg2_comp_from_buf (scatter_comp, index,
						   &params->mac_buf);
    }
  else
    {
      /* Output including mac */
      size = outputlen - iv_len;
      if (size)
	{
	  u32 aad_offset = aad_len ? passthrough_len : 0;

	  index = oct_crypto_fill_sg2_comp_from_iov (scatter_comp, index,
						     params->dst_iov, 0, &size,
						     aad_buf, aad_offset);

	  if (PREDICT_FALSE (size))
	    {
	      clib_warning ("Cryptodev: Insufficient buffer space,"
			    " size %d needed",
			    size);
	      return -1;
	    }
	}
    }

  scatter_sz = (index + 2) / 3;

  cpt_inst_w5.s.gather_sz = gather_sz;
  cpt_inst_w6.s.scatter_sz = scatter_sz;

  cpt_inst_w5.s.dptr = (u64) gather_comp;
  cpt_inst_w6.s.rptr = (u64) scatter_comp;

  inst->w5.u64 = cpt_inst_w5.u64;
  inst->w6.u64 = cpt_inst_w6.u64;

  if (PREDICT_FALSE ((scatter_sz >> 4) || (gather_sz >> 4)))
    {
      clib_warning (
	"Cryptodev: Exceeds max supported components. Reduce segments");
      ret = -1;
    }

  return ret;
}

static_always_inline int
oct_crypto_cpt_hmac_prep (u32 flags, u64 d_offs, u64 d_lens,
			  struct roc_se_fc_params *fc_params,
			  struct cpt_inst_s *inst, u8 is_decrypt)
{
  u32 encr_data_len, auth_data_len, aad_len = 0;
  i32 inputlen, outputlen, enc_dlen, auth_dlen;
  u32 encr_offset, auth_offset, iv_offset = 0;
  union cpt_inst_w4 cpt_inst_w4;
  u32 cipher_type;
  struct roc_se_ctx *se_ctx;
  u32 passthrough_len = 0;
  const u8 *src = NULL;
  u64 offset_ctrl;
  u8 iv_len = 16;
  u8 op_minor;
  u32 mac_len;
  int ret;

  encr_offset = ROC_SE_ENCR_OFFSET (d_offs);
  auth_offset = ROC_SE_AUTH_OFFSET (d_offs);
  encr_data_len = ROC_SE_ENCR_DLEN (d_lens);
  auth_data_len = ROC_SE_AUTH_DLEN (d_lens);

  if (PREDICT_FALSE (flags & ROC_SE_VALID_AAD_BUF))
    {
      /* We don't support both AAD and auth data separately */
      auth_data_len = 0;
      auth_offset = 0;
      aad_len = fc_params->aad_buf.size;
    }

  se_ctx = fc_params->ctx;
  cipher_type = se_ctx->enc_cipher;
  mac_len = se_ctx->mac_len;
  cpt_inst_w4.u64 = se_ctx->template_w4.u64;
  op_minor = cpt_inst_w4.s.opcode_minor;

  if (PREDICT_FALSE (flags & ROC_SE_VALID_AAD_BUF))
    {
      /*
       * When AAD is given, data above encr_offset is pass through
       * Since AAD is given as separate pointer and not as offset,
       * this is a special case as we need to fragment input data
       * into passthrough + encr_data and then insert AAD in between.
       */
      passthrough_len = encr_offset;
      auth_offset = passthrough_len + iv_len;
      encr_offset = passthrough_len + aad_len + iv_len;
      auth_data_len = aad_len + encr_data_len;
    }
  else
    {
      encr_offset += iv_len;
      auth_offset += iv_len;
    }

  auth_dlen = auth_offset + auth_data_len;
  enc_dlen = encr_data_len + encr_offset;

  cpt_inst_w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

  if (is_decrypt)
    {
      cpt_inst_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;

      if (auth_dlen > enc_dlen)
	{
	  inputlen = auth_dlen + mac_len;
	  outputlen = auth_dlen;
	}
      else
	{
	  inputlen = enc_dlen + mac_len;
	  outputlen = enc_dlen;
	}
    }
  else
    {
      cpt_inst_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;

      /* Round  up  to 16 bytes alignment */
      if (PREDICT_FALSE (encr_data_len & 0xf))
	{
	  if (PREDICT_TRUE (cipher_type == ROC_SE_AES_CBC) ||
	      (cipher_type == ROC_SE_DES3_CBC))
	    enc_dlen = PLT_ALIGN_CEIL (encr_data_len, 8) + encr_offset;
	}

      /*
       * auth_dlen is larger than enc_dlen in Authentication cases
       * like AES GMAC Authentication
       */
      if (PREDICT_FALSE (auth_dlen > enc_dlen))
	{
	  inputlen = auth_dlen;
	  outputlen = auth_dlen + mac_len;
	}
      else
	{
	  inputlen = enc_dlen;
	  outputlen = enc_dlen + mac_len;
	}
    }

  if (op_minor & ROC_SE_FC_MINOR_OP_HMAC_FIRST)
    outputlen = enc_dlen;

  cpt_inst_w4.s.param1 = encr_data_len;
  cpt_inst_w4.s.param2 = auth_data_len;

  if (PREDICT_FALSE ((encr_offset >> 16) || (iv_offset >> 8) ||
		     (auth_offset >> 8)))
    {
      clib_warning ("Cryptodev: Offset not supported");
      clib_warning (
	"Cryptodev: enc_offset: %d, iv_offset : %d, auth_offset: %d",
	encr_offset, iv_offset, auth_offset);
      return -1;
    }

  offset_ctrl = clib_host_to_net_u64 (
    ((u64) encr_offset << 16) | ((u64) iv_offset << 8) | ((u64) auth_offset));

  src = fc_params->iv_buf;

  inst->w4.u64 = cpt_inst_w4.u64;

#ifdef PLATFORM_OCTEON9
  ret = oct_crypto_sg_inst_prep (fc_params, inst, offset_ctrl, src, iv_len, 0,
				 0, inputlen, outputlen, passthrough_len,
				 flags, 0, is_decrypt);
#else
  ret = oct_crypto_sg2_inst_prep (fc_params, inst, offset_ctrl, src, iv_len, 0,
				  0, inputlen, outputlen, passthrough_len,
				  flags, 0, is_decrypt);
#endif

  if (PREDICT_FALSE (ret))
    return -1;

  return 0;
}

static_always_inline int
oct_crypto_scatter_gather_mode (
  oct_crypto_sess_t *sess, struct cpt_inst_s *inst, const bool is_aead,
  u8 aad_length, u8 *payload, vnet_crypto_async_frame_elt_t *elts, void *mdata,
  u32 cipher_data_length, u32 cipher_data_offset, u32 auth_data_length,
  u32 auth_data_offset, vlib_buffer_t *b, u16 adj_len)
{
  struct roc_se_fc_params fc_params = { 0 };
  struct roc_se_ctx *ctx = &sess->cpt_ctx;
  u64 d_offs = 0, d_lens = 0;
  vlib_buffer_t *buffer = b;
  u32 flags = 0, index = 0;
  u8 op_minor = 0, cpt_op;
  char src[SRC_IOV_SIZE];
  u32 *iv_buf;

  cpt_op = sess->cpt_op;

  if (is_aead)
    {
      flags |= ROC_SE_VALID_IV_BUF;
      iv_buf = (u32 *) elts->iv;
      iv_buf[3] = clib_host_to_net_u32 (0x1);
      fc_params.iv_buf = elts->iv;

      d_offs = cipher_data_offset;
      d_offs = d_offs << 16;

      d_lens = cipher_data_length;
      d_lens = d_lens << 32;

      fc_params.aad_buf.vaddr = elts->aad;
      fc_params.aad_buf.size = aad_length;
      flags |= ROC_SE_VALID_AAD_BUF;

      if (sess->cpt_ctx.mac_len)
	{
	  flags |= ROC_SE_VALID_MAC_BUF;
	  fc_params.mac_buf.size = sess->cpt_ctx.mac_len;
	  fc_params.mac_buf.vaddr = elts->tag;
	}
    }
  else
    {
      op_minor = ctx->template_w4.s.opcode_minor;

      flags |= ROC_SE_VALID_IV_BUF;

      fc_params.iv_buf = elts->iv;

      d_offs = cipher_data_offset;
      d_offs = (d_offs << 16) | auth_data_offset;

      d_lens = cipher_data_length;
      d_lens = (d_lens << 32) | auth_data_length;

      if (PREDICT_TRUE (sess->cpt_ctx.mac_len))
	{
	  if (!(op_minor & ROC_SE_FC_MINOR_OP_HMAC_FIRST))
	    {
	      flags |= ROC_SE_VALID_MAC_BUF;
	      fc_params.mac_buf.size = sess->cpt_ctx.mac_len;
	      fc_params.mac_buf.vaddr = elts->digest;
	    }
	}
    }

  fc_params.ctx = &sess->cpt_ctx;

  fc_params.src_iov = (void *) src;

  fc_params.src_iov->bufs[index].vaddr = payload;
  fc_params.src_iov->bufs[index].size = b->current_length - adj_len;
  index++;

  while (buffer->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      buffer = vlib_get_buffer (vlib_get_main (), buffer->next_buffer);
      fc_params.src_iov->bufs[index].vaddr =
	buffer->data + buffer->current_data;
      fc_params.src_iov->bufs[index].size = buffer->current_length;
      index++;
    }

  fc_params.src_iov->buf_cnt = index;

  fc_params.dst_iov = (void *) src;

  fc_params.meta_buf.vaddr = mdata;
  fc_params.meta_buf.size = OCT_SCATTER_GATHER_BUFFER_SIZE;

  return oct_crypto_cpt_hmac_prep (flags, d_offs, d_lens, &fc_params, inst,
				   cpt_op);
}

static_always_inline u64
oct_cpt_inst_w7_get (oct_crypto_sess_t *sess, struct roc_cpt *roc_cpt)
{
  union cpt_inst_w7 inst_w7;

  inst_w7.u64 = 0;
  inst_w7.s.cptr = (u64) &sess->cpt_ctx.se_ctx.fctx;

  if (oct_hw_ctx_cache_enable ())
    inst_w7.s.ctx_val = 1;

  /* Set the engine group */
  inst_w7.s.egrp = roc_cpt->eng_grp[CPT_ENG_TYPE_IE];

  return inst_w7.u64;
}

static_always_inline i32
oct_crypto_link_session_update (vlib_main_t *vm, oct_crypto_sess_t *sess,
				u32 key_index, u8 type)
{
  vnet_crypto_key_t *crypto_key, *auth_key;
  roc_se_cipher_type enc_type = 0;
  roc_se_auth_type auth_type = 0;
  vnet_crypto_key_t *key;
  u32 digest_len = ~0;
  i32 rv = 0;

  key = vnet_crypto_get_key (key_index);

  switch (key->alg)
    {
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA1_TAG12:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA1_TYPE;
      digest_len = 12;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA224_TAG14:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA224_TAG14:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA224_TAG14:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA2_SHA224;
      digest_len = 14;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA256_TAG16:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA2_SHA256;
      digest_len = 16;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA384_TAG24:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA2_SHA384;
      digest_len = 24;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA512_TAG32:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA512_TAG32:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA512_TAG32:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA2_SHA512;
      digest_len = 32;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_MD5_TAG12:
    case VNET_CRYPTO_ALG_AES_192_CBC_MD5_TAG12:
    case VNET_CRYPTO_ALG_AES_256_CBC_MD5_TAG12:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_MD5_TYPE;
      digest_len = 12;
      break;
    case VNET_CRYPTO_ALG_AES_128_CTR_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_192_CTR_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_256_CTR_SHA1_TAG12:
      enc_type = ROC_SE_AES_CTR;
      auth_type = ROC_SE_SHA1_TYPE;
      digest_len = 12;
      break;
    case VNET_CRYPTO_ALG_AES_128_CTR_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_192_CTR_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_256_CTR_SHA256_TAG16:
      enc_type = ROC_SE_AES_CTR;
      auth_type = ROC_SE_SHA2_SHA256;
      digest_len = 16;
      break;
    case VNET_CRYPTO_ALG_AES_128_CTR_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_192_CTR_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_256_CTR_SHA384_TAG24:
      enc_type = ROC_SE_AES_CTR;
      auth_type = ROC_SE_SHA2_SHA384;
      digest_len = 24;
      break;
    case VNET_CRYPTO_ALG_AES_128_CTR_SHA512_TAG32:
    case VNET_CRYPTO_ALG_AES_192_CTR_SHA512_TAG32:
    case VNET_CRYPTO_ALG_AES_256_CTR_SHA512_TAG32:
      enc_type = ROC_SE_AES_CTR;
      auth_type = ROC_SE_SHA2_SHA512;
      digest_len = 32;
      break;
    case VNET_CRYPTO_ALG_3DES_CBC_MD5_TAG12:
      enc_type = ROC_SE_DES3_CBC;
      auth_type = ROC_SE_MD5_TYPE;
      digest_len = 12;
      break;
    case VNET_CRYPTO_ALG_3DES_CBC_SHA1_TAG12:
      enc_type = ROC_SE_DES3_CBC;
      auth_type = ROC_SE_SHA1_TYPE;
      digest_len = 12;
      break;
    case VNET_CRYPTO_ALG_3DES_CBC_SHA224_TAG14:
      enc_type = ROC_SE_DES3_CBC;
      auth_type = ROC_SE_SHA2_SHA224;
      digest_len = 14;
      break;
    case VNET_CRYPTO_ALG_3DES_CBC_SHA256_TAG16:
      enc_type = ROC_SE_DES3_CBC;
      auth_type = ROC_SE_SHA2_SHA256;
      digest_len = 16;
      break;
    case VNET_CRYPTO_ALG_3DES_CBC_SHA384_TAG24:
      enc_type = ROC_SE_DES3_CBC;
      auth_type = ROC_SE_SHA2_SHA384;
      digest_len = 24;
      break;
    case VNET_CRYPTO_ALG_3DES_CBC_SHA512_TAG32:
      enc_type = ROC_SE_DES3_CBC;
      auth_type = ROC_SE_SHA2_SHA512;
      digest_len = 32;
      break;
    default:
      clib_warning (
	"Cryptodev: Undefined link algo %u specified. Key index %u", key->alg,
	key_index);
      return -1;
    }

  if (type == VNET_CRYPTO_OP_TYPE_ENCRYPT)
    sess->cpt_ctx.ciph_then_auth = true;
  else
    sess->cpt_ctx.auth_then_ciph = true;

  sess->iv_length = 16;
  sess->cpt_op = type;

  crypto_key = vnet_crypto_get_key (key->index_crypto);
  rv = roc_se_ciph_key_set (&sess->cpt_ctx, enc_type, crypto_key->data,
			    crypto_key->length);
  if (rv)
    {
      clib_warning ("Cryptodev: Error in setting cipher key for enc type %u",
		    enc_type);
      return -1;
    }

  auth_key = vnet_crypto_get_key (key->index_integ);

  rv = roc_se_auth_key_set (&sess->cpt_ctx, auth_type, auth_key->data,
			    auth_key->length, digest_len);
  if (rv)
    {
      clib_warning ("Cryptodev: Error in setting auth key for auth type %u",
		    auth_type);
      return -1;
    }

  sess->cpt_ctx.template_w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

  if (sess->cpt_op == VNET_CRYPTO_OP_TYPE_DECRYPT)
    sess->cpt_ctx.template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;
  else
    sess->cpt_ctx.template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;

  return 0;
}

static_always_inline i32
oct_crypto_aead_session_update (vlib_main_t *vm, oct_crypto_sess_t *sess,
				u32 key_index, u8 type)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (key_index);
  roc_se_cipher_type enc_type = 0;
  roc_se_auth_type auth_type = 0;
  u32 digest_len = 16;
  i32 rv = 0;

  switch (key->alg)
    {
    case VNET_CRYPTO_ALG_AES_128_GCM:
    case VNET_CRYPTO_ALG_AES_192_GCM:
    case VNET_CRYPTO_ALG_AES_256_GCM:
      enc_type = ROC_SE_AES_GCM;
      sess->aes_gcm = 1;
      sess->iv_offset = 0;
      sess->iv_length = 16;
      break;
    case VNET_CRYPTO_ALG_CHACHA20_POLY1305:
      enc_type = ROC_SE_CHACHA20;
      auth_type = ROC_SE_POLY1305;
      break;
    default:
      clib_warning (
	"Cryptodev: Undefined cipher algo %u specified. Key index %u",
	key->alg, key_index);
      return -1;
    }

  sess->cpt_ctx.mac_len = digest_len;
  sess->cpt_op = type;

  rv = roc_se_ciph_key_set (&sess->cpt_ctx, enc_type, key->data, key->length);
  if (rv)
    {
      clib_warning ("Cryptodev: Error in setting cipher key for enc type %u",
		    enc_type);
      return -1;
    }

  rv = roc_se_auth_key_set (&sess->cpt_ctx, auth_type, NULL, 0, digest_len);
  if (rv)
    {
      clib_warning ("Cryptodev: Error in setting auth key for auth type %u",
		    auth_type);
      return -1;
    }

  sess->cpt_ctx.template_w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

  if (sess->cpt_op == VNET_CRYPTO_OP_TYPE_DECRYPT)
    sess->cpt_ctx.template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;
  else
    sess->cpt_ctx.template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;

  if (enc_type == ROC_SE_CHACHA20)
    sess->cpt_ctx.template_w4.s.opcode_minor |= BIT (5);

  return 0;
}

static_always_inline i32
oct_crypto_session_init (vlib_main_t *vm, oct_crypto_sess_t *session,
			 vnet_crypto_key_index_t key_index, int op_type)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  vnet_crypto_key_t *key;
  oct_crypto_dev_t *ocd;
  i32 rv = 0;

  ocd = ocm->crypto_dev[op_type];

  key = vnet_crypto_get_key (key_index);

  if (key->is_link)
    rv = oct_crypto_link_session_update (vm, session, key_index, op_type);
  else
    rv = oct_crypto_aead_session_update (vm, session, key_index, op_type);

  if (rv)
    {
      oct_crypto_session_free (vm, session);
      return -1;
    }

  session->crypto_dev = ocd;

  session->cpt_inst_w7 =
    oct_cpt_inst_w7_get (session, session->crypto_dev->roc_cpt);

  if (oct_hw_ctx_cache_enable ())
    roc_se_ctx_init (&session->cpt_ctx);

  session->initialised = 1;

  return 0;
}

static_always_inline void
oct_crypto_update_frame_error_status (vnet_crypto_async_frame_t *f, u32 index,
				      vnet_crypto_op_status_t s)
{
  u32 i;

  for (i = index; i < f->n_elts; i++)
    f->elts[i].status = s;

  if (index == 0)
    f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
}

static_always_inline void
oct_crypto_direct_mode_linked (vlib_buffer_t *buffer, struct cpt_inst_s *inst,
			       oct_crypto_sess_t *sess,
			       oct_crypto_inflight_req_t *infl_req, u8 aad_len)
{
  u32 encr_offset, auth_offset, iv_offset;
  vnet_crypto_async_frame_elt_t *elts;
  union cpt_inst_w4 cpt_inst_w4;
  u64 *offset_control_word;
  u32 crypto_total_length;
  u32 auth_dlen, enc_dlen;
  u32 enc_auth_len;

  elts = infl_req->fe;
  enc_auth_len = elts->crypto_total_length + elts->integ_length_adj;
  crypto_total_length = elts->crypto_total_length;

  if (sess->cpt_op == VNET_CRYPTO_OP_TYPE_DECRYPT)
    {
      /*
       * Position the offset control word so that it does not
       * overlap with the IV.
       */
      offset_control_word = (void *) (buffer->data) - ROC_SE_OFF_CTRL_LEN - 4;

      iv_offset =
	(void *) elts->iv - (void *) offset_control_word - ROC_SE_OFF_CTRL_LEN;
    }
  else
    {
      offset_control_word = (void *) (elts->iv) - ROC_SE_OFF_CTRL_LEN;
      iv_offset = 0;
    }

  encr_offset = (void *) (buffer->data + elts->crypto_start_offset) -
		(void *) offset_control_word - ROC_SE_OFF_CTRL_LEN;
  auth_offset = (void *) (buffer->data + elts->integ_start_offset) -
		(void *) offset_control_word - ROC_SE_OFF_CTRL_LEN;
  *offset_control_word = clib_host_to_net_u64 (
    ((u64) encr_offset << 16) | ((u64) iv_offset << 8) | ((u64) auth_offset));

  cpt_inst_w4.u64 = sess->cpt_ctx.template_w4.u64;

  cpt_inst_w4.s.param1 = crypto_total_length;
  cpt_inst_w4.s.param2 = enc_auth_len;

  auth_dlen = auth_offset + enc_auth_len + ROC_SE_OFF_CTRL_LEN;
  enc_dlen = encr_offset + crypto_total_length + ROC_SE_OFF_CTRL_LEN;

  if (sess->cpt_op == VNET_CRYPTO_OP_TYPE_DECRYPT)
    cpt_inst_w4.s.dlen = auth_dlen + sess->cpt_ctx.mac_len;
  else
    {
      /*
       * In the case of ESN, 4 bytes of the seqhi will be stored at the end of
       * the cipher. This data must be overwritten by the digest data during
       * the dequeue process.
       */
      if (auth_dlen > enc_dlen)
	infl_req->esn_enabled = true;

      cpt_inst_w4.s.dlen = auth_dlen;
    }

  infl_req->mac_len = sess->cpt_ctx.mac_len;

  inst->dptr = (uint64_t) offset_control_word;
  inst->rptr = (uint64_t) ((void *) offset_control_word + ROC_SE_OFF_CTRL_LEN);
  inst->w4.u64 = cpt_inst_w4.u64;
}

static_always_inline void
oct_crypto_direct_mode_aead (vlib_buffer_t *buffer, struct cpt_inst_s *inst,
			     oct_crypto_sess_t *sess,
			     oct_crypto_inflight_req_t *infl_req, u8 aad_len)
{
  u32 encr_offset, auth_offset, iv_offset;
  u32 auth_copy_offset, iv_copy_offset;
  vnet_crypto_async_frame_elt_t *elts;
  union cpt_inst_w4 cpt_inst_w4;
  u64 *offset_control_word;
  u32 crypto_total_length;

  elts = infl_req->fe;
  crypto_total_length = elts->crypto_total_length;

  ((u32 *) elts->iv)[3] = clib_host_to_net_u32 (0x1);

  offset_control_word = (void *) (elts->aad) - ROC_SE_OFF_CTRL_LEN;
  encr_offset = (void *) (buffer->data + elts->crypto_start_offset) -
		(void *) offset_control_word - ROC_SE_OFF_CTRL_LEN;
  iv_offset = elts->iv - elts->aad;
  auth_offset = encr_offset - aad_len;

  *offset_control_word = clib_host_to_net_u64 (
    ((u64) encr_offset << 16) | ((u64) iv_offset << 8) | ((u64) auth_offset));

  cpt_inst_w4.u64 = sess->cpt_ctx.template_w4.u64;

  cpt_inst_w4.s.param1 = crypto_total_length;
  cpt_inst_w4.s.param2 = crypto_total_length + aad_len;

  if (sess->cpt_op == VNET_CRYPTO_OP_TYPE_DECRYPT)
    cpt_inst_w4.s.dlen = encr_offset + elts->crypto_total_length +
			 ROC_SE_OFF_CTRL_LEN + sess->cpt_ctx.mac_len;
  else
    cpt_inst_w4.s.dlen =
      encr_offset + elts->crypto_total_length + ROC_SE_OFF_CTRL_LEN;

  inst->dptr = (uint64_t) offset_control_word;
  inst->rptr = (uint64_t) ((void *) offset_control_word + ROC_SE_OFF_CTRL_LEN);
  inst->w4.u64 = cpt_inst_w4.u64;

  /*
   * CPT hardware requires the AAD to be followed by the cipher packet.
   * Therefore, maintain a copy of the AAD and IV in the inflight request,
   * and write the AAD in front of the cipher data before submission.
   */
  auth_copy_offset = encr_offset - sess->cpt_ctx.mac_len;
  iv_copy_offset = encr_offset - 8;

  clib_memcpy_fast (infl_req->aad,
		    ((void *) inst->dptr) + auth_copy_offset + 8, 8);
  clib_memcpy_fast (infl_req->iv, ((void *) inst->dptr) + iv_copy_offset + 8,
		    8);
  clib_memcpy_fast (((void *) inst->dptr) + encr_offset + ROC_SE_OFF_CTRL_LEN -
		      aad_len,
		    elts->aad, aad_len);

  infl_req->aead_algo = true;
}

static_always_inline int
oct_crypto_enqueue_enc_dec (vlib_main_t *vm, vnet_crypto_async_frame_t *frame,
			    const u8 is_aead, u8 aad_len, const u8 type)
{
  u32 i, enq_tail, enc_auth_len, buffer_index, nb_infl_allowed;
  struct cpt_inst_s inst[VNET_CRYPTO_FRAME_SIZE];
  u32 crypto_start_offset, integ_start_offset;
  oct_crypto_main_t *ocm = &oct_crypto_main;
  vnet_crypto_async_frame_elt_t *elts;
  oct_crypto_dev_t *crypto_dev = NULL;
  oct_crypto_inflight_req_t *infl_req;
  oct_crypto_pending_queue_t *pend_q;
  u64 dptr_start_ptr, curr_ptr;
  oct_crypto_sess_t *sess;
  u32 crypto_total_length;
  oct_crypto_key_t *key;
  vlib_buffer_t *buffer;
  void *sg_data;
  u16 adj_len;
  int ret = 0;

  /* GCM packets having 8 bytes of aad and 8 bytes of iv */
  u8 aad_iv = 8 + 8;

  pend_q = &ocm->pend_q[vlib_get_thread_index ()];

  nb_infl_allowed = pend_q->n_desc - pend_q->n_crypto_inflight;
  if (PREDICT_FALSE (nb_infl_allowed < frame->n_elts))
    {
      oct_crypto_update_frame_error_status (
	frame, 0, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
      return -1;
    }

  sg_data = pend_q->sg_data;

  for (i = 0; i < frame->n_elts; i++)
    {
      enq_tail = pend_q->enq_tail;
      infl_req = &pend_q->req_queue[enq_tail];
      infl_req->frame = frame;
      infl_req->last_elts = false;
      infl_req->index = i;

      elts = &frame->elts[i];
      infl_req->fe = elts;
      buffer_index = frame->buffer_indices[i];
      key = vec_elt_at_index (ocm->keys[type], elts->key_index);

      if (PREDICT_FALSE (!key->sess))
	{
	  oct_crypto_update_frame_error_status (
	    frame, i, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	  return -1;
	}

      sess = key->sess;

      if (PREDICT_FALSE (!sess->initialised))
	ret = oct_crypto_session_init (vm, sess, elts->key_index, type);
      if (ret)
	{
	  oct_crypto_update_frame_error_status (
	    frame, i, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	  return -1;
	}

      crypto_dev = sess->crypto_dev;

      clib_memset (inst + i, 0, sizeof (struct cpt_inst_s));

      buffer = vlib_get_buffer (vm, buffer_index);

      if (is_aead)
	{
	  if (buffer->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      dptr_start_ptr =
		(u64) (buffer->data + (elts->crypto_start_offset - aad_iv));
	      curr_ptr = (u64) (buffer->data + buffer->current_data);
	      adj_len = (u16) (dptr_start_ptr - curr_ptr);

	      crypto_total_length = elts->crypto_total_length;
	      crypto_start_offset = aad_iv;
	      integ_start_offset = 0;

	      ret = oct_crypto_scatter_gather_mode (
		sess, inst + i, is_aead, aad_len, (u8 *) dptr_start_ptr, elts,
		((oct_crypto_scatter_gather_t *) (sg_data)) + enq_tail,
		crypto_total_length /* cipher_len */,
		crypto_start_offset /* cipher_offset */, 0 /* auth_len */,
		integ_start_offset /* auth_off */, buffer, adj_len);

	      if (PREDICT_FALSE (ret < 0))
		{
		  oct_crypto_update_frame_error_status (
		    frame, i, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  return -1;
		}
	    }
	  else
	    {
	      oct_crypto_direct_mode_aead (buffer, inst + i, sess, infl_req,
					   aad_len);
	    }
	}
      else
	{
	  if (buffer->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      dptr_start_ptr = (u64) (buffer->data + elts->integ_start_offset);

	      curr_ptr = (u64) (buffer->data + buffer->current_data);
	      adj_len = (u16) (dptr_start_ptr - curr_ptr);

	      crypto_start_offset =
		elts->crypto_start_offset - elts->integ_start_offset;
	      integ_start_offset = 0;
	      enc_auth_len =
		elts->crypto_total_length + elts->integ_length_adj;
	      crypto_total_length = elts->crypto_total_length;

	      ret = oct_crypto_scatter_gather_mode (
		sess, inst + i, is_aead, aad_len, (u8 *) dptr_start_ptr, elts,
		((oct_crypto_scatter_gather_t *) (sg_data)) + enq_tail,
		crypto_total_length /* cipher_len */,
		crypto_start_offset /* cipher_offset */,
		enc_auth_len /* auth_len */, integ_start_offset /* auth_off */,
		buffer, adj_len);

	      if (PREDICT_FALSE (ret < 0))
		{
		  oct_crypto_update_frame_error_status (
		    frame, i, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
		  return -1;
		}
	    }
	  else
	    {
	      oct_crypto_direct_mode_linked (buffer, inst + i, sess, infl_req,
					     aad_len);
	    }
	}

      inst[i].w7.u64 = sess->cpt_inst_w7;
      inst[i].res_addr = (u64) &infl_req->res;
      OCT_MOD_INC (pend_q->enq_tail, pend_q->n_desc);
    }

  oct_crypto_burst_submit (crypto_dev, inst, frame->n_elts);

  infl_req->last_elts = true;

  pend_q->n_crypto_inflight += frame->n_elts;
  pend_q->n_crypto_frame++;

  return 0;
}

int
oct_crypto_enqueue_linked_alg_enc (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enqueue_enc_dec (
    vm, frame, 0 /* is_aead */, 0 /* aad_len */, VNET_CRYPTO_OP_TYPE_ENCRYPT);
}

int
oct_crypto_enqueue_linked_alg_dec (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enqueue_enc_dec (
    vm, frame, 0 /* is_aead */, 0 /* aad_len */, VNET_CRYPTO_OP_TYPE_DECRYPT);
}

int
oct_crypto_enqueue_aead_aad_enc (vlib_main_t *vm,
				 vnet_crypto_async_frame_t *frame, u8 aad_len)
{
  return oct_crypto_enqueue_enc_dec (vm, frame, 1 /* is_aead */, aad_len,
				     VNET_CRYPTO_OP_TYPE_ENCRYPT);
}

static_always_inline int
oct_crypto_enqueue_aead_aad_dec (vlib_main_t *vm,
				 vnet_crypto_async_frame_t *frame, u8 aad_len)
{
  return oct_crypto_enqueue_enc_dec (vm, frame, 1 /* is_aead */, aad_len,
				     VNET_CRYPTO_OP_TYPE_DECRYPT);
}

int
oct_crypto_enqueue_aead_aad_8_enc (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enqueue_aead_aad_enc (vm, frame, 8);
}

int
oct_crypto_enqueue_aead_aad_12_enc (vlib_main_t *vm,
				    vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enqueue_aead_aad_enc (vm, frame, 12);
}

int
oct_crypto_enqueue_aead_aad_0_enc (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enqueue_aead_aad_enc (vm, frame, 0);
}

int
oct_crypto_enqueue_aead_aad_8_dec (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enqueue_aead_aad_dec (vm, frame, 8);
}

int
oct_crypto_enqueue_aead_aad_12_dec (vlib_main_t *vm,
				    vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enqueue_aead_aad_dec (vm, frame, 12);
}

int
oct_crypto_enqueue_aead_aad_0_dec (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enqueue_aead_aad_dec (vm, frame, 0);
}

vnet_crypto_async_frame_t *
oct_crypto_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			  clib_thread_index_t *enqueue_thread_idx)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  u32 deq_head, status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  vnet_crypto_async_frame_elt_t *fe = NULL;
  oct_crypto_inflight_req_t *infl_req;
  oct_crypto_pending_queue_t *pend_q;
  vnet_crypto_async_frame_t *frame;
  volatile union cpt_res_s *res;
  bool last_elts_processed;
  vlib_buffer_t *buffer;

  pend_q = &ocm->pend_q[vlib_get_thread_index ()];

  if (!pend_q->n_crypto_frame)
    return NULL;

  last_elts_processed = false;

  for (; last_elts_processed == false;)
    {
      deq_head = pend_q->deq_head;
      infl_req = &pend_q->req_queue[deq_head];
      fe = infl_req->fe;

      res = &infl_req->res;

      if (PREDICT_FALSE (res->cn10k.compcode == CPT_COMP_NOT_DONE))
	return NULL;

      if (PREDICT_FALSE (res->cn10k.uc_compcode))
	{
	  if (res->cn10k.uc_compcode == ROC_SE_ERR_GC_ICV_MISCOMPARE)
	    status = fe->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  else
	    status = fe->status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	}

      buffer =
	vlib_get_buffer (vm, infl_req->frame->buffer_indices[infl_req->index]);

      /*
       * For AEAD, copy the AAD and IV back to their original positions.
       * If ESN is enabled (in case of linked algo), overwrite the ESN
       * seqhi at the end of the cipher with the digest data.
       */
      if (infl_req->aead_algo)
	{
	  clib_memcpy_fast (buffer->data + fe->crypto_start_offset - 8,
			    infl_req->iv, 8);
	  clib_memcpy_fast (buffer->data + fe->crypto_start_offset - 16,
			    infl_req->aad, 8);
	}
      else if (infl_req->esn_enabled)
	clib_memcpy_fast (fe->digest, fe->digest + 4, infl_req->mac_len);

      clib_memset ((void *) &infl_req->res, 0, sizeof (union cpt_res_s));
      last_elts_processed = infl_req->last_elts;
      OCT_MOD_INC (pend_q->deq_head, pend_q->n_desc);
    }

  frame = infl_req->frame;

  pend_q->n_crypto_frame--;
  pend_q->n_crypto_inflight -= frame->n_elts;

  frame->state = status == VNET_CRYPTO_OP_STATUS_COMPLETED ?
		   VNET_CRYPTO_FRAME_STATE_SUCCESS :
		   VNET_CRYPTO_FRAME_STATE_ELT_ERROR;

  *nb_elts_processed = frame->n_elts;
  *enqueue_thread_idx = frame->enqueue_thread_index;

  return frame;
}

int
oct_init_crypto_engine_handlers (vlib_main_t *vm, vnet_dev_t *dev)
{
  u32 engine_index;

  engine_index = vnet_crypto_register_engine (vm, "oct_cryptodev", 100,
					      "OCT Cryptodev Engine");

#define _(n, k, t, a)                                                         \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, engine_index, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,             \
    oct_crypto_enqueue_aead_aad_##a##_enc);                                   \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, engine_index, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,             \
    oct_crypto_enqueue_aead_aad_##a##_dec);
  foreach_oct_crypto_aead_async_alg
#undef _

#define _(c, h, k, d)                                                         \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, engine_index, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,                \
    oct_crypto_enqueue_linked_alg_enc);                                       \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, engine_index, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,                \
    oct_crypto_enqueue_linked_alg_dec);
    foreach_oct_crypto_link_async_alg;
#undef _

  vnet_crypto_register_dequeue_handler (vm, engine_index,
					oct_crypto_frame_dequeue);

  vnet_crypto_register_key_handler (vm, engine_index, oct_crypto_key_handler);

  return 0;
}

int
oct_conf_sw_queue (vlib_main_t *vm, vnet_dev_t *dev, oct_crypto_dev_t *ocd)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  extern oct_plt_init_param_t oct_plt_init_param;
  u32 n_inflight_req;
  int i;

  ocm->pend_q = oct_plt_init_param.oct_plt_zmalloc (
    tm->n_vlib_mains * sizeof (oct_crypto_pending_queue_t),
    CLIB_CACHE_LINE_BYTES);
  if (ocm->pend_q == NULL)
    {
      log_err (dev, "Failed to allocate memory for crypto pending queue");
      return -1;
    }

  /*
   * Each pending queue will get number of cpt desc / number of cores.
   * And that desc count is shared across inflight entries.
   */
  n_inflight_req = (ocd->n_desc / tm->n_vlib_mains);

  for (i = 0; i < tm->n_vlib_mains; ++i)
    {
      ocm->pend_q[i].n_desc = n_inflight_req;

      ocm->pend_q[i].req_queue = oct_plt_init_param.oct_plt_zmalloc (
	ocm->pend_q[i].n_desc * sizeof (oct_crypto_inflight_req_t),
	CLIB_CACHE_LINE_BYTES);
      if (ocm->pend_q[i].req_queue == NULL)
	{
	  log_err (dev,
		   "Failed to allocate memory for crypto inflight request");
	  goto free;
	}

      ocm->pend_q[i].sg_data = oct_plt_init_param.oct_plt_zmalloc (
	OCT_SCATTER_GATHER_BUFFER_SIZE * ocm->pend_q[i].n_desc,
	CLIB_CACHE_LINE_BYTES);
      if (ocm->pend_q[i].sg_data == NULL)
	{
	  log_err (dev, "Failed to allocate crypto scatter gather memory");
	  goto free;
	}
    }

  return 0;

free:
  for (; i >= 0; i--)
    {
      if (ocm->pend_q[i].req_queue == NULL)
	continue;

      oct_plt_init_param.oct_plt_free (ocm->pend_q[i].sg_data);

      oct_plt_init_param.oct_plt_free (ocm->pend_q[i].req_queue);
    }
  oct_plt_init_param.oct_plt_free (ocm->pend_q);

  return -1;
}
