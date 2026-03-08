/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <octeon.h>
#include <crypto.h>
#include <base/roc_api.h>
#include "common.h"

extern oct_plt_init_param_t oct_plt_init_param;

oct_crypto_main_t oct_crypto_main;
oct_crypto_dev_t oct_crypto_dev;

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "crypto",
};

typedef struct
{
  vnet_crypto_frame_enq_fn_t *enc_fn;
  vnet_crypto_frame_enq_fn_t *dec_fn;
  roc_se_cipher_type cipher_type;
  roc_se_auth_type auth_type;
  u8 aad_len;
  u8 digest_len;
  u8 iv_length;
  u8 aes_gcm;
  u16 opcode_minor_flags;
  u8 valid;
} oct_crypto_alg_data_t;

static const oct_crypto_alg_data_t oct_crypto_algs[VNET_CRYPTO_N_ALGS];

static_always_inline bool
oct_hw_ctx_cache_enable (void)
{
  return roc_errata_cpt_hang_on_mixed_ctx_val () || roc_model_is_cn10ka_b0 () ||
	 roc_model_is_cn10kb_a0 ();
}

static_always_inline i32
oct_crypto_session_create (oct_crypto_key_t *ckey, vnet_crypto_ctx_t *ctx __clib_unused,
			   int op_type)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  oct_crypto_sess_t *session;
  oct_crypto_dev_t *ocd;

  ocd = ocm->crypto_dev[op_type];

  session = oct_plt_init_param.oct_plt_zmalloc (sizeof (oct_crypto_sess_t), CLIB_CACHE_LINE_BYTES);
  if (session == NULL)
    {
      log_err (ocd->dev, "Failed to allocate crypto session memory");
      return -1;
    }
  session->crypto_dev = ocd;
  ckey->sess[op_type] = session;
  return 0;
}

void
oct_crypto_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  oct_crypto_key_t *ckey;
  oct_crypto_main_t *ocm = &oct_crypto_main;
  oct_crypto_dev_t *ocd = &oct_crypto_dev;
  bool ctx_cache_enabled;
  u32 type;

  ASSERT (args->handler_type == VNET_CRYPTO_HANDLER_TYPE_ASYNC);
  ckey = (oct_crypto_key_t *) args->key_data;

  if (args->action == VNET_CRYPTO_KEY_DATA_ADD)
    {
      for (type = VNET_CRYPTO_OP_TYPE_ENCRYPT; type <= VNET_CRYPTO_OP_TYPE_DECRYPT; type++)
	{
	  if (ckey->sess[type] == NULL && oct_crypto_session_create (ckey, ctx, type))
	    {
	      log_err (ocd->dev, "Unable to create crypto session");
	      return;
	    }
	}

      ocm->started = 1;
      return;
    }

  ASSERT (args->action == VNET_CRYPTO_KEY_DATA_REMOVE);

  ctx_cache_enabled = oct_hw_ctx_cache_enable ();

  for (type = VNET_CRYPTO_OP_TYPE_ENCRYPT; type <= VNET_CRYPTO_OP_TYPE_DECRYPT; type++)
    {
      if (!ckey->sess[type])
	continue;

      if (ctx_cache_enabled)
	roc_cpt_lf_ctx_flush (&ckey->sess[type]->crypto_dev->lf, &ckey->sess[type]->cpt_ctx.se_ctx,
			      true);

      oct_plt_init_param.oct_plt_free (ckey->sess[type]);
      ckey->sess[type] = NULL;
    }
}

static_always_inline void
oct_crypto_session_free (vlib_main_t *vm __clib_unused, oct_crypto_sess_t *sess)
{
  oct_plt_init_param.oct_plt_free (sess);
}

#ifdef PLATFORM_OCTEON9
static inline void
oct_cpt_inst_submit (struct cpt_inst_s *inst, uint64_t lmtline, uint64_t io_addr)
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
oct_crypto_burst_submit (oct_crypto_dev_t *crypto_dev, struct cpt_inst_s *inst, u32 n_left)
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
	  roc_lmt_mov_seg ((void *) lmt_line[count], inst + count, CPT_LMT_SIZE_COPY);
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
	  roc_lmt_mov_seg ((void *) lmt_line[count], inst + count, CPT_LMT_SIZE_COPY);
	}

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (n_left - 1) << 12;

      roc_lmt_submit_steorl (lmt_arg, io_addr);
    }
#endif
}

static_always_inline uint32_t
oct_crypto_fill_sg_comp_from_iov (struct roc_sglist_comp *list, uint32_t i,
				  struct roc_se_iov_ptr *from, uint32_t from_offset,
				  uint32_t *psize, struct roc_se_buf_ptr *extra_buf,
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
	      to->ptr[i % 4] = clib_host_to_net_u64 ((uint64_t) extra_buf->vaddr);
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
oct_crypto_fill_sg2_comp_from_iov (struct roc_sg2list_comp *list, const u32 i,
				   struct roc_se_iov_ptr *from, u32 from_offset, u32 *psize,
				   struct roc_se_buf_ptr *extra_buf, u32 extra_offset)
{
  u32 index = i;
  u32 seg = i % 3;
  u32 extra_len = extra_buf ? extra_buf->size : 0;
  u32 size = *psize, buf_sz, e_len, next_len;
  struct roc_sg2list_comp *to = &list[i / 3];
  u64 e_vaddr, next_vaddr;
  void *vaddr;
  i32 j;

  for (j = 0; j < from->buf_cnt; j++)
    {
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

      to->u.s.len[seg] = (e_len);
      to->ptr[seg] = (e_vaddr);
      to->u.s.valid_segs = seg + 1;

      if (extra_len && (e_len >= extra_offset))
	{
	  /* Break the data at given offset */
	  next_len = e_len - extra_offset;
	  next_vaddr = e_vaddr + extra_offset;

	  if (!extra_offset)
	    {
	      index--;
	      if (seg == 0)
		{
		  seg = 2;
		  to--;
		}
	      else
		seg--;
	    }
	  else
	    {
	      e_len = extra_offset;
	      size -= e_len;
	      to->u.s.len[seg] = (e_len);
	    }

	  extra_len = clib_min (extra_len, size);
	  /* Insert extra data ptr */
	  if (extra_len)
	    {
	      index++;
	      if (seg == 2)
		{
		  seg = 0;
		  to++;
		}
	      else
		seg++;
	      to->u.s.len[seg] = (extra_len);
	      to->ptr[seg] = ((u64) extra_buf->vaddr);
	      to->u.s.valid_segs = seg + 1;
	      size -= extra_len;
	    }

	  next_len = clib_min (next_len, size);
	  /* insert the rest of the data */
	  if (next_len)
	    {
	      index++;
	      if (seg == 2)
		{
		  seg = 0;
		  to++;
		}
	      else
		seg++;
	      to->u.s.len[seg] = (next_len);
	      to->ptr[seg] = (next_vaddr);
	      to->u.s.valid_segs = seg + 1;
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

      index++;
      if (seg == 2)
	{
	  seg = 0;
	  to++;
	}
      else
	seg++;

      if (PREDICT_FALSE (!size))
	break;
    }

  *psize = size;
  return index;
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
oct_crypto_fill_sg_comp (struct roc_sglist_comp *list, uint32_t i, uint64_t dma_addr, uint32_t size)
{
  struct roc_sglist_comp *to = &list[i >> 2];

  to->u.s.len[i % 4] = clib_host_to_net_u16 (size);
  to->ptr[i % 4] = clib_host_to_net_u64 (dma_addr);
  return ++i;
}

static_always_inline u32
oct_crypto_fill_sg2_comp (struct roc_sg2list_comp *list, u32 index, u64 dma_addr, u32 size)
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
oct_crypto_sg_inst_prep (struct roc_se_fc_params *params, struct cpt_inst_s *inst,
			 uint64_t offset_ctrl, const uint8_t *iv_s, int iv_len, uint8_t pack_iv,
			 uint8_t pdcp_alg_type, int32_t inputlen, int32_t outputlen,
			 uint32_t passthrough_len, uint32_t req_flags, int pdcp_flag, int decrypt)
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

  m_vaddr = (uint8_t *) m_vaddr + ROC_SE_OFF_CTRL_LEN + PLT_ALIGN_CEIL (iv_len, 8);

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
  /* Offset control word followed by iv */

  i =
    oct_crypto_fill_sg_comp (gather_comp, 0, (uint64_t) offset_vaddr, ROC_SE_OFF_CTRL_LEN + iv_len);

  /* Add input data */
  if (decrypt && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = inputlen - iv_len - mac_len;

      if (PREDICT_TRUE (size))
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;
	  i = oct_crypto_fill_sg_comp_from_iov (gather_comp, i, params->src_iov, 0, &size, aad_buf,
						aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      ASSERT (0);
	      return -1;
	    }
	}

      if (mac_len)
	i = oct_crypto_fill_sg_comp_from_buf (gather_comp, i, &params->mac_buf);
    }
  else
    {
      /* input data */
      size = inputlen - iv_len;
      if (size)
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;
	  i = oct_crypto_fill_sg_comp_from_iov (gather_comp, i, params->src_iov, 0, &size, aad_buf,
						aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      ASSERT (0);
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

  scatter_comp = (struct roc_sglist_comp *) ((uint8_t *) gather_comp + g_size_bytes);

  i = oct_crypto_fill_sg_comp (scatter_comp, 0, (uint64_t) offset_vaddr + ROC_SE_OFF_CTRL_LEN,
			       iv_len);

  /* Add output data */
  if ((!decrypt) && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = outputlen - iv_len - mac_len;
      if (size)
	{

	  uint32_t aad_offset = aad_len ? passthrough_len : 0;

	  i = oct_crypto_fill_sg_comp_from_iov (scatter_comp, i, params->dst_iov, 0, &size, aad_buf,
						aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      ASSERT (0);
	      return -1;
	    }
	}

      /* mac data */
      if (mac_len)
	i = oct_crypto_fill_sg_comp_from_buf (scatter_comp, i, &params->mac_buf);
    }
  else
    {
      /* Output including mac */
      size = outputlen - iv_len;

      if (size)
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;

	  i = oct_crypto_fill_sg_comp_from_iov (scatter_comp, i, params->dst_iov, 0, &size, aad_buf,
						aad_offset);

	  if (PREDICT_FALSE (size))
	    {
	      ASSERT (0);
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
      ASSERT (0);
      ret = -1;
    }

  inst->dptr = (uint64_t) in_buffer;
  return ret;
}

static_always_inline int __attribute__ ((unused))
oct_crypto_sg2_inst_prep (struct roc_se_fc_params *params, struct cpt_inst_s *inst, u64 offset_ctrl,
			  const u8 *iv_s, int iv_len, u8 pack_iv, u8 pdcp_alg_type, i32 inputlen,
			  i32 outputlen, u32 passthrough_len, u32 req_flags, int pdcp_flag,
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

  index =
    oct_crypto_fill_sg2_comp (gather_comp, 0, (u64) offset_vaddr, ROC_SE_OFF_CTRL_LEN + iv_len);

  /* Add input data */
  if (decrypt && (req_flags & ROC_SE_VALID_MAC_BUF))
    size = inputlen - iv_len - mac_len;
  else
    size = inputlen - iv_len;

  if (size)
    {
      index = oct_crypto_fill_sg2_comp_from_iov (gather_comp, index, params->src_iov, 0, &size,
						 aad_buf, aad_len ? passthrough_len : 0);
      if (PREDICT_FALSE (size))
	{
	  ASSERT (0);
	  return -1;
	}
    }

  if (decrypt && (req_flags & ROC_SE_VALID_MAC_BUF) && mac_len)
    index = oct_crypto_fill_sg2_comp_from_buf (gather_comp, index, &params->mac_buf);

  gather_sz = (index + 2) / 3;
  g_size_bytes = gather_sz * sizeof (struct roc_sg2list_comp);

  /*
   * Output Scatter List
   */

  scatter_comp = (struct roc_sg2list_comp *) ((u8 *) gather_comp + g_size_bytes);

  index =
    oct_crypto_fill_sg2_comp (scatter_comp, 0, (u64) offset_vaddr + ROC_SE_OFF_CTRL_LEN, iv_len);

  /* Add output data */
  if ((!decrypt) && (req_flags & ROC_SE_VALID_MAC_BUF))
    size = outputlen - iv_len - mac_len;
  else
    size = outputlen - iv_len;

  if (size)
    {
      index = oct_crypto_fill_sg2_comp_from_iov (scatter_comp, index, params->dst_iov, 0, &size,
						 aad_buf, aad_len ? passthrough_len : 0);
      if (PREDICT_FALSE (size))
	{
	  ASSERT (0);
	  return -1;
	}
    }

  if ((!decrypt) && (req_flags & ROC_SE_VALID_MAC_BUF) && mac_len)
    index = oct_crypto_fill_sg2_comp_from_buf (scatter_comp, index, &params->mac_buf);

  scatter_sz = (index + 2) / 3;

  cpt_inst_w5.s.gather_sz = gather_sz;
  cpt_inst_w6.s.scatter_sz = scatter_sz;

  cpt_inst_w5.s.dptr = (u64) gather_comp;
  cpt_inst_w6.s.rptr = (u64) scatter_comp;

  inst->w5.u64 = cpt_inst_w5.u64;
  inst->w6.u64 = cpt_inst_w6.u64;

  if (PREDICT_FALSE ((scatter_sz >> 4) || (gather_sz >> 4)))
    {
      ASSERT (0);
      ret = -1;
    }

  return ret;
}

static_always_inline int
oct_crypto_cpt_prep (u32 flags, u64 d_offs, u64 d_lens, struct roc_se_fc_params *fc_params,
		     struct cpt_inst_s *inst, u8 is_aead, u8 is_decrypt)
{
  u32 encr_offset = ROC_SE_ENCR_OFFSET (d_offs);
  u32 auth_offset;
  u32 encr_data_len = ROC_SE_ENCR_DLEN (d_lens);
  u32 auth_data_len = ROC_SE_AUTH_DLEN (d_lens);
  u32 aad_len = 0;
  u32 data_len;
  i32 inputlen, outputlen, enc_dlen, auth_dlen;
  u32 iv_offset = 0;
  union cpt_inst_w4 cpt_inst_w4;
  u32 cipher_type;
  struct roc_se_ctx *se_ctx;
  u32 passthrough_len = 0;
  const u8 *src;
  u64 offset_ctrl;
  u8 iv_len = fc_params->cipher_iv_len;
  u8 op_minor;
  u32 mac_len;
  int ret;

  se_ctx = fc_params->ctx;
  cipher_type = se_ctx->enc_cipher;
  mac_len = se_ctx->mac_len;
  cpt_inst_w4.u64 = se_ctx->template_w4.u64;
  op_minor = cpt_inst_w4.s.opcode_minor;

  if (PREDICT_FALSE (is_aead && (flags & ROC_SE_VALID_AAD_BUF)))
    {
      aad_len = fc_params->aad_buf.size;
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
      auth_offset = ROC_SE_AUTH_OFFSET (d_offs) + iv_len;
    }

  auth_dlen = auth_offset + auth_data_len;
  enc_dlen = encr_data_len + encr_offset;
  data_len = auth_dlen > enc_dlen ? auth_dlen : enc_dlen;

  cpt_inst_w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

  if (is_decrypt)
    {
      cpt_inst_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;
      inputlen = data_len + mac_len;
      outputlen = data_len;
    }
  else
    {
      cpt_inst_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;

      /* Round  up  to 16 bytes alignment */
      if (PREDICT_FALSE (encr_data_len & 0xf))
	{
	  if (PREDICT_TRUE (cipher_type == ROC_SE_AES_CBC) || (cipher_type == ROC_SE_DES3_CBC))
	    enc_dlen = PLT_ALIGN_CEIL (encr_data_len, 8) + encr_offset;
	}

      /*
       * auth_dlen is larger than enc_dlen in Authentication cases
       * like AES GMAC Authentication
       */
      data_len = auth_dlen > enc_dlen ? auth_dlen : enc_dlen;
      inputlen = data_len;
      outputlen = data_len + mac_len;
    }

  if (op_minor & ROC_SE_FC_MINOR_OP_HMAC_FIRST)
    outputlen = enc_dlen;

  cpt_inst_w4.s.param1 = encr_data_len;
  cpt_inst_w4.s.param2 = auth_data_len;

  ASSERT (!((encr_offset >> 16) || (iv_offset >> 8) || (auth_offset >> 8)));

  offset_ctrl =
    clib_host_to_net_u64 (((u64) encr_offset << 16) | ((u64) iv_offset << 8) | ((u64) auth_offset));

  src = fc_params->iv_buf;

  inst->w4.u64 = cpt_inst_w4.u64;

#ifdef PLATFORM_OCTEON9
  ret = oct_crypto_sg_inst_prep (fc_params, inst, offset_ctrl, src, iv_len, 0, 0, inputlen,
				 outputlen, passthrough_len, flags, 0, is_decrypt);
#else
  ret = oct_crypto_sg2_inst_prep (fc_params, inst, offset_ctrl, src, iv_len, 0, 0, inputlen,
				  outputlen, passthrough_len, flags, 0, is_decrypt);
#endif

  if (PREDICT_FALSE (ret))
    return -1;

  return 0;
}

static_always_inline int
oct_crypto_scatter_gather_mode (vlib_main_t *vm, oct_crypto_sess_t *sess, struct cpt_inst_s *inst,
				const bool is_aead, u8 aad_length, u8 *payload,
				vnet_crypto_buffer_metadata_t *md, void *mdata,
				u32 cipher_data_length, u32 cipher_data_offset,
				u32 auth_data_length, u32 auth_data_offset, vlib_buffer_t *b,
				u16 adj_len)
{
  struct roc_se_fc_params fc_params = { 0 };
  struct roc_se_ctx *se_ctx = &sess->cpt_ctx;
  u64 d_offs = 0, d_lens = 0;
  vlib_buffer_t *buffer = b;
  u32 flags = 0, index = 0;
  u8 inline_aad = is_aead && auth_data_length != 0 && sess->aes_gcm;
  u8 op_minor = 0, cpt_op;
  char src_iov_data[SRC_IOV_SIZE];
  u8 iv_tmp[16] = {};
  u8 *tag_or_digest = 0;

  cpt_op = sess->cpt_op;

  if (is_aead)
    {
      tag_or_digest = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->icv_off);
      flags |= ROC_SE_VALID_IV_BUF;
      fc_params.cipher_iv_len = sess->iv_length;
      fc_params.iv_buf = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->iv_off);

      if (sess->aes_gcm)
	{
	  clib_memcpy_fast (iv_tmp, fc_params.iv_buf, 12);
	  ((u32 *) iv_tmp)[3] = clib_host_to_net_u32 (1);
	  fc_params.iv_buf = iv_tmp;
	}

      d_offs = (u64) cipher_data_offset << 16;
      d_lens = (u64) cipher_data_length << 32;

      if (inline_aad)
	{
	  d_offs |= auth_data_offset;
	  d_lens |= auth_data_length;
	}
      else
	{
	  fc_params.aad_buf.vaddr = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->aad_off);
	  fc_params.aad_buf.size = aad_length;
	  flags |= ROC_SE_VALID_AAD_BUF;
	}

      if (sess->cpt_ctx.mac_len)
	{
	  flags |= ROC_SE_VALID_MAC_BUF;
	  fc_params.mac_buf.size = sess->cpt_ctx.mac_len;
	  fc_params.mac_buf.vaddr = tag_or_digest;
	}
    }
  else
    {
      tag_or_digest = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->icv_off);
      op_minor = se_ctx->template_w4.s.opcode_minor;

      flags |= ROC_SE_VALID_IV_BUF;
      fc_params.cipher_iv_len = sess->iv_length;
      fc_params.iv_buf = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->iv_off);
      d_offs = ((u64) cipher_data_offset << 16) | auth_data_offset;
      d_lens = ((u64) cipher_data_length << 32) | auth_data_length;

      if (PREDICT_TRUE (sess->cpt_ctx.mac_len))
	{
	  if (!(op_minor & ROC_SE_FC_MINOR_OP_HMAC_FIRST))
	    {
	      flags |= ROC_SE_VALID_MAC_BUF;
	      fc_params.mac_buf.size = sess->cpt_ctx.mac_len;
	      fc_params.mac_buf.vaddr = tag_or_digest;
	    }
	}
    }

  fc_params.ctx = &sess->cpt_ctx;
  fc_params.src_iov = (void *) src_iov_data;
  fc_params.src_iov->bufs[index].vaddr = payload;
  fc_params.src_iov->bufs[index].size = b->current_length + adj_len;
  index++;

  while (buffer->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      buffer = vlib_get_buffer (vlib_get_main (), buffer->next_buffer);
      fc_params.src_iov->bufs[index].vaddr = buffer->data + buffer->current_data;
      fc_params.src_iov->bufs[index].size = buffer->current_length;
      index++;
    }

  fc_params.src_iov->buf_cnt = index;
  fc_params.dst_iov = (void *) src_iov_data;

  fc_params.meta_buf.vaddr = mdata;
  fc_params.meta_buf.size = OCT_SCATTER_GATHER_BUFFER_SIZE;

  return oct_crypto_cpt_prep (flags, d_offs, d_lens, &fc_params, inst, is_aead, cpt_op);
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

static_always_inline vnet_crypto_frame_enq_fn_t *
oct_crypto_get_async_enqueue_handler (vnet_crypto_alg_t alg_id, vnet_crypto_op_type_t type)
{
  const oct_crypto_alg_data_t *alg = oct_crypto_algs + alg_id;

  switch (type)
    {
    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
      return alg->enc_fn;
    case VNET_CRYPTO_OP_TYPE_DECRYPT:
      return alg->dec_fn;
    case VNET_CRYPTO_OP_TYPE_HMAC:
    case VNET_CRYPTO_OP_N_TYPES:
      break;
    }

  return 0;
}

static_always_inline i32
oct_crypto_combined_session_update (vlib_main_t *vm, oct_crypto_sess_t *sess,
				    vnet_crypto_ctx_t *ctx, u8 type)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + ctx->alg;
  const oct_crypto_alg_data_t *alg = oct_crypto_algs + ctx->alg;
  const u8 *crypto_key_data, *auth_key_data;
  u16 crypto_key_len = ad->cipher_key_len;
  u16 auth_key_len = 0;
  u32 digest_len = ad->auth_len;
  i32 rv = 0;

  if (PREDICT_FALSE (alg->valid == 0 || alg->cipher_type == 0 || alg->auth_type == 0))
    {
      ASSERT (0);
      return -1;
    }

  if (type == VNET_CRYPTO_OP_TYPE_ENCRYPT)
    sess->cpt_ctx.ciph_then_auth = true;
  else
    sess->cpt_ctx.auth_then_ciph = true;

  sess->iv_length = 16;
  sess->cpt_op = type;

  if (ctx->cipher_key_sz + ctx->auth_key_sz < crypto_key_len)
    return -1;

  auth_key_len = ctx->auth_key_sz;
  if (auth_key_len == 0)
    return -1;

  crypto_key_data = vnet_crypto_get_cipher_key (ctx);
  auth_key_data = vnet_crypto_get_auth_key (ctx);

  rv = roc_se_ciph_key_set (&sess->cpt_ctx, alg->cipher_type, crypto_key_data, crypto_key_len);
  if (rv == 0)
    rv =
      roc_se_auth_key_set (&sess->cpt_ctx, alg->auth_type, auth_key_data, auth_key_len, digest_len);

  if (rv)
    {
      ASSERT (0);
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
oct_crypto_aead_session_update (vlib_main_t *vm, oct_crypto_sess_t *sess, vnet_crypto_ctx_t *ctx,
				vnet_crypto_alg_t alg_id, u8 type)
{
  vnet_crypto_main_t *cm = &crypto_main;
  const oct_crypto_alg_data_t *alg = oct_crypto_algs + alg_id;
  u32 digest_len = alg->digest_len ? alg->digest_len : cm->algs[alg_id].auth_len;
  i32 rv = 0;

  if (PREDICT_FALSE (alg->valid == 0 || alg->cipher_type == 0))
    {
      ASSERT (0);
      return -1;
    }

  sess->aes_gcm = alg->aes_gcm;
  sess->iv_length = alg->iv_length;
  sess->cpt_ctx.mac_len = digest_len;
  sess->cpt_op = type;

  rv = roc_se_ciph_key_set (&sess->cpt_ctx, alg->cipher_type, vnet_crypto_get_cipher_key (ctx),
			    ctx->cipher_key_sz);
  if (rv)
    {
      ASSERT (0);
      return -1;
    }

  rv = roc_se_auth_key_set (&sess->cpt_ctx, alg->auth_type, NULL, 0, digest_len);
  if (rv)
    {
      ASSERT (0);
      return -1;
    }

  sess->cpt_ctx.template_w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

  if (sess->cpt_op == VNET_CRYPTO_OP_TYPE_DECRYPT)
    sess->cpt_ctx.template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;
  else
    sess->cpt_ctx.template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;

  sess->cpt_ctx.template_w4.s.opcode_minor |= alg->opcode_minor_flags;

  return 0;
}

static_always_inline i32
oct_crypto_session_init (vlib_main_t *vm, oct_crypto_sess_t *session, vnet_crypto_ctx_t *ctx,
			 vnet_crypto_alg_t alg_id, int op_type)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  oct_crypto_dev_t *ocd;
  vnet_crypto_main_t *cm = &crypto_main;
  i32 rv = 0;

  ocd = ocm->crypto_dev[op_type];

  if (cm->algs[ctx->alg].alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    rv = oct_crypto_combined_session_update (vm, session, ctx, op_type);
  else
    rv = oct_crypto_aead_session_update (vm, session, ctx, alg_id, op_type);

  if (rv)
    {
      oct_crypto_session_free (vm, session);
      return -1;
    }

  session->crypto_dev = ocd;

  session->cpt_inst_w7 = oct_cpt_inst_w7_get (session, session->crypto_dev->roc_cpt);

  if (oct_hw_ctx_cache_enable ())
    roc_se_ctx_init (&session->cpt_ctx);

  session->initialised = 1;

  return 0;
}

static_always_inline void
oct_crypto_update_frame_error_status (vnet_crypto_async_frame_t *f, u32 index, u8 s)
{
  u32 i;

  for (i = index; i < f->n_elts; i++)
    {
      if (s == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	vlib_crypto_async_frame_set_hmac_fail (f, i);
      else
	vlib_crypto_async_frame_set_engine_error (f, i);
    }

  f->state = VNET_CRYPTO_FRAME_STATE_COMPLETED;
}

static_always_inline int
oct_crypto_enq (vlib_main_t *vm, vnet_crypto_async_frame_t *frame, const u8 is_aead, u8 aad_len,
		const u8 is_enc)
{
  u32 i, enq_tail, enc_auth_len, buffer_index, nb_infl_allowed;
  struct cpt_inst_s inst[VNET_CRYPTO_FRAME_SIZE];
  u32 auth_start_offset, auth_len;
  u8 aad_inline_len;
  u16 adj_len;
  u32 crypto_start_offset, integ_start_offset;
  oct_crypto_main_t *ocm = &oct_crypto_main;
  oct_crypto_dev_t *crypto_dev = NULL;
  oct_crypto_inflight_req_t *infl_req;
  oct_crypto_pending_queue_t *pend_q;
  oct_crypto_sess_t *sess;
  u32 crypto_total_length;
  oct_crypto_key_t *ckey;
  vnet_crypto_buffer_metadata_t *md;
  vnet_crypto_ctx_t *ctx;
  vlib_buffer_t *buffer;
  u8 *payload;
  void *sg_data;
  u8 type;
  int ret = 0;

  type = is_enc ? VNET_CRYPTO_OP_TYPE_ENCRYPT : VNET_CRYPTO_OP_TYPE_DECRYPT;
  pend_q = &ocm->pend_q[vlib_get_thread_index ()];

  nb_infl_allowed = pend_q->n_desc - pend_q->n_crypto_inflight;
  if (PREDICT_FALSE (nb_infl_allowed < frame->n_elts))
    {
      oct_crypto_update_frame_error_status (frame, 0, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
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

      buffer_index = frame->buffer_indices[i];
      ctx = frame->ctxs[i];
      ckey = (oct_crypto_key_t *) vnet_crypto_get_async_key_data (ctx);

      if (PREDICT_FALSE (!ckey->sess[type]))
	{
	  oct_crypto_update_frame_error_status (frame, i, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	  return -1;
	}

      sess = ckey->sess[type];

      if (PREDICT_FALSE (!sess->initialised))
	ret = oct_crypto_session_init (vm, sess, ctx, frame->alg, type);
      if (ret)
	{
	  oct_crypto_update_frame_error_status (frame, i, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	  return -1;
	}

      crypto_dev = sess->crypto_dev;

      inst[i] = (struct cpt_inst_s){};

      buffer = vlib_get_buffer (vm, buffer_index);
      md = vnet_crypto_buffer_get_metadata (buffer);
      payload = buffer->data - VLIB_BUFFER_PRE_DATA_SIZE;
      adj_len = VLIB_BUFFER_PRE_DATA_SIZE + buffer->current_data;

      if (is_aead)
	{
	  crypto_total_length = md->cipher_data_len;
	  ASSERT (md->cipher_data_start_off + VLIB_BUFFER_PRE_DATA_SIZE >= 0);
	  crypto_start_offset = md->cipher_data_start_off + VLIB_BUFFER_PRE_DATA_SIZE;
	  integ_start_offset = 0;
	  auth_start_offset = 0;
	  auth_len = 0;
	  aad_inline_len = (sess->aes_gcm || crypto_total_length == 0) ? aad_len : 16;

	  if (aad_len && md->cipher_data_start_off == buffer->current_data)
	    {
	      ASSERT (adj_len >= aad_inline_len);
	      if (aad_inline_len != aad_len)
		clib_memset (payload + crypto_start_offset - aad_inline_len, 0, aad_inline_len);
	      clib_memcpy_fast (payload + crypto_start_offset - aad_inline_len,
				vnet_crypto_buffer_metadata_get_ptr (vm, buffer, md->aad_off),
				aad_len);
	      auth_start_offset = crypto_start_offset - aad_inline_len;
	      auth_len = aad_inline_len + crypto_total_length;
	    }

	  ret = oct_crypto_scatter_gather_mode (
	    vm, sess, inst + i, is_aead, aad_len, payload, md,
	    ((oct_crypto_scatter_gather_t *) (sg_data)) + enq_tail,
	    crypto_total_length /* cipher_len */, crypto_start_offset /* cipher_offset */, auth_len,
	    auth_start_offset /* auth_off */, buffer, adj_len);

	  if (PREDICT_FALSE (ret < 0))
	    {
	      oct_crypto_update_frame_error_status (frame, i,
						    VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      return -1;
	    }
	}
      else
	{
	  ASSERT (md->cipher_data_start_off + VLIB_BUFFER_PRE_DATA_SIZE >= 0);
	  ASSERT (md->auth_data_start_off + VLIB_BUFFER_PRE_DATA_SIZE >= 0);
	  crypto_start_offset = md->cipher_data_start_off + VLIB_BUFFER_PRE_DATA_SIZE;
	  integ_start_offset = md->auth_data_start_off + VLIB_BUFFER_PRE_DATA_SIZE;
	  enc_auth_len = md->auth_data_len;
	  crypto_total_length = md->cipher_data_len;

	  ret = oct_crypto_scatter_gather_mode (
	    vm, sess, inst + i, is_aead, aad_len, payload, md,
	    ((oct_crypto_scatter_gather_t *) (sg_data)) + enq_tail,
	    crypto_total_length /* cipher_len */, crypto_start_offset /* cipher_offset */,
	    enc_auth_len /* auth_len */, integ_start_offset /* auth_off */, buffer, adj_len);

	  if (PREDICT_FALSE (ret < 0))
	    {
	      oct_crypto_update_frame_error_status (frame, i,
						    VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      return -1;
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

static int
oct_crypto_enqueue_enc (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enq (vm, frame, 0 /* is_aead */, 0 /* aad_len */, 1 /* is_enc */);
}

static int
oct_crypto_enqueue_dec (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enq (vm, frame, 0 /* is_aead */, 0 /* aad_len */, 0 /* is_enc */);
}

static int
oct_crypto_enqueue_aead_aad8_enc (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enq (vm, frame, 1 /* is_aead */, 8 /* aad_len */, 1 /* is_enc */);
}

static int
oct_crypto_enqueue_aead_aad12_enc (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enq (vm, frame, 1 /* is_aead */, 12 /* aad_len */, 1 /* is_enc */);
}

static int
oct_crypto_enqueue_aead_aad0_enc (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enq (vm, frame, 1 /* is_aead */, 0 /* aad_len */, 1 /* is_enc */);
}

static int
oct_crypto_enqueue_aead_aad8_dec (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enq (vm, frame, 1 /* is_aead */, 8 /* aad_len */, 0 /* is_enc */);
}

static int
oct_crypto_enqueue_aead_aad12_dec (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enq (vm, frame, 1 /* is_aead */, 12 /* aad_len */, 0 /* is_enc */);
}

static int
oct_crypto_enqueue_aead_aad0_dec (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return oct_crypto_enq (vm, frame, 1 /* is_aead */, 0 /* aad_len */, 0 /* is_enc */);
}

vnet_crypto_async_frame_t *
oct_crypto_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			  clib_thread_index_t *enqueue_thread_idx)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  u32 deq_head;
  oct_crypto_inflight_req_t *infl_req;
  oct_crypto_pending_queue_t *pend_q;
  vnet_crypto_async_frame_t *frame;
  volatile union cpt_res_s *res;
  bool last_elts_processed;

  pend_q = &ocm->pend_q[vlib_get_thread_index ()];

  if (!pend_q->n_crypto_frame)
    return NULL;

  last_elts_processed = false;

  for (; last_elts_processed == false;)
    {
      deq_head = pend_q->deq_head;
      infl_req = &pend_q->req_queue[deq_head];
      res = &infl_req->res;

      if (PREDICT_FALSE (res->cn10k.compcode == CPT_COMP_NOT_DONE))
	return NULL;

      if (PREDICT_FALSE (res->cn10k.uc_compcode))
	{
	  if (res->cn10k.uc_compcode == ROC_SE_ERR_GC_ICV_MISCOMPARE)
	    vlib_crypto_async_frame_set_hmac_fail (infl_req->frame, infl_req->index);
	  else
	    vlib_crypto_async_frame_set_engine_error (infl_req->frame, infl_req->index);
	}

      infl_req->res = (union cpt_res_s){};
      last_elts_processed = infl_req->last_elts;
      OCT_MOD_INC (pend_q->deq_head, pend_q->n_desc);
    }

  frame = infl_req->frame;

  pend_q->n_crypto_frame--;
  pend_q->n_crypto_inflight -= frame->n_elts;

  frame->state = VNET_CRYPTO_FRAME_STATE_COMPLETED;

  *nb_elts_processed = frame->n_elts;
  *enqueue_thread_idx = frame->enqueue_thread_index;

  return frame;
}

int
oct_init_crypto_engine_handlers (vlib_main_t *vm, vnet_dev_t *dev __clib_unused)
{
  vnet_crypto_frame_enq_fn_t *fn;
  u32 engine_index;

  engine_index = vnet_crypto_register_engine (vm, "octteon_cpt", 100, "Octeon CPT Engine");

  vnet_crypto_register_dequeue_handler (vm, engine_index, oct_crypto_frame_dequeue);

  for (u32 i = 1; i < VNET_CRYPTO_N_ALGS; i++)
    {
      for (u32 type = 0; type < VNET_CRYPTO_OP_N_TYPES; type++)
	{
	  fn = oct_crypto_get_async_enqueue_handler (i, type);
	  if (fn)
	    vnet_crypto_register_enqueue_handler_by_alg (vm, engine_index, i, type, fn);
	}
    }

  if (vnet_crypto_register_key_change_handler (vm, engine_index, oct_crypto_key_change_handler,
					       sizeof (oct_crypto_key_t)))
    return -1;

  return 0;
}

int
oct_conf_sw_queue (vlib_main_t *vm, vnet_dev_t *dev, oct_crypto_dev_t *ocd)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_inflight_req;
  int i;

  ocm->pend_q = oct_plt_init_param.oct_plt_zmalloc (
    tm->n_vlib_mains * sizeof (oct_crypto_pending_queue_t), CLIB_CACHE_LINE_BYTES);
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
	ocm->pend_q[i].n_desc * sizeof (oct_crypto_inflight_req_t), CLIB_CACHE_LINE_BYTES);
      if (ocm->pend_q[i].req_queue == NULL)
	{
	  log_err (dev, "Failed to allocate memory for crypto inflight request");
	  goto free;
	}

      ocm->pend_q[i].sg_data = oct_plt_init_param.oct_plt_zmalloc (
	OCT_SCATTER_GATHER_BUFFER_SIZE * ocm->pend_q[i].n_desc, CLIB_CACHE_LINE_BYTES);
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

static const oct_crypto_alg_data_t oct_crypto_algs[VNET_CRYPTO_N_ALGS] = {
  [VNET_CRYPTO_ALG_AES_128_CBC] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .iv_length = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_MD5_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_MD5_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_MD5_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_MD5_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_MD5_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_MD5_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_SHA1_160_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_SHA1_160_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_SHA1_160_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_SHA_256_ICV16] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_SHA_256_ICV16] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_SHA_256_ICV16] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_SHA_384_ICV24] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_SHA_384_ICV24] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_SHA_384_ICV24] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CBC_SHA_512_ICV32] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CBC_SHA_512_ICV32] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CBC_SHA_512_ICV32] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CBC,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR_SHA1_160_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR_SHA1_160_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR_SHA1_160_ICV12] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA1_TYPE,
    .digest_len = 12,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR_SHA_256_ICV16] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR_SHA_256_ICV16] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR_SHA_256_ICV16] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA256,
    .digest_len = 16,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR_SHA_384_ICV24] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR_SHA_384_ICV24] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR_SHA_384_ICV24] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA384,
    .digest_len = 24,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_CTR_SHA_512_ICV32] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_CTR_SHA_512_ICV32] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_CTR_SHA_512_ICV32] = {
    .enc_fn = oct_crypto_enqueue_enc,
    .dec_fn = oct_crypto_enqueue_dec,
    .cipher_type = ROC_SE_AES_CTR,
    .auth_type = ROC_SE_SHA2_SHA512,
    .digest_len = 32,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_GCM_ICV16_AAD8] = {
    .enc_fn = oct_crypto_enqueue_aead_aad8_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad8_dec,
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 8,
    .digest_len = 16,
    .iv_length = 16,
    .aes_gcm = 1,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_128_GCM_ICV16_AAD12] = {
    .enc_fn = oct_crypto_enqueue_aead_aad12_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad12_dec,
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 12,
    .digest_len = 16,
    .iv_length = 16,
    .aes_gcm = 1,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_GCM_ICV16_AAD8] = {
    .enc_fn = oct_crypto_enqueue_aead_aad8_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad8_dec,
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 8,
    .digest_len = 16,
    .iv_length = 16,
    .aes_gcm = 1,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_192_GCM_ICV16_AAD12] = {
    .enc_fn = oct_crypto_enqueue_aead_aad12_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad12_dec,
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 12,
    .digest_len = 16,
    .iv_length = 16,
    .aes_gcm = 1,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_GCM_ICV16_AAD8] = {
    .enc_fn = oct_crypto_enqueue_aead_aad8_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad8_dec,
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 8,
    .digest_len = 16,
    .iv_length = 16,
    .aes_gcm = 1,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_AES_256_GCM_ICV16_AAD12] = {
    .enc_fn = oct_crypto_enqueue_aead_aad12_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad12_dec,
    .cipher_type = ROC_SE_AES_GCM,
    .aad_len = 12,
    .digest_len = 16,
    .iv_length = 16,
    .aes_gcm = 1,
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD0] = {
    .enc_fn = oct_crypto_enqueue_aead_aad0_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad0_dec,
    .cipher_type = ROC_SE_CHACHA20,
    .auth_type = ROC_SE_POLY1305,
    .digest_len = 16,
    .iv_length = 12,
    .opcode_minor_flags = BIT (5),
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD8] = {
    .enc_fn = oct_crypto_enqueue_aead_aad8_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad8_dec,
    .cipher_type = ROC_SE_CHACHA20,
    .auth_type = ROC_SE_POLY1305,
    .aad_len = 8,
    .digest_len = 16,
    .iv_length = 12,
    .opcode_minor_flags = BIT (5),
    .valid = 1,
  },
  [VNET_CRYPTO_ALG_CHACHA20_POLY1305_ICV16_AAD12] = {
    .enc_fn = oct_crypto_enqueue_aead_aad12_enc,
    .dec_fn = oct_crypto_enqueue_aead_aad12_dec,
    .cipher_type = ROC_SE_CHACHA20,
    .auth_type = ROC_SE_POLY1305,
    .aad_len = 12,
    .digest_len = 16,
    .iv_length = 12,
    .opcode_minor_flags = BIT (5),
    .valid = 1,
  },
};
