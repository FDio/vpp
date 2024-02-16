/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <dev_octeon/octeon.h>
#include <dev_octeon/crypto.h>
#include <base/roc_api.h>
#include <common.h>

oct_crypto_t oct_crypto;
oct_crypto_dev_t oct_crypto_dev;

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "init",
};

void
oct_crypto_key_del_handler (vlib_main_t *vm, vnet_crypto_key_index_t key_index)
{
  extern oct_plt_init_param_t oct_plt_init_param;
  oct_crypto_key_t *ckey;

  vec_validate (oct_crypto.keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  ckey =
    vec_elt_at_index (oct_crypto.keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  if (ckey->sess)
    {
      oct_plt_init_param.oct_plt_free (ckey->sess);
      ckey->sess = NULL;
      return;
    }

  ckey =
    vec_elt_at_index (oct_crypto.keys[VNET_CRYPTO_OP_TYPE_DECRYPT], key_index);
  if (ckey->sess)
    {
      oct_plt_init_param.oct_plt_free (ckey->sess);
      ckey->sess = NULL;
      return;
    }
}

void
oct_crypto_key_add_handler (vlib_main_t *vm, vnet_crypto_key_index_t key_index)
{
  oct_crypto_key_t *ckey;

  vec_validate (oct_crypto.keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  ckey =
    vec_elt_at_index (oct_crypto.keys[VNET_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  ckey->sess = NULL;

  vec_validate (oct_crypto.keys[VNET_CRYPTO_OP_TYPE_DECRYPT], key_index);
  ckey =
    vec_elt_at_index (oct_crypto.keys[VNET_CRYPTO_OP_TYPE_DECRYPT], key_index);
  ckey->sess = NULL;
}

void
oct_crypto_key_handler (vlib_main_t *vm, vnet_crypto_key_op_t kop,
			vnet_crypto_key_index_t idx)
{
  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      oct_crypto_key_del_handler (vm, idx);
      return;
    }
  oct_crypto_key_add_handler (vm, idx);
}

static_always_inline oct_crypto_sess_t *
oct_crypto_session_alloc (vlib_main_t *vm)
{
  extern oct_plt_init_param_t oct_plt_init_param;
  oct_crypto_sess_t *addr = NULL;
  u32 size;

  size = sizeof (oct_crypto_sess_t);
  addr = oct_plt_init_param.oct_plt_zmalloc (size, CLIB_CACHE_LINE_BYTES);
  if (addr == NULL)
    {
      log_err (oct_crypto_dev.dev, "Failed to allocate crypto session memory");
      return NULL;
    }

  return addr;
}

static_always_inline void
oct_crypto_session_free (vlib_main_t *vm, oct_crypto_sess_t *sess)
{
  extern oct_plt_init_param_t oct_plt_init_param;

  oct_plt_init_param.oct_plt_free (sess);
  return;
}

void
oct_crypto_burst_submit (oct_crypto_dev_t *crypto_dev, struct cpt_inst_s *inst,
			 u32 n_left)
{
  u64 *lmt_line[OCT_MAX_LMT_SZ];
  u64 lmt_arg, core_lmt_id;
  u64 lmt_base;
  u64 io_addr;
  u32 count;

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
      asm volatile("dmb oshst" ::: "memory");

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
      asm volatile("dmb oshst" ::: "memory");

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

static_always_inline int
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
	      log_err (oct_crypto_dev.dev,
		       "Insufficient buffer"
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
	      log_err (oct_crypto_dev.dev,
		       "Insufficient buffer space,"
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
	      log_err (oct_crypto_dev.dev,
		       "Insufficient buffer space,"
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
	      log_err (oct_crypto_dev.dev,
		       "Insufficient buffer space,"
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
      log_err (oct_crypto_dev.dev,
	       "Exceeds max supported components. Reduce segments");
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
  u32 cipher_type, hash_type;
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
  hash_type = se_ctx->hash_type;
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
	  if (PREDICT_TRUE (cipher_type == ROC_SE_AES_CBC))
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
      log_err (oct_crypto_dev.dev, "Offset not supported");
      log_err (oct_crypto_dev.dev,
	       "enc_offset: %d, iv_offset : %d, auth_offset: %d", encr_offset,
	       iv_offset, auth_offset);
      return -1;
    }

  offset_ctrl = clib_host_to_net_u64 (
    ((u64) encr_offset << 16) | ((u64) iv_offset << 8) | ((u64) auth_offset));

  src = fc_params->iv_buf;

  inst->w4.u64 = cpt_inst_w4.u64;

  ret = oct_crypto_sg2_inst_prep (fc_params, inst, offset_ctrl, src, iv_len, 0,
				  0, inputlen, outputlen, passthrough_len,
				  flags, 0, is_decrypt);

  if (PREDICT_FALSE (ret))
    {
      log_err (oct_crypto_dev.dev, "sg prep failed");
      return -1;
    }

  return 0;
}

static_always_inline void
oct_crypto_fill_fc_params (oct_crypto_sess_t *sess, struct cpt_inst_s *inst,
			   const bool is_aead, u8 aad_length, u8 *payload,
			   vnet_crypto_async_frame_elt_t *elts, void *mdata,
			   u32 cipher_data_length, u32 cipher_data_offset,
			   u32 auth_data_length, u32 auth_data_offset,
			   vlib_buffer_t *b, u16 adj_len)
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

  oct_crypto_cpt_hmac_prep (flags, d_offs, d_lens, &fc_params, inst, cpt_op);
}

static_always_inline u64
oct_cpt_inst_w7_get (oct_crypto_sess_t *sess, struct roc_cpt *roc_cpt)
{
  union cpt_inst_w7 inst_w7;

  inst_w7.u64 = 0;
  inst_w7.s.cptr = (u64) &sess->cpt_ctx.se_ctx.fctx;
  /* Set the engine group */
  inst_w7.s.egrp = roc_cpt->eng_grp[CPT_ENG_TYPE_IE];

  return inst_w7.u64;
}

static_always_inline void
oct_map_keyindex_to_session (oct_crypto_sess_t *sess, u32 key_index, u8 type)
{
  oct_crypto_key_t *ckey;

  ckey = vec_elt_at_index (oct_crypto.keys[type], key_index);

  ckey->sess = sess;
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

  switch (key->async_alg)
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
    default:
      log_err (oct_crypto_dev.dev,
	       "Crypto: Undefined link algo %u specified. Key index %u",
	       key->async_alg, key_index);
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
			    vec_len (crypto_key->data));
  if (rv)
    {
      log_err (oct_crypto_dev.dev,
	       "Error in setting cipher key for enc type %u", enc_type);
      return -1;
    }

  auth_key = vnet_crypto_get_key (key->index_integ);

  rv = roc_se_auth_key_set (&sess->cpt_ctx, auth_type, auth_key->data,
			    vec_len (auth_key->data), digest_len);
  if (rv)
    {
      log_err (oct_crypto_dev.dev,
	       "Error in setting auth key for auth type %u", auth_type);
      return -1;
    }

  oct_map_keyindex_to_session (sess, key_index, type);
  /*
   * Map session to crypto key index also. This entry can be referred
   * while deleting key
   */
  oct_map_keyindex_to_session (sess, key->index_crypto, type);

  return 0;
}

static_always_inline i32
oct_crypto_aead_session_update (vlib_main_t *vm, oct_crypto_sess_t *sess,
				u32 key_index, u8 type)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (key_index);
  roc_se_cipher_type enc_type = 0;
  roc_se_auth_type auth_type = 0;
  u32 digest_len = ~0;
  i32 rv = 0;

  switch (key->async_alg)
    {
    case VNET_CRYPTO_ALG_AES_128_GCM:
    case VNET_CRYPTO_ALG_AES_192_GCM:
    case VNET_CRYPTO_ALG_AES_256_GCM:
      enc_type = ROC_SE_AES_GCM;
      sess->aes_gcm = 1;
      sess->iv_offset = 0;
      sess->iv_length = 16;
      sess->cpt_ctx.mac_len = 16;
      sess->cpt_op = type;
      digest_len = 16;
      break;
    default:
      log_err (oct_crypto_dev.dev,
	       "Crypto: Undefined cipher algo %u specified. Key index %u",
	       key->async_alg, key_index);
      return -1;
    }

  rv = roc_se_ciph_key_set (&sess->cpt_ctx, enc_type, key->data,
			    vec_len (key->data));
  if (rv)
    {
      log_err (oct_crypto_dev.dev,
	       "Error in setting cipher key for enc type %u", enc_type);
      return -1;
    }

  rv = roc_se_auth_key_set (&sess->cpt_ctx, auth_type, NULL, 0, digest_len);
  if (rv)
    {
      log_err (oct_crypto_dev.dev,
	       "Error in setting auth key for auth type %u", auth_type);
      return -1;
    }

  oct_map_keyindex_to_session (sess, key_index, type);

  return 0;
}

i32
oct_crypto_session_create (vlib_main_t *vm, vnet_crypto_key_index_t key_index,
			   int op_type)
{
  oct_crypto_sess_t *session;
  vnet_crypto_key_t *key;
  i32 rv = 0;

  key = vnet_crypto_get_key (key_index);

  session = oct_crypto_session_alloc (vm);
  if (session == NULL)
    return -1;

  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    rv = oct_crypto_link_session_update (vm, session, key_index, op_type);
  else
    rv = oct_crypto_aead_session_update (vm, session, key_index, op_type);

  if (rv)
    {
      oct_crypto_session_free (vm, session);
      return -1;
    }

  session->crypto_dev = &oct_crypto_dev;

  session->cpt_inst_w7 =
    oct_cpt_inst_w7_get (session, session->crypto_dev->roc_cpt);

  return 0;
}

static_always_inline void
oct_crypto_update_frame_error_status (vnet_crypto_async_frame_t *f,
				      vnet_crypto_op_status_t s)
{
  u32 i;

  for (i = 0; i < f->n_elts; i++)
    f->elts[i].status = s;

  f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
}

int
oct_crypto_enqueue_enc_dec (vlib_main_t *vm, vnet_crypto_async_frame_t *frame,
			    const u8 is_aead, u8 aad_len, const u8 type)
{
  struct cpt_inst_s inst[VNET_CRYPTO_FRAME_SIZE];
  u32 i, enq_tail, enc_auth_len, buffer_index;
  u32 crypto_start_offset, integ_start_offset;
  vnet_crypto_async_frame_elt_t *elts;
  oct_crypto_dev_t *crypto_dev = NULL;
  oct_crypto_inflight_req_t *infl_req;
  oct_crypto_pending_queue_t *pend_q;
  u64 dptr_start_ptr, curr_ptr;
  oct_crypto_sess_t *sess;
  u32 crypto_total_length;
  oct_crypto_key_t *key;
  vlib_buffer_t *buffer;
  u16 adj_len;

  /* GCM packets having 8 bytes of aad and 8 bytes of iv */
  u8 aad_iv = 8 + 8;

  pend_q = &oct_crypto.pend_q[vlib_get_thread_index ()];

  enq_tail = pend_q->enq_tail;

  infl_req = &pend_q->req_queue[enq_tail];
  infl_req->frame = frame;

  for (i = 0; i < frame->n_elts; i++)
    {
      elts = &frame->elts[i];
      buffer_index = frame->buffer_indices[i];
      key = vec_elt_at_index (oct_crypto.keys[type], elts->key_index);

      if (!key->sess)
	{
	  if (oct_crypto_session_create (vm, elts->key_index, type) == -1)
	    {
	      oct_crypto_update_frame_error_status (
		frame, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      return -1;
	    }
	}
      sess = key->sess;
      crypto_dev = sess->crypto_dev;

      memset (inst + i, 0, sizeof (struct cpt_inst_s));

      buffer = vlib_get_buffer (vm, buffer_index);

      if (is_aead)
	{
	  dptr_start_ptr =
	    (u64) (buffer->data + (elts->crypto_start_offset - aad_iv));
	  curr_ptr = (u64) (buffer->data + buffer->current_data);
	  adj_len = (u16) (dptr_start_ptr - curr_ptr);

	  crypto_total_length = elts->crypto_total_length;
	  crypto_start_offset = aad_iv;
	  integ_start_offset = 0;

	  oct_crypto_fill_fc_params (
	    sess, inst + i, is_aead, aad_len, (u8 *) dptr_start_ptr, elts,
	    (oct_crypto_scatter_gather_t *) (infl_req->sg_data) + i,
	    crypto_total_length /* cipher_len */,
	    crypto_start_offset /* cipher_offset */, 0 /* auth_len */,
	    integ_start_offset /* auth_off */, buffer, adj_len);
	}
      else
	{
	  dptr_start_ptr = (u64) (buffer->data + elts->crypto_start_offset -
				  elts->integ_length_adj);
	  enc_auth_len = elts->crypto_total_length + elts->integ_length_adj;

	  curr_ptr = (u64) (buffer->data + buffer->current_data);
	  adj_len = (u16) (dptr_start_ptr - curr_ptr);

	  crypto_total_length = elts->crypto_total_length;
	  crypto_start_offset =
	    elts->crypto_start_offset - elts->integ_start_offset;
	  integ_start_offset = 0;

	  oct_crypto_fill_fc_params (
	    sess, inst + i, is_aead, aad_len, (u8 *) dptr_start_ptr, elts,
	    (oct_crypto_scatter_gather_t *) (infl_req->sg_data) + i,
	    crypto_total_length /* cipher_len */,
	    crypto_start_offset /* cipher_offset */,
	    enc_auth_len /* auth_len */, integ_start_offset /* auth_off */,
	    buffer, adj_len);
	}

      inst[i].w7.u64 = sess->cpt_inst_w7;
      inst[i].res_addr = (u64) &infl_req->res[i];
    }

  oct_crypto_burst_submit (crypto_dev, inst, frame->n_elts);

  infl_req->elts = frame->n_elts;
  OCT_MOD_INC (pend_q->enq_tail, pend_q->n_desc);
  pend_q->n_crypto_inflight++;

  return 0;
}

int
oct_crypto_enqueue_linked_alg_enc (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  oct_crypto_enqueue_enc_dec (vm, frame, 0 /* is_aead */, 0 /* aad_len */,
			      VNET_CRYPTO_OP_TYPE_ENCRYPT);
  return 0;
}

int
oct_crypto_enqueue_linked_alg_dec (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  oct_crypto_enqueue_enc_dec (vm, frame, 0 /* is_aead */, 0 /* aad_len */,
			      VNET_CRYPTO_OP_TYPE_DECRYPT);
  return 0;
}

int
oct_crypto_enqueue_aead_aad_enc (vlib_main_t *vm,
				 vnet_crypto_async_frame_t *frame, u8 aad_len)
{
  oct_crypto_enqueue_enc_dec (vm, frame, 1 /* is_aead */, aad_len,
			      VNET_CRYPTO_OP_TYPE_ENCRYPT);

  return 0;
}

int
oct_crypto_enqueue_aead_aad_dec (vlib_main_t *vm,
				 vnet_crypto_async_frame_t *frame, u8 aad_len)
{
  oct_crypto_enqueue_enc_dec (vm, frame, 1 /* is_aead */, aad_len,
			      VNET_CRYPTO_OP_TYPE_DECRYPT);

  return 0;
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

vnet_crypto_async_frame_t *
oct_crypto_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			  u32 *enqueue_thread_idx)
{
  u32 deq_head, status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  vnet_crypto_async_frame_elt_t *fe = NULL;
  oct_crypto_inflight_req_t *infl_req;
  oct_crypto_pending_queue_t *pend_q;
  vnet_crypto_async_frame_t *frame;
  volatile union cpt_res_s *res;
  int i;

  pend_q = &oct_crypto.pend_q[vlib_get_thread_index ()];

  if (!pend_q->n_crypto_inflight)
    return NULL;

  deq_head = pend_q->deq_head;
  infl_req = &pend_q->req_queue[deq_head];
  frame = infl_req->frame;

  fe = frame->elts;

  for (i = infl_req->deq_elts; i < infl_req->elts; ++i)
    {
      res = &infl_req->res[i];

      if (PREDICT_FALSE (res->cn10k.compcode == CPT_COMP_NOT_DONE))
	return NULL;

      if (PREDICT_FALSE (res->cn10k.uc_compcode))
	{
	  if (res->cn10k.uc_compcode == ROC_SE_ERR_GC_ICV_MISCOMPARE)
	    status = fe[i].status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  else
	    status = fe[i].status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	}

      infl_req->deq_elts++;
    }

  clib_memset ((void *) infl_req->res, 0,
	       sizeof (union cpt_res_s) * VNET_CRYPTO_FRAME_SIZE);

  OCT_MOD_INC (pend_q->deq_head, pend_q->n_desc);
  pend_q->n_crypto_inflight--;

  frame->state = status == VNET_CRYPTO_OP_STATUS_COMPLETED ?
			 VNET_CRYPTO_FRAME_STATE_SUCCESS :
			 VNET_CRYPTO_FRAME_STATE_ELT_ERROR;

  *nb_elts_processed = frame->n_elts;
  *enqueue_thread_idx = frame->enqueue_thread_index;

  infl_req->deq_elts = 0;
  infl_req->elts = 0;

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
oct_conf_sw_queue (vlib_main_t *vm, vnet_dev_t *dev)
{
  extern oct_plt_init_param_t oct_plt_init_param;
  vnet_device_main_t *vdm = &vnet_device_main;
  oct_crypto_inflight_req_t *infl_req_queue;
  u8 num_worker_cores;
  int i, j = 0;

  num_worker_cores =
    vdm->last_worker_thread_index - vdm->first_worker_thread_index + 1;

  oct_crypto.pend_q = oct_plt_init_param.oct_plt_zmalloc (
    num_worker_cores * sizeof (oct_crypto_pending_queue_t),
    CLIB_CACHE_LINE_BYTES);
  if (oct_crypto.pend_q == NULL)
    {
      log_err (dev, "Failed to allocate memory for crypto pending queue");
      return -1;
    }

  for (i = 0; i <= num_worker_cores; ++i)
    {
      oct_crypto.pend_q[i].n_desc = OCT_CRYPTO_DEFAULT_SW_ASYNC_FRAME_COUNT;

      oct_crypto.pend_q[i].req_queue = oct_plt_init_param.oct_plt_zmalloc (
	OCT_CRYPTO_DEFAULT_SW_ASYNC_FRAME_COUNT *
	  sizeof (oct_crypto_inflight_req_t),
	CLIB_CACHE_LINE_BYTES);
      if (oct_crypto.pend_q[i].req_queue == NULL)
	{
	  log_err (dev,
		   "Failed to allocate memory for crypto inflight request");
	  goto free;
	}

      for (j = 0; j <= oct_crypto.pend_q[i].n_desc; ++j)
	{
	  infl_req_queue = &oct_crypto.pend_q[i].req_queue[j];

	  infl_req_queue->sg_data = oct_plt_init_param.oct_plt_zmalloc (
	    OCT_SCATTER_GATHER_BUFFER_SIZE * VNET_CRYPTO_FRAME_SIZE,
	    CLIB_CACHE_LINE_BYTES);
	  if (infl_req_queue->sg_data == NULL)
	    {
	      log_err (dev, "Failed to allocate crypto scatter gather memory");
	      goto free;
	    }
	}
    }
  return 0;
free:
  for (; i >= 0; i--)
    {
      if (oct_crypto.pend_q[i].req_queue == NULL)
	continue;
      for (; j >= 0; j--)
	{
	  infl_req_queue = &oct_crypto.pend_q[i].req_queue[j];

	  if (infl_req_queue->sg_data == NULL)
	    continue;

	  oct_plt_init_param.oct_plt_free (infl_req_queue->sg_data);
	}
      oct_plt_init_param.oct_plt_free (oct_crypto.pend_q[i].req_queue);
    }
  oct_plt_init_param.oct_plt_free (oct_crypto.pend_q);

  return -1;
}
