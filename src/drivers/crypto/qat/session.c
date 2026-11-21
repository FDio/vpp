/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <qat.h>

VLIB_REGISTER_LOG_CLASS (qat_log, static) = {
  .class_name = "qat",
  .subclass_name = "session",
};

static u32
qat_tmpl_cipher (qat_fw_cd_ctrl_t *cc, u32 offset, const qat_alg_t *a, u8 is_ucs)
{
  u32 key_sz, size;

  if (is_ucs)
    {
      key_sz = round_pow2 (a->key_len, 16);
      size = sizeof (qat_hw_ucs_cipher_blk_t) + key_sz;
    }
  else
    {
      key_sz = a->key_len;
      size = sizeof (qat_hw_cipher_blk_t) + key_sz;
    }

  cc->cipher_cfg_offset = offset >> 3;
  cc->cipher_key_sz = key_sz >> 3;
  cc->cipher_state_sz = 16 >> 3;
  return round_pow2 (size, 8);
}

static u32
qat_tmpl_auth (qat_fw_cd_ctrl_t *cc, u32 offset, const qat_alg_t *a)
{
  u8 block_size = clib_sha2_variants[a->sha2_type].block_size;
  u8 state_sz = block_size == CLIB_SHA2_512_BLOCK_SIZE ? 8 * sizeof (u64) : 8 * sizeof (u32);

  cc->hash_cfg_offset = offset >> 3;
  cc->inner_state1_sz = state_sz;
  cc->inner_state2_sz = state_sz;
  cc->inner_state2_offset = cc->hash_cfg_offset + ((sizeof (qat_hw_auth_blk_t) + state_sz) >> 3);
  cc->inner_res_sz = a->digest_len;
  cc->final_sz = a->digest_len;
  return sizeof (qat_hw_auth_blk_t) + 2 * state_sz;
}

void
qat_tmpl_build (qat_fw_la_req_t *req, const qat_alg_t *a, u8 is_enc, const qat_gen_config_t *gc)
{
  /* without UCS slice AES-CTR runs on the legacy cipher slice */
  u8 is_ucs = a->is_ucs && gc->has_ucs;
  qat_fw_cd_ctrl_t *cc = &req->cd_ctrl;
  qat_fw_req_hdr_t *hdr = &req->hdr;
  u32 cd_sz = 0;

  *req = (qat_fw_la_req_t){
    .hdr = {
      .service_type = QAT_FW_COMN_REQ_CPM_FW_LA,
      .valid = QAT_FW_HDR_FLAG_VALID,
      .la_flags = {
	.ciph_iv_16byte_data = 1,
	.slice_type = is_ucs ? QAT_FW_LA_SLICE_TYPE_UCS : 0,
      },
    },
  };

  switch (a->type)
    {
    case QAT_ALG_TYPE_AEAD:
      hdr->service_cmd_id = QAT_FW_LA_CMD_CIPHER;
      hdr->la_flags.single_pass = 1;
      hdr->la_flags.gcm_iv_len_12_octets = a->cipher_mode == QAT_HW_CIPHER_AEAD_MODE;
      hdr->la_flags.ret_auth_res = is_enc;
      hdr->la_flags.cmp_auth_res = is_enc == 0;
      cd_sz = qat_tmpl_cipher (cc, 0, a, is_ucs);
      cc->cipher_curr_id = QAT_FW_SLICE_CIPHER;
      cc->cipher_next_id = QAT_FW_SLICE_DRAM_WR;
      req->ucs.spc_aad_sz = a->aad_len;
      req->ucs.spc_auth_res_sz = a->digest_len;
      break;

    case QAT_ALG_TYPE_CIPHER:
      hdr->service_cmd_id = QAT_FW_LA_CMD_CIPHER;
      cd_sz = qat_tmpl_cipher (cc, 0, a, is_ucs);
      cc->cipher_curr_id = QAT_FW_SLICE_CIPHER;
      cc->cipher_next_id = QAT_FW_SLICE_DRAM_WR;
      break;

    case QAT_ALG_TYPE_COMBINED:
      /* encrypt then MAC, verify then decrypt */
      if (is_enc)
	{
	  hdr->service_cmd_id = QAT_FW_LA_CMD_CIPHER_HASH;
	  hdr->la_flags.ret_auth_res = 1;
	  cd_sz = qat_tmpl_cipher (cc, 0, a, is_ucs);
	  cd_sz += qat_tmpl_auth (cc, cd_sz, a);
	  cc->cipher_curr_id = QAT_FW_SLICE_CIPHER;
	  cc->cipher_next_id = QAT_FW_SLICE_AUTH;
	  cc->auth_curr_id = QAT_FW_SLICE_AUTH;
	  cc->auth_next_id = QAT_FW_SLICE_DRAM_WR;
	}
      else
	{
	  hdr->service_cmd_id = QAT_FW_LA_CMD_HASH_CIPHER;
	  hdr->la_flags.cmp_auth_res = 1;
	  cd_sz = qat_tmpl_auth (cc, 0, a);
	  cd_sz += qat_tmpl_cipher (cc, cd_sz, a, is_ucs);
	  cc->auth_curr_id = QAT_FW_SLICE_AUTH;
	  cc->auth_next_id = QAT_FW_SLICE_CIPHER;
	  cc->cipher_curr_id = QAT_FW_SLICE_CIPHER;
	  cc->cipher_next_id = QAT_FW_SLICE_DRAM_WR;
	}
      req->cipher_auth.auth_res_sz = a->digest_len;
      break;

    case QAT_ALG_TYPE_NONE:
      ASSERT (0);
      break;
    }

  ASSERT (cd_sz <= QAT_CD_SIZE);
  req->cd_pars.content_desc_params_sz = round_pow2 (cd_sz, 8) >> 3;
}

static void
qat_cd_cipher (u8 *cd, const qat_fw_la_req_t *req, const qat_alg_t *a, const u8 *key, u8 is_enc)
{
  u8 *p = cd + (req->cd_ctrl.cipher_cfg_offset << 3);
  qat_hw_cipher_config_t cfg = {
    .algo = a->cipher_algo,
    .mode = a->cipher_mode,
  };

  /* single pass ChaCha20-Poly1305 must know whether to verify the tag */
  if (a->cipher_mode != QAT_HW_CIPHER_CTR_MODE ||
      a->cipher_algo == QAT_HW_CIPHER_ALGO_CHACHA20_POLY1305)
    cfg.decrypt = is_enc == 0;

  /* the CBC decrypt key schedule is derived by the hardware */
  if (a->cipher_mode == QAT_HW_CIPHER_CBC_MODE)
    cfg.key_convert = is_enc == 0;

  if (a->type == QAT_ALG_TYPE_AEAD)
    cfg.aead_hash_cmp_len = a->digest_len;

  if (req->hdr.la_flags.slice_type == QAT_FW_LA_SLICE_TYPE_UCS)
    {
      qat_hw_ucs_cipher_blk_t *b = (qat_hw_ucs_cipher_blk_t *) p;
      *b = (qat_hw_ucs_cipher_blk_t){
	.config = cfg,
	.config_upper = {
	  .aad_size_lower = a->aad_len,
	},
      };
      clib_memcpy (b->key, key, a->key_len);
    }
  else
    {
      qat_hw_cipher_blk_t *b = (qat_hw_cipher_blk_t *) p;
      *b = (qat_hw_cipher_blk_t) {
	.config = cfg,
      };
      clib_memcpy (b->key, key, a->key_len);
    }
}

static void
qat_cd_auth (u8 *cd, const qat_fw_la_req_t *req, const qat_alg_t *a, vnet_crypto_ctx_t *ctx)
{
  const qat_fw_cd_ctrl_t *cc = &req->cd_ctrl;
  qat_hw_auth_blk_t *b = (qat_hw_auth_blk_t *) (cd + (cc->hash_cfg_offset << 3));
  u8 *ipad = b->state, *opad = cd + (cc->inner_state2_offset << 3);
  u8 block_size = clib_sha2_variants[a->sha2_type].block_size;
  clib_sha2_hmac_key_data_t kd;

  *b = (qat_hw_auth_blk_t){
    .config = {
      .algo = a->auth_algo,
      .mode = QAT_HW_AUTH_MODE1,
      .cmp_len = a->digest_len,
    },
    .counter_be = clib_host_to_net_u32 (block_size),
  };

  /* mode 1 HMAC takes the inner and outer hash state after the first block */
  clib_sha2_hmac_key_data (a->sha2_type, vnet_crypto_get_auth_key (ctx), ctx->auth_key_sz, &kd);

  for (u32 i = 0; i < 8; i++)
    if (block_size == CLIB_SHA2_512_BLOCK_SIZE)
      {
	((u64u *) ipad)[i] = clib_host_to_net_u64 (kd.ipad_h.h64[i]);
	((u64u *) opad)[i] = clib_host_to_net_u64 (kd.opad_h.h64[i]);
      }
    else
      {
	((u32u *) ipad)[i] = clib_host_to_net_u32 (kd.ipad_h.h32[i]);
	((u32u *) opad)[i] = clib_host_to_net_u32 (kd.opad_h.h32[i]);
      }

  clib_memset (&kd, 0, sizeof (kd));
}

/* writes the keys at the offsets the template has */
static void
qat_cd_build (u8 *cd, const qat_fw_la_req_t *req, const qat_alg_t *a, vnet_crypto_ctx_t *ctx,
	      u8 is_enc)
{
  clib_memset (cd, 0, QAT_CD_SIZE);
  qat_cd_cipher (cd, req, a, vnet_crypto_get_cipher_key (ctx), is_enc);
  if (a->type == QAT_ALG_TYPE_COMBINED)
    qat_cd_auth (cd, req, a, ctx);
}

static vnet_dev_t *
qat_session_dev (vnet_crypto_engine_id_t engine)
{
  vnet_dev_crypto_engine_t *e = vnet_dev_crypto_get_engine (engine);

  if (e == 0)
    return 0;

  for (u32 ti = 0; ti < vlib_get_n_threads (); ti++)
    vec_foreach_pointer (cq, vnet_dev_crypto_get_thread_queues (e, ti))
      return cq->dev;

  return 0;
}

static void
qat_session_cd_free (vlib_main_t *vm, void *p)
{
  vnet_dev_dma_slab_free (vm, 0, p);
}

static void
qat_session_release (vlib_main_t *vm, vnet_crypto_engine_id_t engine, qat_key_t *k)
{
  qat_session_cd_t *cd = k->cd;

  if (cd == 0)
    return;

  /* the device may still read the content descriptors of requests in flight */
  __atomic_store_n (&k->cd, 0, __ATOMIC_RELEASE);
  vnet_dev_crypto_defer_free (vm, engine, cd, qat_session_cd_free);
  log_debug (0, "session %p released", cd);
}

void
qat_key_change (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_crypto_engine_id_t engine = vnet_crypto_ctx_get_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_ASYNC);
  qat_key_t *k = (qat_key_t *) args->key_data;
  const qat_alg_t *a = qat_algs + ctx->alg;
  const qat_alg_tmpl_t *tmpl;
  qat_session_cd_t *cd;
  qat_driver_t *qdrv;
  qat_device_t *qd;
  vnet_dev_t *dev;

  ASSERT (args->handler_type == VNET_CRYPTO_HANDLER_TYPE_ASYNC);

  qat_session_release (vm, engine, k);

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;

  if (a->type == QAT_ALG_TYPE_NONE)
    return;

  dev = qat_session_dev (engine);
  if (dev == 0)
    return;

  qd = vnet_dev_get_data (dev);
  qdrv = vnet_dev_get_driver_data (pool_elt_at_index (vnet_dev_main.drivers, dev->driver_index));
  tmpl = qdrv->templates[qd->gen] + ctx->alg;

  /* algorithm not supported by this generation */
  if (tmpl->req[VNET_CRYPTO_OP_TYPE_ENCRYPT].hdr.valid == 0)
    return;

  if ((cd = vnet_dev_dma_slab_alloc (vm, dev, sizeof (qat_session_cd_t), 0)) == 0)
    {
      log_err (dev, "session memory allocation failed");
      return;
    }

  qat_cd_build (cd->cd[VNET_CRYPTO_OP_TYPE_ENCRYPT], tmpl->req + VNET_CRYPTO_OP_TYPE_ENCRYPT, a,
		ctx, 1);
  qat_cd_build (cd->cd[VNET_CRYPTO_OP_TYPE_DECRYPT], tmpl->req + VNET_CRYPTO_OP_TYPE_DECRYPT, a,
		ctx, 0);

  k->tmpl = tmpl;
  k->cd_dma = vnet_dev_dma_slab_get_dma_addr (vm, dev, cd);
  __atomic_store_n (&k->cd, cd, __ATOMIC_RELEASE);
  log_debug (dev, "ctx %u alg %U session %p dma 0x%lx", ctx->index, format_vnet_crypto_alg,
	     ctx->alg, cd, k->cd_dma);
}
