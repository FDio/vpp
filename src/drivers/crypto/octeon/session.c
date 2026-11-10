/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/dev/dev.h>
#include <octeon_common.h>
#include <crypto.h>

static u64
oct_cpt_inst_w7_get (struct roc_se_ctx *cpt_ctx, oct_crypto_device_t *cd)
{
  union cpt_inst_w7 inst_w7;

  inst_w7.u64 = 0;

  /* the context processor reads the context header in front of the context */
  if (cd->hw_ctx_cache)
    {
      inst_w7.s.cptr = pointer_to_uword (&cpt_ctx->se_ctx);
      inst_w7.s.ctx_val = 1;
    }
  else
    inst_w7.s.cptr = pointer_to_uword (&cpt_ctx->se_ctx.fctx);

  /* Set the engine group */
  inst_w7.s.egrp = cd->roc_cpt->eng_grp[CPT_ENG_TYPE_IE];

  return inst_w7.u64;
}

static i32
oct_crypto_combined_session_update (vlib_main_t *vm, oct_crypto_key_t *ckey,
				    struct roc_se_ctx *cpt_ctx, vnet_crypto_ctx_t *ctx, u8 type)
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
    cpt_ctx->ciph_then_auth = true;
  else
    cpt_ctx->auth_then_ciph = true;

  ckey->iv_length = 16;

  if (ctx->cipher_key_sz + ctx->auth_key_sz < crypto_key_len)
    return -1;

  auth_key_len = ctx->auth_key_sz;
  if (auth_key_len == 0)
    return -1;

  crypto_key_data = vnet_crypto_get_cipher_key (ctx);
  auth_key_data = vnet_crypto_get_auth_key (ctx);

  rv = roc_se_ciph_key_set (cpt_ctx, alg->cipher_type, crypto_key_data, crypto_key_len);
  if (rv == 0)
    rv = roc_se_auth_key_set (cpt_ctx, alg->auth_type, auth_key_data, auth_key_len, digest_len);

  if (rv)
    {
      ASSERT (0);
      return -1;
    }

  cpt_ctx->template_w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

  if (type == VNET_CRYPTO_OP_TYPE_DECRYPT)
    cpt_ctx->template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;
  else
    cpt_ctx->template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;

  return 0;
}

static i32
oct_crypto_aead_session_update (vlib_main_t *vm, oct_crypto_key_t *ckey, struct roc_se_ctx *cpt_ctx,
				vnet_crypto_ctx_t *ctx, vnet_crypto_alg_t alg_id, u8 type)
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

  ckey->iv_length = alg->iv_length;
  cpt_ctx->mac_len = digest_len;

  rv = roc_se_ciph_key_set (cpt_ctx, alg->cipher_type, vnet_crypto_get_cipher_key (ctx),
			    ctx->cipher_key_sz);
  if (rv)
    {
      ASSERT (0);
      return -1;
    }

  rv = roc_se_auth_key_set (cpt_ctx, alg->auth_type, 0, 0, digest_len);
  if (rv)
    {
      ASSERT (0);
      return -1;
    }

  cpt_ctx->template_w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

  if (type == VNET_CRYPTO_OP_TYPE_DECRYPT)
    cpt_ctx->template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;
  else
    cpt_ctx->template_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;

  cpt_ctx->template_w4.s.opcode_minor |= alg->opcode_minor_flags;

  return 0;
}

static i32
oct_crypto_session_setup (vlib_main_t *vm, oct_crypto_key_t *ckey, struct roc_se_ctx *cpt_ctx,
			  vnet_crypto_ctx_t *ctx, oct_crypto_device_t *cd, u8 type, u64 *inst_w4,
			  u64 *inst_w7)
{
  union cpt_inst_w4 w4;
  vnet_crypto_main_t *cm = &crypto_main;
  i32 rv;

  if (cm->algs[ctx->alg].alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    rv = oct_crypto_combined_session_update (vm, ckey, cpt_ctx, ctx, type);
  else
    rv = oct_crypto_aead_session_update (vm, ckey, cpt_ctx, ctx, ctx->alg, type);

  if (rv)
    return -1;

  *inst_w7 = oct_cpt_inst_w7_get (cpt_ctx, cd);

  if (cd->hw_ctx_cache)
    {
      roc_se_ctx_init (cpt_ctx);
      /* the initial context fetch of the LF must not be larger than the context */
      if (cpt_ctx->se_ctx.w0.s.ctx_size < cd->roc_cpt->ctx_ilen)
	cpt_ctx->se_ctx.w0.s.ctx_size = cd->roc_cpt->ctx_ilen;
    }

  w4 = cpt_ctx->template_w4;
  w4.s.opcode_major |= ROC_DMA_MODE_SG;
  *inst_w4 = w4.u64;
  ckey->mac_len = cpt_ctx->mac_len;
  ckey->cbc_pad = cpt_ctx->enc_cipher == ROC_SE_AES_CBC || cpt_ctx->enc_cipher == ROC_SE_DES3_CBC;

  return 0;
}

i32
oct_crypto_session_init (vlib_main_t *vm, oct_crypto_key_t *ckey, vnet_crypto_ctx_t *ctx,
			 oct_crypto_device_t *cd)
{
  if (oct_crypto_session_setup (vm, ckey, ckey->enc_ctx, ctx, cd, VNET_CRYPTO_OP_TYPE_ENCRYPT,
				&ckey->enc_inst_w4, &ckey->enc_inst_w7))
    return -1;

  return oct_crypto_session_setup (vm, ckey, ckey->dec_ctx, ctx, cd, VNET_CRYPTO_OP_TYPE_DECRYPT,
				   &ckey->dec_inst_w4, &ckey->dec_inst_w7);
}
