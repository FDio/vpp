/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/ipsec/ipsec.h>

ipsec_main_t ipsec_main = {
  .crypto_algs = {
    [IPSEC_CRYPTO_ALG_NONE] = {
      .enc_op_id = VNET_CRYPTO_OP_NONE,
      .dec_op_id = VNET_CRYPTO_OP_NONE,
      .alg = VNET_CRYPTO_ALG_NONE,
      .iv_size = 0,
      .block_align = 1,
    },

    [IPSEC_CRYPTO_ALG_DES_CBC] = {
      .enc_op_id = VNET_CRYPTO_OP_DES_CBC_ENC,
      .dec_op_id = VNET_CRYPTO_OP_DES_CBC_DEC,
      .alg = VNET_CRYPTO_ALG_DES_CBC,
      .iv_size = 8,
      .block_align = 8,
    },

    [IPSEC_CRYPTO_ALG_3DES_CBC] = {
      .enc_op_id = VNET_CRYPTO_OP_3DES_CBC_ENC,
      .dec_op_id = VNET_CRYPTO_OP_3DES_CBC_DEC,
      .alg = VNET_CRYPTO_ALG_3DES_CBC,
      .iv_size = 8,
      .block_align = 8,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CBC_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CBC_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CBC,
      .iv_size = 16,
      .block_align = 16,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CBC_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CBC_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CBC,
      .iv_size = 16,
      .block_align = 16,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CBC_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CBC_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CBC,
      .iv_size = 16,
      .block_align = 16,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CTR_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CTR_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CTR,
      .iv_size = 8,
      .block_align = 1,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CTR_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CTR_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CTR,
      .iv_size = 8,
      .block_align = 1,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CTR_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CTR_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CTR,
      .iv_size = 8,
      .block_align = 1,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_GCM_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_GCM_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_GCM_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_GCM,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_aead = 1,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_GCM_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_GCM_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_GCM_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_GCM,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_aead = 1,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_GCM_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_GCM_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_GCM_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_GCM,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_aead = 1,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_CHACHA20_POLY1305] = {
      .enc_op_id = VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC,
      .dec_op_id = VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC,
      .alg = VNET_CRYPTO_ALG_CHACHA20_POLY1305,
      .iv_size = 8,
      .icv_size = 16,
      .is_ctr = 1,
      .is_aead = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_NULL_GMAC_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_NULL_GMAC_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_NULL_GMAC_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_GCM,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_ctr = 1,
      .is_aead = 1,
      .is_null_gmac = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_NULL_GMAC_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_NULL_GMAC_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_NULL_GMAC_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_GCM,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_ctr = 1,
      .is_aead = 1,
      .is_null_gmac = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_NULL_GMAC_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_NULL_GMAC_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_NULL_GMAC_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_GCM,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_ctr = 1,
      .is_aead = 1,
      .is_null_gmac = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_128_MD5] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CBC_MD5_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CBC_MD5_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CBC_MD5_TAG12,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 12,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_192_MD5] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CBC_MD5_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CBC_MD5_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CBC_MD5_TAG12,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 12,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_256_MD5] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CBC_MD5_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CBC_MD5_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CBC_MD5_TAG12,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 12,
    },

    [IPSEC_CRYPTO_ALG_3DES_CBC_MD5] = {
      .enc_op_id = VNET_CRYPTO_OP_3DES_CBC_MD5_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_3DES_CBC_MD5_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_3DES_CBC_MD5_TAG12,
      .iv_size = 8,
      .block_align = 8,
      .icv_size = 12,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_128_SHA1_96] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CBC_SHA1_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CBC_SHA1_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA1_TAG12,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 12,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_192_SHA1_96] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CBC_SHA1_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CBC_SHA1_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA1_TAG12,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 12,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_256_SHA1_96] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CBC_SHA1_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CBC_SHA1_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA1_TAG12,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 12,
    },

    [IPSEC_CRYPTO_ALG_3DES_CBC_SHA1_96] = {
      .enc_op_id = VNET_CRYPTO_OP_3DES_CBC_SHA1_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_3DES_CBC_SHA1_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA1_TAG12,
      .iv_size = 8,
      .block_align = 8,
      .icv_size = 12,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_128_SHA1_96] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CTR_SHA1_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CTR_SHA1_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA1_TAG12,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 12,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_192_SHA1_96] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CTR_SHA1_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CTR_SHA1_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA1_TAG12,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 12,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_256_SHA1_96] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CTR_SHA1_TAG12_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CTR_SHA1_TAG12_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA1_TAG12,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 12,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_128_SHA_256_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CBC_SHA256_TAG16_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CBC_SHA256_TAG16_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA256_TAG16,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 16,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_192_SHA_256_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CBC_SHA256_TAG16_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CBC_SHA256_TAG16_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA256_TAG16,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 16,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_256_SHA_256_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CBC_SHA256_TAG16_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CBC_SHA256_TAG16_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA256_TAG16,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 16,
    },

    [IPSEC_CRYPTO_ALG_3DES_CBC_SHA_256_128] = {
      .enc_op_id = VNET_CRYPTO_OP_3DES_CBC_SHA256_TAG16_ENC,
      .dec_op_id = VNET_CRYPTO_OP_3DES_CBC_SHA256_TAG16_DEC,
      .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA256_TAG16,
      .iv_size = 8,
      .block_align = 8,
      .icv_size = 16,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_128_SHA_256_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CTR_SHA256_TAG16_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CTR_SHA256_TAG16_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA256_TAG16,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_192_SHA_256_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CTR_SHA256_TAG16_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CTR_SHA256_TAG16_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA256_TAG16,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_256_SHA_256_128] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CTR_SHA256_TAG16_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CTR_SHA256_TAG16_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA256_TAG16,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 16,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_128_SHA_384_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CBC_SHA384_TAG24_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CBC_SHA384_TAG24_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA384_TAG24,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 24,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_192_SHA_384_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CBC_SHA384_TAG24_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CBC_SHA384_TAG24_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA384_TAG24,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 24,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_256_SHA_384_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CBC_SHA384_TAG24_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CBC_SHA384_TAG24_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA384_TAG24,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 24,
    },

    [IPSEC_CRYPTO_ALG_3DES_CBC_SHA_384_192] = {
      .enc_op_id = VNET_CRYPTO_OP_3DES_CBC_SHA384_TAG24_ENC,
      .dec_op_id = VNET_CRYPTO_OP_3DES_CBC_SHA384_TAG24_DEC,
      .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA384_TAG24,
      .iv_size = 8,
      .block_align = 8,
      .icv_size = 24,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_128_SHA_384_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CTR_SHA384_TAG24_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CTR_SHA384_TAG24_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA384_TAG24,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 24,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_192_SHA_384_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CTR_SHA384_TAG24_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CTR_SHA384_TAG24_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA384_TAG24,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 24,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_256_SHA_384_192] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CTR_SHA384_TAG24_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CTR_SHA384_TAG24_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA384_TAG24,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 24,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_128_SHA_512_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CBC_SHA512_TAG32_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CBC_SHA512_TAG32_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CBC_SHA512_TAG32,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 32,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_192_SHA_512_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CBC_SHA512_TAG32_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CBC_SHA512_TAG32_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CBC_SHA512_TAG32,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 32,
    },

    [IPSEC_CRYPTO_ALG_AES_CBC_256_SHA_512_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CBC_SHA512_TAG32_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CBC_SHA512_TAG32_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CBC_SHA512_TAG32,
      .iv_size = 16,
      .block_align = 16,
      .icv_size = 32,
    },

    [IPSEC_CRYPTO_ALG_3DES_CBC_SHA_512_256] = {
      .enc_op_id = VNET_CRYPTO_OP_3DES_CBC_SHA512_TAG32_ENC,
      .dec_op_id = VNET_CRYPTO_OP_3DES_CBC_SHA512_TAG32_DEC,
      .alg = VNET_CRYPTO_ALG_3DES_CBC_SHA512_TAG32,
      .iv_size = 8,
      .block_align = 8,
      .icv_size = 32,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_128_SHA_512_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_128_CTR_SHA512_TAG32_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_128_CTR_SHA512_TAG32_DEC,
      .alg = VNET_CRYPTO_ALG_AES_128_CTR_SHA512_TAG32,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 32,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_192_SHA_512_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_192_CTR_SHA512_TAG32_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_192_CTR_SHA512_TAG32_DEC,
      .alg = VNET_CRYPTO_ALG_AES_192_CTR_SHA512_TAG32,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 32,
      .is_ctr = 1,
    },

    [IPSEC_CRYPTO_ALG_AES_CTR_256_SHA_512_256] = {
      .enc_op_id = VNET_CRYPTO_OP_AES_256_CTR_SHA512_TAG32_ENC,
      .dec_op_id = VNET_CRYPTO_OP_AES_256_CTR_SHA512_TAG32_DEC,
      .alg = VNET_CRYPTO_ALG_AES_256_CTR_SHA512_TAG32,
      .iv_size = 8,
      .block_align = 1,
      .icv_size = 32,
      .is_ctr = 1,
    },
  },
  .integ_algs = {
    [IPSEC_INTEG_ALG_MD5_96] = {
      .op_id = VNET_CRYPTO_OP_MD5_HMAC,
      .alg = VNET_CRYPTO_ALG_HMAC_MD5,
      .icv_size = 12,
    },

    [IPSEC_INTEG_ALG_SHA1_96] = {
      .op_id = VNET_CRYPTO_OP_SHA1_HMAC,
      .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
      .icv_size = 12,
    },

    [IPSEC_INTEG_ALG_SHA_256_96] = {
      .op_id = VNET_CRYPTO_OP_SHA1_HMAC,
      .alg = VNET_CRYPTO_ALG_HMAC_SHA256,
      .icv_size = 12,
    },

    [IPSEC_INTEG_ALG_SHA_256_128] = {
      .op_id = VNET_CRYPTO_OP_SHA256_HMAC,
      .alg = VNET_CRYPTO_ALG_HMAC_SHA256,
      .icv_size = 16,
    },

    [IPSEC_INTEG_ALG_SHA_384_192] = {
      .op_id = VNET_CRYPTO_OP_SHA384_HMAC,
      .alg = VNET_CRYPTO_ALG_HMAC_SHA384,
      .icv_size = 24,
    },

    [IPSEC_INTEG_ALG_SHA_512_256] = {
      .op_id = VNET_CRYPTO_OP_SHA512_HMAC,
      .alg = VNET_CRYPTO_ALG_HMAC_SHA512,
      .icv_size = 32,
    },
  },
};
