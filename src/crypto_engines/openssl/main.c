/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024-2026 Cisco Systems, Inc.
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>

typedef struct
{
  EVP_CIPHER_CTX *evp_cipher_enc_ctx;
  EVP_CIPHER_CTX *evp_cipher_dec_ctx;
} openssl_cipher_key_data_t;

typedef struct
{
  EVP_CIPHER_CTX *evp_cipher_enc_ctx;
  EVP_CIPHER_CTX *evp_cipher_dec_ctx;
  HMAC_CTX *hmac_ctx;
} openssl_combined_key_data_t;

typedef struct
{
  HMAC_CTX *hmac_ctx;
} openssl_hmac_key_data_t;

#define foreach_openssl_aes_evp_op                                                                 \
  _ (cbc, DES_CBC, EVP_des_cbc, 0, 0)                                                              \
  _ (cbc, 3DES_CBC, EVP_des_ede3_cbc, 0, 0)                                                        \
  _ (cbc, AES_128_CBC, EVP_aes_128_cbc, 0, 0)                                                      \
  _ (cbc, AES_192_CBC, EVP_aes_192_cbc, 0, 0)                                                      \
  _ (cbc, AES_256_CBC, EVP_aes_256_cbc, 0, 0)                                                      \
  _ (cbc, AES_128_CTR, EVP_aes_128_ctr, 0, 0)                                                      \
  _ (cbc, AES_192_CTR, EVP_aes_192_ctr, 0, 0)                                                      \
  _ (cbc, AES_256_CTR, EVP_aes_256_ctr, 0, 0)

#define foreach_openssl_aes_gcm_evp_op                                                             \
  _ (gcm, AES_128_GCM, EVP_aes_128_gcm, 0, 0)                                                      \
  _ (gcm, AES_128_GCM_ICV16_AAD8, EVP_aes_128_gcm, 1, 8)                                           \
  _ (gcm, AES_128_GCM_ICV16_AAD12, EVP_aes_128_gcm, 1, 12)                                         \
  _ (gcm, AES_192_GCM, EVP_aes_192_gcm, 0, 0)                                                      \
  _ (gcm, AES_192_GCM_ICV16_AAD8, EVP_aes_192_gcm, 1, 8)                                           \
  _ (gcm, AES_192_GCM_ICV16_AAD12, EVP_aes_192_gcm, 1, 12)                                         \
  _ (gcm, AES_256_GCM, EVP_aes_256_gcm, 0, 0)                                                      \
  _ (gcm, AES_256_GCM_ICV16_AAD8, EVP_aes_256_gcm, 1, 8)                                           \
  _ (gcm, AES_256_GCM_ICV16_AAD12, EVP_aes_256_gcm, 1, 12)                                         \
  _ (null_gmac, AES_128_NULL_GMAC, EVP_aes_128_gcm, 0, 0)                                          \
  _ (null_gmac, AES_128_NULL_GMAC_ICV16_AAD8, EVP_aes_128_gcm, 1, 8)                               \
  _ (null_gmac, AES_128_NULL_GMAC_ICV16_AAD12, EVP_aes_128_gcm, 1, 12)                             \
  _ (null_gmac, AES_192_NULL_GMAC, EVP_aes_192_gcm, 0, 0)                                          \
  _ (null_gmac, AES_192_NULL_GMAC_ICV16_AAD8, EVP_aes_192_gcm, 1, 8)                               \
  _ (null_gmac, AES_192_NULL_GMAC_ICV16_AAD12, EVP_aes_192_gcm, 1, 12)                             \
  _ (null_gmac, AES_256_NULL_GMAC, EVP_aes_256_gcm, 0, 0)                                          \
  _ (null_gmac, AES_256_NULL_GMAC_ICV16_AAD8, EVP_aes_256_gcm, 1, 8)                               \
  _ (null_gmac, AES_256_NULL_GMAC_ICV16_AAD12, EVP_aes_256_gcm, 1, 12)

#define foreach_openssl_combined_evp_op                                                            \
  _ (3DES_CBC_MD5, EVP_des_ede3_cbc, EVP_md5, 24, 0)                                               \
  _ (AES_128_CBC_MD5, EVP_aes_128_cbc, EVP_md5, 16, 0)                                             \
  _ (AES_192_CBC_MD5, EVP_aes_192_cbc, EVP_md5, 24, 0)                                             \
  _ (AES_256_CBC_MD5, EVP_aes_256_cbc, EVP_md5, 32, 0)                                             \
  _ (3DES_CBC_SHA1_160, EVP_des_ede3_cbc, EVP_sha1, 24, 0)                                         \
  _ (AES_128_CBC_SHA1_160, EVP_aes_128_cbc, EVP_sha1, 16, 0)                                       \
  _ (AES_192_CBC_SHA1_160, EVP_aes_192_cbc, EVP_sha1, 24, 0)                                       \
  _ (AES_256_CBC_SHA1_160, EVP_aes_256_cbc, EVP_sha1, 32, 0)                                       \
  _ (3DES_CBC_SHA_224, EVP_des_ede3_cbc, EVP_sha224, 24, 0)                                        \
  _ (AES_128_CBC_SHA_224, EVP_aes_128_cbc, EVP_sha224, 16, 0)                                      \
  _ (AES_192_CBC_SHA_224, EVP_aes_192_cbc, EVP_sha224, 24, 0)                                      \
  _ (AES_256_CBC_SHA_224, EVP_aes_256_cbc, EVP_sha224, 32, 0)                                      \
  _ (3DES_CBC_SHA_256, EVP_des_ede3_cbc, EVP_sha256, 24, 0)                                        \
  _ (AES_128_CBC_SHA_256, EVP_aes_128_cbc, EVP_sha256, 16, 0)                                      \
  _ (AES_192_CBC_SHA_256, EVP_aes_192_cbc, EVP_sha256, 24, 0)                                      \
  _ (AES_256_CBC_SHA_256, EVP_aes_256_cbc, EVP_sha256, 32, 0)                                      \
  _ (3DES_CBC_SHA_384, EVP_des_ede3_cbc, EVP_sha384, 24, 0)                                        \
  _ (AES_128_CBC_SHA_384, EVP_aes_128_cbc, EVP_sha384, 16, 0)                                      \
  _ (AES_192_CBC_SHA_384, EVP_aes_192_cbc, EVP_sha384, 24, 0)                                      \
  _ (AES_256_CBC_SHA_384, EVP_aes_256_cbc, EVP_sha384, 32, 0)                                      \
  _ (3DES_CBC_SHA_512, EVP_des_ede3_cbc, EVP_sha512, 24, 0)                                        \
  _ (AES_128_CBC_SHA_512, EVP_aes_128_cbc, EVP_sha512, 16, 0)                                      \
  _ (AES_192_CBC_SHA_512, EVP_aes_192_cbc, EVP_sha512, 24, 0)                                      \
  _ (AES_256_CBC_SHA_512, EVP_aes_256_cbc, EVP_sha512, 32, 0)                                      \
  _ (AES_128_CTR_SHA1_160, EVP_aes_128_ctr, EVP_sha1, 16, 0)                                       \
  _ (AES_192_CTR_SHA1_160, EVP_aes_192_ctr, EVP_sha1, 24, 0)                                       \
  _ (AES_256_CTR_SHA1_160, EVP_aes_256_ctr, EVP_sha1, 32, 0)                                       \
  _ (AES_128_CTR_SHA_256, EVP_aes_128_ctr, EVP_sha256, 16, 0)                                      \
  _ (AES_192_CTR_SHA_256, EVP_aes_192_ctr, EVP_sha256, 24, 0)                                      \
  _ (AES_256_CTR_SHA_256, EVP_aes_256_ctr, EVP_sha256, 32, 0)                                      \
  _ (AES_128_CTR_SHA_384, EVP_aes_128_ctr, EVP_sha384, 16, 0)                                      \
  _ (AES_192_CTR_SHA_384, EVP_aes_192_ctr, EVP_sha384, 24, 0)                                      \
  _ (AES_256_CTR_SHA_384, EVP_aes_256_ctr, EVP_sha384, 32, 0)                                      \
  _ (AES_128_CTR_SHA_512, EVP_aes_128_ctr, EVP_sha512, 16, 0)                                      \
  _ (AES_192_CTR_SHA_512, EVP_aes_192_ctr, EVP_sha512, 24, 0)                                      \
  _ (AES_256_CTR_SHA_512, EVP_aes_256_ctr, EVP_sha512, 32, 0)                                      \
  _ (3DES_CBC_SHA1_160_ICV12, EVP_des_ede3_cbc, EVP_sha1, 24, 12)                                  \
  _ (3DES_CBC_SHA_224_ICV14, EVP_des_ede3_cbc, EVP_sha224, 24, 14)                                 \
  _ (3DES_CBC_SHA_256_ICV12, EVP_des_ede3_cbc, EVP_sha256, 24, 12)                                 \
  _ (3DES_CBC_SHA_256_ICV16, EVP_des_ede3_cbc, EVP_sha256, 24, 16)                                 \
  _ (3DES_CBC_SHA_384_ICV24, EVP_des_ede3_cbc, EVP_sha384, 24, 24)                                 \
  _ (3DES_CBC_SHA_512_ICV32, EVP_des_ede3_cbc, EVP_sha512, 24, 32)                                 \
  _ (AES_128_CBC_SHA1_160_ICV12, EVP_aes_128_cbc, EVP_sha1, 16, 12)                                \
  _ (AES_192_CBC_SHA1_160_ICV12, EVP_aes_192_cbc, EVP_sha1, 24, 12)                                \
  _ (AES_256_CBC_SHA1_160_ICV12, EVP_aes_256_cbc, EVP_sha1, 32, 12)                                \
  _ (AES_128_CBC_SHA_224_ICV14, EVP_aes_128_cbc, EVP_sha224, 16, 14)                               \
  _ (AES_192_CBC_SHA_224_ICV14, EVP_aes_192_cbc, EVP_sha224, 24, 14)                               \
  _ (AES_256_CBC_SHA_224_ICV14, EVP_aes_256_cbc, EVP_sha224, 32, 14)                               \
  _ (AES_128_CBC_SHA_256_ICV12, EVP_aes_128_cbc, EVP_sha256, 16, 12)                               \
  _ (AES_192_CBC_SHA_256_ICV12, EVP_aes_192_cbc, EVP_sha256, 24, 12)                               \
  _ (AES_256_CBC_SHA_256_ICV12, EVP_aes_256_cbc, EVP_sha256, 32, 12)                               \
  _ (AES_128_CBC_SHA_256_ICV16, EVP_aes_128_cbc, EVP_sha256, 16, 16)                               \
  _ (AES_192_CBC_SHA_256_ICV16, EVP_aes_192_cbc, EVP_sha256, 24, 16)                               \
  _ (AES_256_CBC_SHA_256_ICV16, EVP_aes_256_cbc, EVP_sha256, 32, 16)                               \
  _ (AES_128_CBC_SHA_384_ICV24, EVP_aes_128_cbc, EVP_sha384, 16, 24)                               \
  _ (AES_192_CBC_SHA_384_ICV24, EVP_aes_192_cbc, EVP_sha384, 24, 24)                               \
  _ (AES_256_CBC_SHA_384_ICV24, EVP_aes_256_cbc, EVP_sha384, 32, 24)                               \
  _ (AES_128_CBC_SHA_512_ICV32, EVP_aes_128_cbc, EVP_sha512, 16, 32)                               \
  _ (AES_192_CBC_SHA_512_ICV32, EVP_aes_192_cbc, EVP_sha512, 24, 32)                               \
  _ (AES_256_CBC_SHA_512_ICV32, EVP_aes_256_cbc, EVP_sha512, 32, 32)                               \
  _ (AES_128_CBC_MD5_ICV12, EVP_aes_128_cbc, EVP_md5, 16, 12)                                      \
  _ (AES_192_CBC_MD5_ICV12, EVP_aes_192_cbc, EVP_md5, 24, 12)                                      \
  _ (AES_256_CBC_MD5_ICV12, EVP_aes_256_cbc, EVP_md5, 32, 12)                                      \
  _ (AES_128_CTR_SHA1_160_ICV12, EVP_aes_128_ctr, EVP_sha1, 16, 12)                                \
  _ (AES_192_CTR_SHA1_160_ICV12, EVP_aes_192_ctr, EVP_sha1, 24, 12)                                \
  _ (AES_256_CTR_SHA1_160_ICV12, EVP_aes_256_ctr, EVP_sha1, 32, 12)                                \
  _ (AES_128_CTR_SHA_256_ICV12, EVP_aes_128_ctr, EVP_sha256, 16, 12)                               \
  _ (AES_192_CTR_SHA_256_ICV12, EVP_aes_192_ctr, EVP_sha256, 24, 12)                               \
  _ (AES_256_CTR_SHA_256_ICV12, EVP_aes_256_ctr, EVP_sha256, 32, 12)                               \
  _ (AES_128_CTR_SHA_256_ICV16, EVP_aes_128_ctr, EVP_sha256, 16, 16)                               \
  _ (AES_192_CTR_SHA_256_ICV16, EVP_aes_192_ctr, EVP_sha256, 24, 16)                               \
  _ (AES_256_CTR_SHA_256_ICV16, EVP_aes_256_ctr, EVP_sha256, 32, 16)                               \
  _ (AES_128_CTR_SHA_384_ICV24, EVP_aes_128_ctr, EVP_sha384, 16, 24)                               \
  _ (AES_192_CTR_SHA_384_ICV24, EVP_aes_192_ctr, EVP_sha384, 24, 24)                               \
  _ (AES_256_CTR_SHA_384_ICV24, EVP_aes_256_ctr, EVP_sha384, 32, 24)                               \
  _ (AES_128_CTR_SHA_512_ICV32, EVP_aes_128_ctr, EVP_sha512, 16, 32)                               \
  _ (AES_192_CTR_SHA_512_ICV32, EVP_aes_192_ctr, EVP_sha512, 24, 32)                               \
  _ (AES_256_CTR_SHA_512_ICV32, EVP_aes_256_ctr, EVP_sha512, 32, 32)

#define foreach_openssl_chacha20_evp_op                                                            \
  _ (chacha20_poly1305, CHACHA20_POLY1305, EVP_chacha20_poly1305, 0, 0)                            \
  _ (chacha20_poly1305, CHACHA20_POLY1305_ICV16_AAD0, EVP_chacha20_poly1305, 1, 0)                 \
  _ (chacha20_poly1305, CHACHA20_POLY1305_ICV16_AAD8, EVP_chacha20_poly1305, 1, 8)                 \
  _ (chacha20_poly1305, CHACHA20_POLY1305_ICV16_AAD12, EVP_chacha20_poly1305, 1, 12)

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define foreach_openssl_evp_op                                                                     \
  foreach_openssl_aes_evp_op foreach_openssl_aes_gcm_evp_op foreach_openssl_chacha20_evp_op
#else
#define foreach_openssl_evp_op foreach_openssl_aes_evp_op foreach_openssl_aes_gcm_evp_op
#endif

#ifndef EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_AEAD_GET_TAG EVP_CTRL_GCM_GET_TAG
#endif

#ifndef EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_AEAD_SET_TAG EVP_CTRL_GCM_SET_TAG
#endif

#define foreach_openssl_hash_op                                                                    \
  _ (SHA1_160, EVP_sha1)                                                                           \
  _ (SHA_224, EVP_sha224)                                                                          \
  _ (SHA_256, EVP_sha256)                                                                          \
  _ (SHA_384, EVP_sha384)                                                                          \
  _ (SHA_512, EVP_sha512)

#define foreach_openssl_hmac_op                                                                    \
  _ (MD5, EVP_md5)                                                                                 \
  _ (SHA1_160, EVP_sha1)                                                                           \
  _ (SHA_224, EVP_sha224)                                                                          \
  _ (SHA_256, EVP_sha256)                                                                          \
  _ (SHA_384, EVP_sha384)                                                                          \
  _ (SHA_512, EVP_sha512)

static_always_inline u32
openssl_ops_enc_cbc_hmac (vnet_crypto_op_t *ops[], u32 n_ops, u32 auth_len,
			  clib_thread_index_t thread_index)
{
  EVP_CIPHER_CTX *enc_ctx;
  HMAC_CTX *hmac_ctx;
  u32 i;
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u32 len = auth_len ? auth_len : op->auth_len;
      int out_len = 0;
      unsigned int hmac_out_len = 0;

      openssl_combined_key_data_t *kd =
	(openssl_combined_key_data_t *) vnet_crypto_get_simple_key_data_for_thread (op->ctx,
										    thread_index);
      enc_ctx = kd->evp_cipher_enc_ctx;
      hmac_ctx = kd->hmac_ctx;
      EVP_EncryptInit_ex (enc_ctx, NULL, NULL, NULL, op->iv);
      HMAC_Init_ex (hmac_ctx, NULL, 0, NULL, NULL);

      EVP_EncryptUpdate (enc_ctx, op->dst, &out_len, op->src, op->len);
      if (out_len < op->len)
	EVP_EncryptFinal_ex (enc_ctx, op->dst + out_len, &out_len);

      HMAC_Update (hmac_ctx, op->auth_src, op->auth_src_len);
      HMAC_Final (hmac_ctx, buffer, &hmac_out_len);
      clib_memcpy_fast (op->auth, buffer, len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_hmac_dec_cbc (vnet_crypto_op_t *ops[], u32 n_ops, u32 auth_len,
			  clib_thread_index_t thread_index)
{
  HMAC_CTX *hmac_ctx;
  EVP_CIPHER_CTX *dec_ctx;
  u32 i, n_fail = 0;
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u32 len = auth_len ? auth_len : op->auth_len;
      int out_len = 0;
      unsigned int hmac_out_len = 0;

      openssl_combined_key_data_t *kd =
	(openssl_combined_key_data_t *) vnet_crypto_get_simple_key_data_for_thread (op->ctx,
										    thread_index);
      hmac_ctx = kd->hmac_ctx;
      dec_ctx = kd->evp_cipher_dec_ctx;
      HMAC_Init_ex (hmac_ctx, NULL, 0, NULL, NULL);
      EVP_DecryptInit_ex (dec_ctx, NULL, NULL, NULL, op->iv);

      HMAC_Update (hmac_ctx, op->auth_src, op->auth_src_len);
      HMAC_Final (hmac_ctx, buffer, &hmac_out_len);
      if ((memcmp (op->auth, buffer, len)))
	{
	  n_fail++;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  continue;
	}
      EVP_DecryptUpdate (dec_ctx, op->dst, &out_len, op->src, op->len);
      if (out_len < op->len)
	EVP_DecryptFinal_ex (dec_ctx, op->dst + out_len, &out_len);

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
}

static_always_inline u32
openssl_ops_enc_cbc_hmac_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				  u32 n_ops, u32 auth_len, clib_thread_index_t thread_index)
{
  EVP_CIPHER_CTX *enc_ctx;
  HMAC_CTX *hmac_ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, curr_len = 0;
  u8 out_buf[VLIB_BUFFER_DEFAULT_DATA_SIZE * 5];
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u32 len = auth_len ? auth_len : op->auth_len;
      int out_len = 0;
      unsigned int hmac_out_len = 0;

      openssl_combined_key_data_t *kd =
	(openssl_combined_key_data_t *) vnet_crypto_get_chained_key_data_for_thread (op->ctx,
										     thread_index);
      enc_ctx = kd->evp_cipher_enc_ctx;
      hmac_ctx = kd->hmac_ctx;
      EVP_EncryptInit_ex (enc_ctx, NULL, NULL, NULL, op->iv);
      HMAC_Init_ex (hmac_ctx, NULL, 0, NULL, NULL);

      chp = chunks + op->chunk_index;
      u32 offset = 0;
      for (j = 0; j < op->n_chunks; j++)
	{
	  EVP_EncryptUpdate (enc_ctx, out_buf + offset, &out_len, chp->src,
			     chp->len);
	  curr_len = chp->len;
	  offset += out_len;
	  chp += 1;
	}
      if (out_len < curr_len)
	EVP_EncryptFinal_ex (enc_ctx, out_buf + offset, &out_len);

      offset = 0;
      chp = chunks + op->chunk_index;
      for (j = 0; j < op->n_chunks; j++)
	{
	  clib_memcpy_fast (chp->dst, out_buf + offset, chp->len);
	  offset += chp->len;
	  chp += 1;
	}
      chp = chunks + op->auth_chunk_index;
      for (j = 0; j < op->auth_n_chunks; j++)
	{
	  HMAC_Update (hmac_ctx, chp->src, chp->len);
	  chp += 1;
	}

      HMAC_Final (hmac_ctx, buffer, &hmac_out_len);
      clib_memcpy_fast (op->auth, buffer, len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_hmac_dec_cbc_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				  u32 n_ops, u32 auth_len, clib_thread_index_t thread_index)
{
  HMAC_CTX *hmac_ctx;
  EVP_CIPHER_CTX *dec_ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, curr_len = 0, n_fail = 0;
  u8 out_buf[VLIB_BUFFER_DEFAULT_DATA_SIZE * 5];
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u32 len = auth_len ? auth_len : op->auth_len;
      int out_len = 0;
      unsigned int hmac_out_len = 0;

      openssl_combined_key_data_t *kd =
	(openssl_combined_key_data_t *) vnet_crypto_get_chained_key_data_for_thread (op->ctx,
										     thread_index);
      hmac_ctx = kd->hmac_ctx;
      dec_ctx = kd->evp_cipher_dec_ctx;
      HMAC_Init_ex (hmac_ctx, NULL, 0, NULL, NULL);
      EVP_DecryptInit_ex (dec_ctx, NULL, NULL, NULL, op->iv);

      chp = chunks + op->auth_chunk_index;
      for (j = 0; j < op->auth_n_chunks; j++)
	{
	  HMAC_Update (hmac_ctx, chp->src, chp->len);
	  chp += 1;
	}
      HMAC_Final (hmac_ctx, buffer, &hmac_out_len);
      if ((memcmp (op->auth, buffer, len)))
	{
	  n_fail++;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  continue;
	}

      chp = chunks + op->chunk_index;
      u32 offset = 0;
      for (j = 0; j < op->n_chunks; j++)
	{
	  EVP_DecryptUpdate (dec_ctx, out_buf + offset, &out_len, chp->src,
			     chp->len);
	  curr_len = chp->len;
	  offset += out_len;
	  chp += 1;
	}
      if (out_len < curr_len)
	EVP_DecryptFinal_ex (dec_ctx, out_buf + offset, &out_len);

      offset = 0;
      chp = chunks + op->chunk_index;
      for (j = 0; j < op->n_chunks; j++)
	{
	  clib_memcpy_fast (chp->dst, out_buf + offset, chp->len);
	  offset += chp->len;
	  chp += 1;
	}
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
}

static_always_inline u32
openssl_ops_enc_cbc (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		     const EVP_CIPHER *cipher, u32 fixed, u32 aad_len,
		     clib_thread_index_t thread_index)
{
  EVP_CIPHER_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, curr_len = 0;
  u8 out_buf[VLIB_BUFFER_DEFAULT_DATA_SIZE * 5];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      openssl_cipher_key_data_t *kd =
	chunks ?
	  (openssl_cipher_key_data_t *) vnet_crypto_get_chained_key_data_for_thread (op->ctx,
										     thread_index) :
	  (openssl_cipher_key_data_t *) vnet_crypto_get_simple_key_data_for_thread (op->ctx,
										    thread_index);
      int out_len = 0;

      ctx = kd->evp_cipher_enc_ctx;
      EVP_EncryptInit_ex (ctx, NULL, NULL, NULL, op->iv);

      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  chp = chunks + op->chunk_index;
	  u32 offset = 0;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      EVP_EncryptUpdate (ctx, out_buf + offset, &out_len, chp->src,
				 chp->len);
	      curr_len = chp->len;
	      offset += out_len;
	      chp += 1;
	    }
	  if (out_len < curr_len)
	    EVP_EncryptFinal_ex (ctx, out_buf + offset, &out_len);

	  offset = 0;
	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      clib_memcpy_fast (chp->dst, out_buf + offset, chp->len);
	      offset += chp->len;
	      chp += 1;
	    }
	}
      else
	{
	  EVP_EncryptUpdate (ctx, op->dst, &out_len, op->src, op->len);
	  if (out_len < op->len)
	    EVP_EncryptFinal_ex (ctx, op->dst + out_len, &out_len);
	}
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_dec_cbc (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		     const EVP_CIPHER *cipher, u32 fixed, u32 aad_len,
		     clib_thread_index_t thread_index)
{
  EVP_CIPHER_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, curr_len = 0;
  u8 out_buf[VLIB_BUFFER_DEFAULT_DATA_SIZE * 5];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      openssl_cipher_key_data_t *kd =
	chunks ?
	  (openssl_cipher_key_data_t *) vnet_crypto_get_chained_key_data_for_thread (op->ctx,
										     thread_index) :
	  (openssl_cipher_key_data_t *) vnet_crypto_get_simple_key_data_for_thread (op->ctx,
										    thread_index);
      int out_len = 0;

      ctx = kd->evp_cipher_dec_ctx;
      EVP_DecryptInit_ex (ctx, NULL, NULL, NULL, op->iv);

      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  chp = chunks + op->chunk_index;
	  u32 offset = 0;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      EVP_DecryptUpdate (ctx, out_buf + offset, &out_len, chp->src,
				 chp->len);
	      curr_len = chp->len;
	      offset += out_len;
	      chp += 1;
	    }
	  if (out_len < curr_len)
	    EVP_DecryptFinal_ex (ctx, out_buf + offset, &out_len);

	  offset = 0;
	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      clib_memcpy_fast (chp->dst, out_buf + offset, chp->len);
	      offset += chp->len;
	      chp += 1;
	    }
	}
      else
	{
	  EVP_DecryptUpdate (ctx, op->dst, &out_len, op->src, op->len);
	  if (out_len < op->len)
	    EVP_DecryptFinal_ex (ctx, op->dst + out_len, &out_len);
	}
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_enc_aead (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		      const EVP_CIPHER *cipher, int is_gcm, int is_gmac, i32 aadlen, u32 taglen,
		      clib_thread_index_t thread_index)
{
  EVP_CIPHER_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      openssl_cipher_key_data_t *kd =
	chunks ?
	  (openssl_cipher_key_data_t *) vnet_crypto_get_chained_key_data_for_thread (op->ctx,
										     thread_index) :
	  (openssl_cipher_key_data_t *) vnet_crypto_get_simple_key_data_for_thread (op->ctx,
										    thread_index);
      int len = 0;
      u32 tag_len = taglen ? taglen : op->auth_len;
      u32 aad_len = aadlen >= 0 ? aadlen : op->aad_len;

      if (i + 2 < n_ops)
	{
	  CLIB_PREFETCH (ops[i + 1]->src, 4 * CLIB_CACHE_PREFETCH_BYTES, LOAD);
	  CLIB_PREFETCH (ops[i + 1]->dst, 4 * CLIB_CACHE_PREFETCH_BYTES,
			 STORE);

	  CLIB_PREFETCH (ops[i + 2]->src, 4 * CLIB_CACHE_PREFETCH_BYTES, LOAD);
	  CLIB_PREFETCH (ops[i + 2]->dst, 4 * CLIB_CACHE_PREFETCH_BYTES,
			 STORE);
	}

      ctx = kd->evp_cipher_enc_ctx;
      EVP_EncryptInit_ex (ctx, 0, 0, NULL, op->iv);

      if (aad_len)
	EVP_EncryptUpdate (ctx, NULL, &len, op->aad, aad_len);
      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      EVP_EncryptUpdate (ctx, is_gmac ? 0 : chp->dst, &len, chp->src,
				 chp->len);
	      chp += 1;
	    }
	}
      else
	EVP_EncryptUpdate (ctx, is_gmac ? 0 : op->dst, &len, op->src, op->len);
      EVP_EncryptFinal_ex (ctx, is_gmac ? 0 : op->dst + len, &len);
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, op->auth);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_enc_null_gmac (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
			   const EVP_CIPHER *cipher, i32 aadlen, u32 taglen,
			   clib_thread_index_t thread_index)
{
  return openssl_ops_enc_aead (ops, chunks, n_ops, cipher, /* is_gcm */ 1,
			       /* is_gmac */ 1, aadlen, taglen, thread_index);
}

static_always_inline u32
openssl_ops_enc_gcm (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		     const EVP_CIPHER *cipher, i32 aadlen, u32 taglen,
		     clib_thread_index_t thread_index)
{
  return openssl_ops_enc_aead (ops, chunks, n_ops, cipher, /* is_gcm */ 1,
			       /* is_gmac */ 0, aadlen, taglen, thread_index);
}

static_always_inline __clib_unused u32
openssl_ops_enc_chacha20_poly1305 (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				   u32 n_ops, const EVP_CIPHER *cipher, i32 aadlen, u32 taglen,
				   clib_thread_index_t thread_index)
{
  return openssl_ops_enc_aead (ops, chunks, n_ops, cipher, /* is_gcm */ 0,
			       /* is_gmac */ 0, aadlen, taglen, thread_index);
}

static_always_inline u32
openssl_ops_dec_aead (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		      const EVP_CIPHER *cipher, int is_gcm, int is_gmac, i32 aadlen, u32 taglen,
		      clib_thread_index_t thread_index)
{
  EVP_CIPHER_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, n_fail = 0;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      openssl_cipher_key_data_t *kd =
	chunks ?
	  (openssl_cipher_key_data_t *) vnet_crypto_get_chained_key_data_for_thread (op->ctx,
										     thread_index) :
	  (openssl_cipher_key_data_t *) vnet_crypto_get_simple_key_data_for_thread (op->ctx,
										    thread_index);
      int len = 0;
      u32 tag_len = taglen ? taglen : op->auth_len;
      u32 aad_len = aadlen >= 0 ? aadlen : op->aad_len;

      ctx = kd->evp_cipher_dec_ctx;
      EVP_DecryptInit_ex (ctx, 0, 0, NULL, op->iv);
      if (aad_len)
	EVP_DecryptUpdate (ctx, 0, &len, op->aad, aad_len);
      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      EVP_DecryptUpdate (ctx, is_gmac ? 0 : chp->dst, &len, chp->src,
				 chp->len);
	      chp += 1;
	    }
	}
      else
	{
	  EVP_DecryptUpdate (ctx, is_gmac ? 0 : op->dst, &len, op->src,
			     op->len);
	}
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, op->auth);

      if (EVP_DecryptFinal_ex (ctx, is_gmac ? 0 : op->dst + len, &len) > 0)
	op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      else
	{
	  n_fail++;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	}
    }
  return n_ops - n_fail;
}

static_always_inline u32
openssl_ops_dec_null_gmac (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
			   const EVP_CIPHER *cipher, i32 aad_len, u32 taglen,
			   clib_thread_index_t thread_index)
{
  return openssl_ops_dec_aead (ops, chunks, n_ops, cipher, /* is_gcm */ 1,
			       /* is_gmac */ 1, aad_len, taglen, thread_index);
}

static_always_inline u32
openssl_ops_dec_gcm (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		     const EVP_CIPHER *cipher, i32 aad_len, u32 taglen,
		     clib_thread_index_t thread_index)
{
  return openssl_ops_dec_aead (ops, chunks, n_ops, cipher, /* is_gcm */ 1,
			       /* is_gmac */ 0, aad_len, taglen, thread_index);
}

static_always_inline __clib_unused u32
openssl_ops_dec_chacha20_poly1305 (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				   u32 n_ops, const EVP_CIPHER *cipher, i32 aad_len, u32 taglen,
				   clib_thread_index_t thread_index)
{
  return openssl_ops_dec_aead (ops, chunks, n_ops, cipher, /* is_gcm */ 0,
			       /* is_gmac */ 0, aad_len, taglen, thread_index);
}

static_always_inline u32
openssl_ops_hash (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		  const EVP_MD *md)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_create ();
  vnet_crypto_op_chunk_t *chp;
  u32 md_len, i, j, n_fail = 0;

  if (ctx == 0)
    {
      for (u32 k = 0; k < n_ops; k++)
	ops[k]->status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
      return 0;
    }

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];

      EVP_DigestInit_ex (ctx, md, NULL);
      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  chp = chunks + op->chunk_index;
	  for (j = 0; j < op->n_chunks; j++)
	    {
	      EVP_DigestUpdate (ctx, chp->src, chp->len);
	      chp += 1;
	    }
	}
      else
	EVP_DigestUpdate (ctx, op->src, op->len);

      EVP_DigestFinal_ex (ctx, op->auth, &md_len);
      op->auth_len = md_len;
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  EVP_MD_CTX_destroy (ctx);
  return n_ops - n_fail;
}

static_always_inline void openssl_ctx_hmac_add (const u8 *key_bytes, u16 key_len, u8 *key_data,
						const EVP_MD *md);

static_always_inline u32
openssl_ops_hmac (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		  const EVP_MD *md, clib_thread_index_t thread_index)
{
  u8 buffer[64];
  HMAC_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, n_fail = 0;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      openssl_hmac_key_data_t *kd =
	chunks ?
	  (openssl_hmac_key_data_t *) vnet_crypto_get_chained_key_data_for_thread (op->ctx,
										   thread_index) :
	  (openssl_hmac_key_data_t *) vnet_crypto_get_simple_key_data_for_thread (op->ctx,
										  thread_index);
      unsigned int out_len = 0;
      size_t sz = op->auth_len ? op->auth_len : EVP_MD_size (md);

      ctx = kd->hmac_ctx;
      if (ctx == 0)
	{
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	  n_fail++;
	  continue;
	}
      HMAC_Init_ex (ctx, NULL, 0, NULL, NULL);
      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  chp = chunks + op->auth_chunk_index;
	  for (j = 0; j < op->auth_n_chunks; j++)
	    {
	      HMAC_Update (ctx, chp->src, chp->len);
	      chp += 1;
	    }
	}
      else
	HMAC_Update (ctx, op->auth_src, op->auth_src_len);
      HMAC_Final (ctx, buffer, &out_len);

      if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	{
	  if ((memcmp (op->auth, buffer, sz)))
	    {
	      n_fail++;
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      continue;
	    }
	}
      else
	clib_memcpy_fast (op->auth, buffer, sz);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
}

static_always_inline void
openssl_ctx_cipher_add (const u8 *key_bytes, u8 *key_data, const EVP_CIPHER *cipher, int is_gcm)
{
  EVP_CIPHER_CTX *ctx;
  openssl_cipher_key_data_t *kd = (openssl_cipher_key_data_t *) key_data;

  if (kd->evp_cipher_enc_ctx)
    {
      ctx = kd->evp_cipher_enc_ctx;
      EVP_EncryptInit_ex (ctx, cipher, NULL, NULL, NULL);
      if (is_gcm)
	EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
      EVP_EncryptInit_ex (ctx, 0, 0, key_bytes, 0);
    }
  else
    {
      ctx = EVP_CIPHER_CTX_new ();
      EVP_CIPHER_CTX_set_padding (ctx, 0);
      EVP_EncryptInit_ex (ctx, cipher, NULL, NULL, NULL);
      if (is_gcm)
	EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
      EVP_EncryptInit_ex (ctx, 0, 0, key_bytes, 0);
      kd->evp_cipher_enc_ctx = ctx;
    }

  if (kd->evp_cipher_dec_ctx)
    {
      ctx = kd->evp_cipher_dec_ctx;
      EVP_DecryptInit_ex (ctx, cipher, 0, 0, 0);
      if (is_gcm)
	EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0);
      EVP_DecryptInit_ex (ctx, 0, 0, key_bytes, 0);
    }
  else
    {
      ctx = EVP_CIPHER_CTX_new ();
      EVP_CIPHER_CTX_set_padding (ctx, 0);
      EVP_DecryptInit_ex (ctx, cipher, 0, 0, 0);
      if (is_gcm)
	EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0);
      EVP_DecryptInit_ex (ctx, 0, 0, key_bytes, 0);
      kd->evp_cipher_dec_ctx = ctx;
    }
}

static_always_inline void
openssl_ctx_cipher_del (vnet_crypto_ctx_t *ctx __clib_unused, u8 *key_data)
{
  openssl_cipher_key_data_t *kd = (openssl_cipher_key_data_t *) key_data;

  if (kd->evp_cipher_enc_ctx)
    {
      EVP_CIPHER_CTX_free (kd->evp_cipher_enc_ctx);
      kd->evp_cipher_enc_ctx = 0;
    }

  if (kd->evp_cipher_dec_ctx)
    {
      EVP_CIPHER_CTX_free (kd->evp_cipher_dec_ctx);
      kd->evp_cipher_dec_ctx = 0;
    }
}

static_always_inline void
openssl_ctx_hmac_add (const u8 *key_bytes, u16 key_len, u8 *key_data, const EVP_MD *md)
{
  openssl_hmac_key_data_t *kd = (openssl_hmac_key_data_t *) key_data;
  HMAC_CTX *ctx = kd->hmac_ctx;

  if (ctx)
    {
      HMAC_Init_ex (ctx, key_bytes, key_len, md, NULL);
      return;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = HMAC_CTX_new ();
  HMAC_Init_ex (ctx, key_bytes, key_len, md, NULL);
  kd->hmac_ctx = ctx;
#else
  ctx = clib_mem_alloc_aligned (sizeof (*ctx), CLIB_CACHE_LINE_BYTES);
  HMAC_CTX_init (ctx);
  HMAC_Init_ex (ctx, key_bytes, key_len, md, NULL);
  kd->hmac_ctx = ctx;
#endif
}

static_always_inline void
openssl_ctx_hmac_del (vnet_crypto_ctx_t *ctx __clib_unused, u8 *key_data)
{
  openssl_hmac_key_data_t *kd = (openssl_hmac_key_data_t *) key_data;
  HMAC_CTX *hctx = kd->hmac_ctx;

  if (hctx == 0)
    return;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX_free (hctx);
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX_cleanup (hctx);
  clib_mem_free_s (hctx);
#endif
  kd->hmac_ctx = 0;
}

static_always_inline void
openssl_ctx_combined_hmac_add (const u8 *key_bytes, u16 key_len, u8 *key_data, const EVP_MD *md)
{
  openssl_combined_key_data_t *kd = (openssl_combined_key_data_t *) key_data;
  HMAC_CTX *ctx = kd->hmac_ctx;

  if (ctx)
    {
      HMAC_Init_ex (ctx, key_bytes, key_len, md, NULL);
      return;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = HMAC_CTX_new ();
  HMAC_Init_ex (ctx, key_bytes, key_len, md, NULL);
  kd->hmac_ctx = ctx;
#else
  ctx = clib_mem_alloc_aligned (sizeof (*ctx), CLIB_CACHE_LINE_BYTES);
  HMAC_CTX_init (ctx);
  HMAC_Init_ex (ctx, key_bytes, key_len, md, NULL);
  kd->hmac_ctx = ctx;
#endif
}

static_always_inline void
openssl_ctx_combined_hmac_del (vnet_crypto_ctx_t *ctx __clib_unused, u8 *key_data)
{
  openssl_combined_key_data_t *kd = (openssl_combined_key_data_t *) key_data;
  HMAC_CTX *hctx = kd->hmac_ctx;

  if (hctx == 0)
    return;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX_free (hctx);
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX_cleanup (hctx);
  clib_mem_free_s (hctx);
#endif
  kd->hmac_ctx = 0;
}

static_always_inline void
openssl_ctx_cipher_md_add (vnet_crypto_ctx_t *ctx, u8 *key_data, const EVP_CIPHER *cipher,
			   const EVP_MD *md, u32 crypto_key_len)
{
  const u8 *cipher_key;
  const u8 *auth_key;
  u16 auth_key_len;

  if (ctx->cipher_key_sz + ctx->auth_key_sz < crypto_key_len)
    return;

  cipher_key = vnet_crypto_get_cipher_key (ctx);
  auth_key = vnet_crypto_get_auth_key (ctx);
  auth_key_len = ctx->auth_key_sz;

  openssl_ctx_cipher_add (cipher_key, key_data, cipher, 0);
  openssl_ctx_combined_hmac_add (auth_key, auth_key_len, key_data, md);
}

typedef const EVP_CIPHER *(openssl_cipher_fn_t) (void);
typedef const EVP_MD *(openssl_md_fn_t) (void);

static openssl_cipher_fn_t *openssl_cipher_fn_by_alg[VNET_CRYPTO_N_ALGS] = {
#define _(m, a, b, f, l) [VNET_CRYPTO_ALG_##a] = b,
  foreach_openssl_evp_op
#undef _
};

static openssl_md_fn_t *openssl_hmac_md_fn_by_alg[VNET_CRYPTO_N_ALGS] = {
#define _(a, b) [VNET_CRYPTO_ALG_##a] = b,
  foreach_openssl_hmac_op
#undef _
    [VNET_CRYPTO_ALG_MD5_ICV12] = EVP_md5,
  [VNET_CRYPTO_ALG_SHA1_160_ICV12] = EVP_sha1,
  [VNET_CRYPTO_ALG_SHA_256_ICV12] = EVP_sha256,
  [VNET_CRYPTO_ALG_SHA_256_ICV16] = EVP_sha256,
  [VNET_CRYPTO_ALG_SHA_384_ICV24] = EVP_sha384,
  [VNET_CRYPTO_ALG_SHA_512_ICV32] = EVP_sha512,
};

static openssl_cipher_fn_t *openssl_combined_cipher_fn_by_alg[VNET_CRYPTO_N_ALGS] = {
#define _(a, c, h, k, d) [VNET_CRYPTO_ALG_##a] = c,
  foreach_openssl_combined_evp_op
#undef _
};

static openssl_md_fn_t *openssl_combined_md_fn_by_alg[VNET_CRYPTO_N_ALGS] = {
#define _(a, c, h, k, d) [VNET_CRYPTO_ALG_##a] = h,
  foreach_openssl_combined_evp_op
#undef _
};

static u16 openssl_combined_cipher_key_size_by_alg[VNET_CRYPTO_N_ALGS] = {
#define _(a, c, h, k, d) [VNET_CRYPTO_ALG_##a] = k,
  foreach_openssl_combined_evp_op
#undef _
};

static void
openssl_ctx_add_cipher_group_internal (vnet_crypto_ctx_t *ctx, u8 *key_data, int is_gcm)
{
  openssl_cipher_fn_t *f = openssl_cipher_fn_by_alg[ctx->alg];

  if (f == 0)
    return;

  openssl_ctx_cipher_add (vnet_crypto_get_cipher_key (ctx), key_data, f (), is_gcm);
}

static void
openssl_ctx_add_cipher_key_data (vnet_crypto_ctx_t *ctx, u8 *key_data, void *arg)
{
  openssl_ctx_add_cipher_group_internal (ctx, key_data, pointer_to_uword (arg));
}

static void
openssl_ctx_del_cipher_key_data (vnet_crypto_ctx_t *ctx, u8 *key_data, void *arg __clib_unused)
{
  openssl_ctx_cipher_del (ctx, key_data);
}

static void
openssl_ctx_add_combined_key_data (vnet_crypto_ctx_t *ctx, u8 *key_data, void *arg __clib_unused)
{
  openssl_cipher_fn_t *cf = openssl_combined_cipher_fn_by_alg[ctx->alg];
  openssl_md_fn_t *mf = openssl_combined_md_fn_by_alg[ctx->alg];
  u16 key_size = openssl_combined_cipher_key_size_by_alg[ctx->alg];

  if (cf == 0 || mf == 0 || key_size == 0)
    return;

  openssl_ctx_cipher_md_add (ctx, key_data, cf (), mf (), key_size);
}

static void
openssl_ctx_del_combined_key_data (vnet_crypto_ctx_t *ctx, u8 *key_data, void *arg __clib_unused)
{
  openssl_ctx_cipher_del (ctx, key_data);
  openssl_ctx_combined_hmac_del (ctx, key_data);
}

static void
openssl_ctx_add_hmac_key_data (vnet_crypto_ctx_t *ctx, u8 *key_data, void *arg __clib_unused)
{
  openssl_md_fn_t *f = openssl_hmac_md_fn_by_alg[ctx->alg];

  if (f == 0)
    return;

  openssl_ctx_hmac_add (vnet_crypto_get_auth_key (ctx), ctx->auth_key_sz, key_data, f ());
}

static void
openssl_ctx_del_hmac_key_data (vnet_crypto_ctx_t *ctx, u8 *key_data, void *arg __clib_unused)
{
  openssl_ctx_hmac_del (ctx, key_data);
}

static vnet_crypto_key_data_t
openssl_ctx_get_change_data (vnet_crypto_key_change_args_t *args)
{
  return args->action == VNET_CRYPTO_THREAD_KEY_DATA_ADD ||
	     args->action == VNET_CRYPTO_THREAD_KEY_DATA_REMOVE ?
	   args->thread_key_data :
	   args->key_data;
}

static void
openssl_ctx_change_cipher_group (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data = openssl_ctx_get_change_data (args);

  if (args->action == VNET_CRYPTO_KEY_DATA_ADD || args->action == VNET_CRYPTO_THREAD_KEY_DATA_ADD)
    openssl_ctx_add_cipher_key_data (ctx, key_data, 0);
  else
    openssl_ctx_del_cipher_key_data (ctx, key_data, 0);
}

static void
openssl_ctx_change_gcm_group (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data = openssl_ctx_get_change_data (args);

  if (args->action == VNET_CRYPTO_KEY_DATA_ADD || args->action == VNET_CRYPTO_THREAD_KEY_DATA_ADD)
    openssl_ctx_add_cipher_key_data (ctx, key_data, uword_to_pointer (1, void *));
  else
    openssl_ctx_del_cipher_key_data (ctx, key_data, 0);
}

static void
openssl_ctx_change_combined_group (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data = openssl_ctx_get_change_data (args);

  if (args->action == VNET_CRYPTO_KEY_DATA_ADD || args->action == VNET_CRYPTO_THREAD_KEY_DATA_ADD)
    openssl_ctx_add_combined_key_data (ctx, key_data, 0);
  else
    openssl_ctx_del_combined_key_data (ctx, key_data, 0);
}

static void
openssl_ctx_change_hmac_group (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data = openssl_ctx_get_change_data (args);

  if (args->action == VNET_CRYPTO_KEY_DATA_ADD || args->action == VNET_CRYPTO_THREAD_KEY_DATA_ADD)
    openssl_ctx_add_hmac_key_data (ctx, key_data, 0);
  else
    openssl_ctx_del_hmac_key_data (ctx, key_data, 0);
}

#define _(m, a, b, f, l)                                                                           \
  static u32 openssl_ops_enc_##a (vnet_crypto_op_t *ops[],                                         \
				  vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,         \
				  clib_thread_index_t thread_index)                                \
  {                                                                                                \
    return openssl_ops_enc_##m (ops, 0, n_ops, b (), f ? l : -1, f ? 16 : 0, thread_index);        \
  }                                                                                                \
                                                                                                   \
  u32 openssl_ops_dec_##a (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused,  \
			   u32 n_ops, clib_thread_index_t thread_index)                            \
  {                                                                                                \
    return openssl_ops_dec_##m (ops, 0, n_ops, b (), f ? l : -1, f ? 16 : 0, thread_index);        \
  }                                                                                                \
                                                                                                   \
  static u32 openssl_ops_enc_chained_##a (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
					  u32 n_ops, clib_thread_index_t thread_index)             \
  {                                                                                                \
    return openssl_ops_enc_##m (ops, chunks, n_ops, b (), f ? l : -1, f ? 16 : 0, thread_index);   \
  }                                                                                                \
                                                                                                   \
  static u32 openssl_ops_dec_chained_##a (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
					  u32 n_ops, clib_thread_index_t thread_index)             \
  {                                                                                                \
    return openssl_ops_dec_##m (ops, chunks, n_ops, b (), f ? l : -1, f ? 16 : 0, thread_index);   \
  }

foreach_openssl_evp_op;
#undef _

#define _(a, c, h, k, d)                                                                           \
  static u32 openssl_ops_enc_##a (vnet_crypto_op_t *ops[],                                         \
				  vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,         \
				  clib_thread_index_t thread_index)                                \
  {                                                                                                \
    return openssl_ops_enc_cbc_hmac (ops, n_ops, d, thread_index);                                 \
  }                                                                                                \
                                                                                                   \
  u32 openssl_ops_dec_##a (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused,  \
			   u32 n_ops, clib_thread_index_t thread_index)                            \
  {                                                                                                \
    return openssl_ops_hmac_dec_cbc (ops, n_ops, d, thread_index);                                 \
  }                                                                                                \
                                                                                                   \
  static u32 openssl_ops_enc_chained_##a (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
					  u32 n_ops, clib_thread_index_t thread_index)             \
  {                                                                                                \
    return openssl_ops_enc_cbc_hmac_chained (ops, chunks, n_ops, d, thread_index);                 \
  }                                                                                                \
                                                                                                   \
  static u32 openssl_ops_dec_chained_##a (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
					  u32 n_ops, clib_thread_index_t thread_index)             \
  {                                                                                                \
    return openssl_ops_hmac_dec_cbc_chained (ops, chunks, n_ops, d, thread_index);                 \
  }

foreach_openssl_combined_evp_op;
#undef _

#define _(a, b)                                                                                    \
  static u32 openssl_ops_hash_##a (vnet_crypto_op_t *ops[],                                        \
				   vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,        \
				   clib_thread_index_t thread_index __clib_unused)                 \
  {                                                                                                \
    return openssl_ops_hash (ops, 0, n_ops, b ());                                                 \
  }                                                                                                \
  static u32 openssl_ops_hash_chained_##a (vnet_crypto_op_t *ops[],                                \
					   vnet_crypto_op_chunk_t *chunks, u32 n_ops,              \
					   clib_thread_index_t thread_index __clib_unused)         \
  {                                                                                                \
    return openssl_ops_hash (ops, chunks, n_ops, b ());                                            \
  }

  foreach_openssl_hash_op;
#undef _

#define _(a, b)                                                                                    \
  static u32 openssl_ops_hmac_##a (vnet_crypto_op_t *ops[],                                        \
				   vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,        \
				   clib_thread_index_t thread_index)                               \
  {                                                                                                \
    return openssl_ops_hmac (ops, 0, n_ops, b (), thread_index);                                   \
  }                                                                                                \
  static u32 openssl_ops_hmac_chained_##a (vnet_crypto_op_t *ops[],                                \
					   vnet_crypto_op_chunk_t *chunks, u32 n_ops,              \
					   clib_thread_index_t thread_index)                       \
  {                                                                                                \
    return openssl_ops_hmac (ops, chunks, n_ops, b (), thread_index);                              \
  }

foreach_openssl_hmac_op;
#undef _

static char *
crypto_openssl_init (vnet_crypto_engine_registration_t *r __clib_unused)
{
  u8 seed[32];

  if (syscall (SYS_getrandom, &seed, sizeof (seed), 0) != sizeof (seed))
    return "getrandom() failed";

  RAND_seed (seed, sizeof (seed));

  return 0;
}

VNET_CRYPTO_REG_ALG_GROUP (openssl_cipher_group) = {
  .max_key_data_sz = sizeof (openssl_cipher_key_data_t),
  .key_data_per_thread = 1,
  .key_change_fn = openssl_ctx_change_cipher_group,
};

VNET_CRYPTO_REG_ALG_GROUP (openssl_gcm_group) = {
  .max_key_data_sz = sizeof (openssl_cipher_key_data_t),
  .key_data_per_thread = 1,
  .key_change_fn = openssl_ctx_change_gcm_group,
};

VNET_CRYPTO_REG_ALG_GROUP (openssl_combined_group) = {
  .max_key_data_sz = sizeof (openssl_combined_key_data_t),
  .key_data_per_thread = 1,
  .key_change_fn = openssl_ctx_change_combined_group,
};

VNET_CRYPTO_REG_ALG_GROUP (openssl_hmac_group) = {
  .max_key_data_sz = sizeof (openssl_hmac_key_data_t),
  .key_data_per_thread = 1,
  .key_change_fn = openssl_ctx_change_hmac_group,
};

VNET_CRYPTO_REG_ALG_GROUP (openssl_hash_group) = {
  .max_key_data_sz = 0,
};

#define _(m, a, b, f, l)                                                                           \
  VNET_CRYPTO_REG_ALG (openssl_##a) = {                                                            \
    .group = &openssl_cipher_group,                                                                \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = {                                                                                    \
      .enc_fn = openssl_ops_enc_##a,                                                               \
      .dec_fn = openssl_ops_dec_##a,                                                               \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = openssl_ops_enc_chained_##a,                                                       \
      .dec_fn = openssl_ops_dec_chained_##a,                                                       \
    },                                                                                             \
  };
foreach_openssl_aes_evp_op foreach_openssl_chacha20_evp_op
#undef _

#define _(m, a, b, f, l)                                                                           \
  VNET_CRYPTO_REG_ALG (openssl_##a) = {                                                            \
    .group = &openssl_gcm_group,                                                                   \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = {                                                                                    \
      .enc_fn = openssl_ops_enc_##a,                                                               \
      .dec_fn = openssl_ops_dec_##a,                                                               \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = openssl_ops_enc_chained_##a,                                                       \
      .dec_fn = openssl_ops_dec_chained_##a,                                                       \
    },                                                                                             \
  };
  foreach_openssl_aes_gcm_evp_op
#undef _

#define _(a, c, h, k, d)                                                                           \
  VNET_CRYPTO_REG_ALG (openssl_##a) = {                                                            \
    .group = &openssl_combined_group,                                                              \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = {                                                                                    \
      .enc_fn = openssl_ops_enc_##a,                                                               \
      .dec_fn = openssl_ops_dec_##a,                                                               \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = openssl_ops_enc_chained_##a,                                                       \
      .dec_fn = openssl_ops_dec_chained_##a,                                                       \
    },                                                                                             \
  };
    foreach_openssl_combined_evp_op
#undef _

#define _(a, b)                                                                                    \
  VNET_CRYPTO_REG_ALG (openssl_hmac_##a) = {                                                       \
    .group = &openssl_hmac_group,                                                                  \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = { .hmac_fn = openssl_ops_hmac_##a, },                                                \
    .chained = { .hmac_fn = openssl_ops_hmac_chained_##a, },                                       \
  };
      foreach_openssl_hmac_op
#undef _

VNET_CRYPTO_REG_ALG (openssl_hmac_md5_icv12) = {
  .group = &openssl_hmac_group,
  .alg_id = VNET_CRYPTO_ALG_MD5_ICV12,
  .simple = { .hmac_fn = openssl_ops_hmac_MD5, },
  .chained = { .hmac_fn = openssl_ops_hmac_chained_MD5, },
};

VNET_CRYPTO_REG_ALG (openssl_hmac_sha1_icv12) = {
  .group = &openssl_hmac_group,
  .alg_id = VNET_CRYPTO_ALG_SHA1_160_ICV12,
  .simple = { .hmac_fn = openssl_ops_hmac_SHA1_160, },
  .chained = { .hmac_fn = openssl_ops_hmac_chained_SHA1_160, },
};

VNET_CRYPTO_REG_ALG (openssl_hmac_sha256_icv12) = {
  .group = &openssl_hmac_group,
  .alg_id = VNET_CRYPTO_ALG_SHA_256_ICV12,
  .simple = { .hmac_fn = openssl_ops_hmac_SHA_256, },
  .chained = { .hmac_fn = openssl_ops_hmac_chained_SHA_256, },
};

VNET_CRYPTO_REG_ALG (openssl_hmac_sha256_icv16) = {
  .group = &openssl_hmac_group,
  .alg_id = VNET_CRYPTO_ALG_SHA_256_ICV16,
  .simple = { .hmac_fn = openssl_ops_hmac_SHA_256, },
  .chained = { .hmac_fn = openssl_ops_hmac_chained_SHA_256, },
};

VNET_CRYPTO_REG_ALG (openssl_hmac_sha384_icv24) = {
  .group = &openssl_hmac_group,
  .alg_id = VNET_CRYPTO_ALG_SHA_384_ICV24,
  .simple = { .hmac_fn = openssl_ops_hmac_SHA_384, },
  .chained = { .hmac_fn = openssl_ops_hmac_chained_SHA_384, },
};

VNET_CRYPTO_REG_ALG (openssl_hmac_sha512_icv32) = {
  .group = &openssl_hmac_group,
  .alg_id = VNET_CRYPTO_ALG_SHA_512_ICV32,
  .simple = { .hmac_fn = openssl_ops_hmac_SHA_512, },
  .chained = { .hmac_fn = openssl_ops_hmac_chained_SHA_512, },
};

#define _(a, b)                                                                                    \
  VNET_CRYPTO_REG_ALG (openssl_hash_##a) = {                                                       \
    .group = &openssl_hash_group,                                                                  \
    .alg_id = VNET_CRYPTO_ALG_##a,                                                                 \
    .simple = { .hash_fn = openssl_ops_hash_##a, },                                                \
    .chained = { .hash_fn = openssl_ops_hash_chained_##a, },                                       \
  };
foreach_openssl_hash_op;
#undef _

VNET_CRYPTO_REG_ENGINE () = {
  .name = "openssl",
  .desc = "OpenSSL",
  .prio = 50,
  .init_fn = crypto_openssl_init,
};
