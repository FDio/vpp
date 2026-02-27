/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>
#include <openssl/crypto_openssl.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  EVP_CIPHER_CTX **evp_cipher_enc_ctx;
  EVP_CIPHER_CTX **evp_cipher_dec_ctx;
  HMAC_CTX **hmac_ctx;
  EVP_MD_CTX *hash_ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX _hmac_ctx;
#endif
} openssl_per_thread_data_t;

static openssl_per_thread_data_t *per_thread_data;
static u32 num_threads;

#define foreach_openssl_aes_evp_op                                            \
  _ (cbc, DES_CBC, EVP_des_cbc, 0, 0)                                         \
  _ (cbc, 3DES_CBC, EVP_des_ede3_cbc, 0, 0)                                   \
  _ (cbc, AES_128_CBC, EVP_aes_128_cbc, 0, 0)                                 \
  _ (cbc, AES_192_CBC, EVP_aes_192_cbc, 0, 0)                                 \
  _ (cbc, AES_256_CBC, EVP_aes_256_cbc, 0, 0)                                 \
  _ (gcm, AES_128_GCM, EVP_aes_128_gcm, 0, 0)                                 \
  _ (gcm, AES_128_GCM_TAG16_AAD8, EVP_aes_128_gcm, 1, 8)                      \
  _ (gcm, AES_128_GCM_TAG16_AAD12, EVP_aes_128_gcm, 1, 12)                    \
  _ (gcm, AES_192_GCM, EVP_aes_192_gcm, 0, 0)                                 \
  _ (gcm, AES_192_GCM_TAG16_AAD8, EVP_aes_192_gcm, 1, 8)                      \
  _ (gcm, AES_192_GCM_TAG16_AAD12, EVP_aes_192_gcm, 1, 12)                    \
  _ (gcm, AES_256_GCM, EVP_aes_256_gcm, 0, 0)                                 \
  _ (gcm, AES_256_GCM_TAG16_AAD8, EVP_aes_256_gcm, 1, 8)                      \
  _ (gcm, AES_256_GCM_TAG16_AAD12, EVP_aes_256_gcm, 1, 12)                    \
  _ (cbc, AES_128_CTR, EVP_aes_128_ctr, 0, 0)                                 \
  _ (cbc, AES_192_CTR, EVP_aes_192_ctr, 0, 0)                                 \
  _ (cbc, AES_256_CTR, EVP_aes_256_ctr, 0, 0)                                 \
  _ (null_gmac, AES_128_NULL_GMAC, EVP_aes_128_gcm, 0, 0)                     \
  _ (null_gmac, AES_192_NULL_GMAC, EVP_aes_192_gcm, 0, 0)                     \
  _ (null_gmac, AES_256_NULL_GMAC, EVP_aes_256_gcm, 0, 0)

#define foreach_openssl_linked_evp_op                                         \
  _ (3DES_CBC_SHA1_TAG12)                                                     \
  _ (3DES_CBC_SHA224_TAG14)                                                   \
  _ (3DES_CBC_SHA256_TAG16)                                                   \
  _ (3DES_CBC_SHA384_TAG24)                                                   \
  _ (3DES_CBC_SHA512_TAG32)                                                   \
  _ (AES_128_CBC_SHA1_TAG12)                                                  \
  _ (AES_192_CBC_SHA1_TAG12)                                                  \
  _ (AES_256_CBC_SHA1_TAG12)                                                  \
  _ (AES_128_CBC_SHA224_TAG14)                                                \
  _ (AES_192_CBC_SHA224_TAG14)                                                \
  _ (AES_256_CBC_SHA224_TAG14)                                                \
  _ (AES_128_CBC_SHA256_TAG16)                                                \
  _ (AES_192_CBC_SHA256_TAG16)                                                \
  _ (AES_256_CBC_SHA256_TAG16)                                                \
  _ (AES_128_CBC_SHA384_TAG24)                                                \
  _ (AES_192_CBC_SHA384_TAG24)                                                \
  _ (AES_256_CBC_SHA384_TAG24)                                                \
  _ (AES_128_CBC_SHA512_TAG32)                                                \
  _ (AES_192_CBC_SHA512_TAG32)                                                \
  _ (AES_256_CBC_SHA512_TAG32)                                                \
  _ (AES_128_CBC_MD5_TAG12)                                                   \
  _ (AES_192_CBC_MD5_TAG12)                                                   \
  _ (AES_256_CBC_MD5_TAG12)                                                   \
  _ (AES_128_CTR_SHA1_TAG12)                                                  \
  _ (AES_192_CTR_SHA1_TAG12)                                                  \
  _ (AES_256_CTR_SHA1_TAG12)                                                  \
  _ (AES_128_CTR_SHA256_TAG16)                                                \
  _ (AES_192_CTR_SHA256_TAG16)                                                \
  _ (AES_256_CTR_SHA256_TAG16)                                                \
  _ (AES_128_CTR_SHA384_TAG24)                                                \
  _ (AES_192_CTR_SHA384_TAG24)                                                \
  _ (AES_256_CTR_SHA384_TAG24)                                                \
  _ (AES_128_CTR_SHA512_TAG32)                                                \
  _ (AES_192_CTR_SHA512_TAG32)                                                \
  _ (AES_256_CTR_SHA512_TAG32)

#define foreach_openssl_chacha20_evp_op                                       \
  _ (chacha20_poly1305, CHACHA20_POLY1305, EVP_chacha20_poly1305, 0, 0)       \
  _ (chacha20_poly1305, CHACHA20_POLY1305_TAG16_AAD0, EVP_chacha20_poly1305,  \
     1, 0)                                                                    \
  _ (chacha20_poly1305, CHACHA20_POLY1305_TAG16_AAD8, EVP_chacha20_poly1305,  \
     1, 8)                                                                    \
  _ (chacha20_poly1305, CHACHA20_POLY1305_TAG16_AAD12, EVP_chacha20_poly1305, \
     1, 12)

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define foreach_openssl_evp_op foreach_openssl_aes_evp_op \
                               foreach_openssl_chacha20_evp_op
#else
#define foreach_openssl_evp_op foreach_openssl_aes_evp_op
#endif

#ifndef EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_AEAD_GET_TAG EVP_CTRL_GCM_GET_TAG
#endif

#ifndef EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_AEAD_SET_TAG EVP_CTRL_GCM_SET_TAG
#endif

#define foreach_openssl_hash_op                                               \
  _ (SHA1, EVP_sha1)                                                          \
  _ (SHA224, EVP_sha224)                                                      \
  _ (SHA256, EVP_sha256)                                                      \
  _ (SHA384, EVP_sha384)                                                      \
  _ (SHA512, EVP_sha512)

#define foreach_openssl_hmac_op \
  _(MD5, EVP_md5) \
  _(SHA1, EVP_sha1) \
  _(SHA224, EVP_sha224) \
  _(SHA256, EVP_sha256) \
  _(SHA384, EVP_sha384) \
  _(SHA512, EVP_sha512)

crypto_openssl_main_t crypto_openssl_main;

static_always_inline u32
openssl_ops_enc_cbc_hmac (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  EVP_CIPHER_CTX *enc_ctx;
  HMAC_CTX *hmac_ctx;
  u32 i;
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len = 0;
      unsigned int hmac_out_len = 0;

      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      enc_ctx = ptd->evp_cipher_enc_ctx[key->index_crypto];
      hmac_ctx = ptd->hmac_ctx[key->index_integ];
      EVP_EncryptInit_ex (enc_ctx, NULL, NULL, NULL, op->iv);
      HMAC_Init_ex (hmac_ctx, NULL, 0, NULL, NULL);

      EVP_EncryptUpdate (enc_ctx, op->dst, &out_len, op->src, op->len);
      if (out_len < op->len)
	EVP_EncryptFinal_ex (enc_ctx, op->dst + out_len, &out_len);

      HMAC_Update (hmac_ctx, op->integ_src, op->integ_len);
      HMAC_Final (hmac_ctx, buffer, &hmac_out_len);
      clib_memcpy_fast (op->digest, buffer, op->digest_len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_hmac_dec_cbc (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  HMAC_CTX *hmac_ctx;
  EVP_CIPHER_CTX *dec_ctx;
  u32 i, n_fail = 0;
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len = 0;
      unsigned int hmac_out_len = 0;

      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      hmac_ctx = ptd->hmac_ctx[key->index_integ];
      dec_ctx = ptd->evp_cipher_dec_ctx[key->index_crypto];
      HMAC_Init_ex (hmac_ctx, NULL, 0, NULL, NULL);
      EVP_DecryptInit_ex (dec_ctx, NULL, NULL, NULL, op->iv);

      HMAC_Update (hmac_ctx, op->integ_src, op->integ_len);
      HMAC_Final (hmac_ctx, buffer, &hmac_out_len);
      if ((memcmp (op->digest, buffer, op->digest_len)))
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
openssl_ops_enc_cbc_hmac_chained (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				  vnet_crypto_op_chunk_t *chunks, u32 n_ops)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  EVP_CIPHER_CTX *enc_ctx;
  HMAC_CTX *hmac_ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, curr_len = 0;
  u8 out_buf[VLIB_BUFFER_DEFAULT_DATA_SIZE * 5];
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len = 0;
      unsigned int hmac_out_len = 0;

      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      enc_ctx = ptd->evp_cipher_enc_ctx[key->index_crypto];
      hmac_ctx = ptd->hmac_ctx[key->index_integ];
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
      chp = chunks + op->integ_chunk_index;
      for (j = 0; j < op->integ_n_chunks; j++)
	{
	  HMAC_Update (hmac_ctx, chp->src, chp->len);
	  chp += 1;
	}

      HMAC_Final (hmac_ctx, buffer, &hmac_out_len);
      clib_memcpy_fast (op->digest, buffer, op->digest_len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_hmac_dec_cbc_chained (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				  vnet_crypto_op_chunk_t *chunks, u32 n_ops)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  HMAC_CTX *hmac_ctx;
  EVP_CIPHER_CTX *dec_ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, curr_len = 0, n_fail = 0;
  u8 out_buf[VLIB_BUFFER_DEFAULT_DATA_SIZE * 5];
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len = 0;
      unsigned int hmac_out_len = 0;

      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      hmac_ctx = ptd->hmac_ctx[key->index_integ];
      dec_ctx = ptd->evp_cipher_dec_ctx[key->index_crypto];
      HMAC_Init_ex (hmac_ctx, NULL, 0, NULL, NULL);
      EVP_DecryptInit_ex (dec_ctx, NULL, NULL, NULL, op->iv);

      chp = chunks + op->integ_chunk_index;
      for (j = 0; j < op->integ_n_chunks; j++)
	{
	  HMAC_Update (hmac_ctx, chp->src, chp->len);
	  chp += 1;
	}
      HMAC_Final (hmac_ctx, buffer, &hmac_out_len);
      if ((memcmp (op->digest, buffer, op->digest_len)))
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
openssl_ops_enc_cbc (vlib_main_t *vm, vnet_crypto_op_t *ops[],
		     vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		     const EVP_CIPHER *cipher, u32 fixed, u32 aad_len)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  EVP_CIPHER_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, curr_len = 0;
  u8 out_buf[VLIB_BUFFER_DEFAULT_DATA_SIZE * 5];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len = 0;

      ctx = ptd->evp_cipher_enc_ctx[op->key_index];
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
openssl_ops_dec_cbc (vlib_main_t *vm, vnet_crypto_op_t *ops[],
		     vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		     const EVP_CIPHER *cipher, u32 fixed, u32 aad_len)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  EVP_CIPHER_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, curr_len = 0;
  u8 out_buf[VLIB_BUFFER_DEFAULT_DATA_SIZE * 5];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int out_len = 0;

      ctx = ptd->evp_cipher_dec_ctx[op->key_index];
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
openssl_ops_enc_aead (vlib_main_t *vm, vnet_crypto_op_t *ops[],
		      vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		      const EVP_CIPHER *cipher, int is_gcm, int is_gmac,
		      u32 fixed, u32 aadlen)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  EVP_CIPHER_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int len = 0;
      u32 taglen = 16;

      if (i + 2 < n_ops)
	{
	  CLIB_PREFETCH (ops[i + 1]->src, 4 * CLIB_CACHE_PREFETCH_BYTES, LOAD);
	  CLIB_PREFETCH (ops[i + 1]->dst, 4 * CLIB_CACHE_PREFETCH_BYTES,
			 STORE);

	  CLIB_PREFETCH (ops[i + 2]->src, 4 * CLIB_CACHE_PREFETCH_BYTES, LOAD);
	  CLIB_PREFETCH (ops[i + 2]->dst, 4 * CLIB_CACHE_PREFETCH_BYTES,
			 STORE);
	}

      ctx = ptd->evp_cipher_enc_ctx[op->key_index];
      EVP_EncryptInit_ex (ctx, 0, 0, NULL, op->iv);
      if (!fixed)
	{
	  taglen = op->tag_len;
	  aadlen = op->aad_len;
	}

      if (aadlen)
	EVP_EncryptUpdate (ctx, NULL, &len, op->aad, aadlen);
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
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_GET_TAG, taglen, op->tag);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_enc_null_gmac (vlib_main_t *vm, vnet_crypto_op_t *ops[],
			   vnet_crypto_op_chunk_t *chunks, u32 n_ops,
			   const EVP_CIPHER *cipher, u32 fixed, u32 aadlen)
{
  return openssl_ops_enc_aead (vm, ops, chunks, n_ops, cipher,
			       /* is_gcm */ 1, /* is_gmac */ 1, fixed, aadlen);
}

static_always_inline u32
openssl_ops_enc_gcm (vlib_main_t *vm, vnet_crypto_op_t *ops[],
		     vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		     const EVP_CIPHER *cipher, u32 fixed, u32 aadlen)
{
  return openssl_ops_enc_aead (vm, ops, chunks, n_ops, cipher,
			       /* is_gcm */ 1, /* is_gmac */ 0, fixed, aadlen);
}

static_always_inline __clib_unused u32
openssl_ops_enc_chacha20_poly1305 (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				   vnet_crypto_op_chunk_t *chunks, u32 n_ops,
				   const EVP_CIPHER *cipher, u32 fixed,
				   u32 aadlen)
{
  return openssl_ops_enc_aead (vm, ops, chunks, n_ops, cipher,
			       /* is_gcm */ 0, /* is_gmac */ 0, fixed, aadlen);
}

static_always_inline u32
openssl_ops_dec_aead (vlib_main_t *vm, vnet_crypto_op_t *ops[],
		      vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		      const EVP_CIPHER *cipher, int is_gcm, int is_gmac,
		      u32 fixed, u32 aadlen)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  EVP_CIPHER_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, n_fail = 0;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      int len = 0;
      u32 taglen = 16;

      if (!fixed)
	{
	  taglen = op->tag_len;
	  aadlen = op->aad_len;
	}
      ctx = ptd->evp_cipher_dec_ctx[op->key_index];
      EVP_DecryptInit_ex (ctx, 0, 0, NULL, op->iv);
      if (op->aad_len)
	EVP_DecryptUpdate (ctx, 0, &len, op->aad, aadlen);
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
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_SET_TAG, taglen, op->tag);

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
openssl_ops_dec_null_gmac (vlib_main_t *vm, vnet_crypto_op_t *ops[],
			   vnet_crypto_op_chunk_t *chunks, u32 n_ops,
			   const EVP_CIPHER *cipher, u32 fixed, u32 aad_len)
{
  return openssl_ops_dec_aead (vm, ops, chunks, n_ops, cipher,
			       /* is_gcm */ 1, /* is_gmac */ 1, fixed,
			       aad_len);
}

static_always_inline u32
openssl_ops_dec_gcm (vlib_main_t *vm, vnet_crypto_op_t *ops[],
		     vnet_crypto_op_chunk_t *chunks, u32 n_ops,
		     const EVP_CIPHER *cipher, u32 fixed, u32 aad_len)
{
  return openssl_ops_dec_aead (vm, ops, chunks, n_ops, cipher,
			       /* is_gcm */ 1, /* is_gmac */ 0, fixed,
			       aad_len);
}

static_always_inline __clib_unused u32
openssl_ops_dec_chacha20_poly1305 (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				   vnet_crypto_op_chunk_t *chunks, u32 n_ops,
				   const EVP_CIPHER *cipher, u32 fixed,
				   u32 aad_len)
{
  return openssl_ops_dec_aead (vm, ops, chunks, n_ops, cipher,
			       /* is_gcm */ 0, /* is_gmac */ 0, fixed,
			       aad_len);
}

static_always_inline u32
openssl_ops_hash (vlib_main_t *vm, vnet_crypto_op_t *ops[],
		  vnet_crypto_op_chunk_t *chunks, u32 n_ops, const EVP_MD *md)
{
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  EVP_MD_CTX *ctx = ptd->hash_ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 md_len, i, j, n_fail = 0;

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

      EVP_DigestFinal_ex (ctx, op->digest, &md_len);
      op->digest_len = md_len;
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
}

static_always_inline u32
openssl_ops_hmac (vlib_main_t * vm, vnet_crypto_op_t * ops[],
		  vnet_crypto_op_chunk_t * chunks, u32 n_ops,
		  const EVP_MD * md)
{
  u8 buffer[64];
  openssl_per_thread_data_t *ptd = per_thread_data + vm->thread_index;
  HMAC_CTX *ctx;
  vnet_crypto_op_chunk_t *chp;
  u32 i, j, n_fail = 0;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      unsigned int out_len = 0;
      size_t sz = op->digest_len ? op->digest_len : EVP_MD_size (md);

      ctx = ptd->hmac_ctx[op->key_index];
      HMAC_Init_ex (ctx, NULL, 0, NULL, NULL);
      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  chp = chunks + op->integ_chunk_index;
	  for (j = 0; j < op->integ_n_chunks; j++)
	    {
	      HMAC_Update (ctx, chp->src, chp->len);
	      chp += 1;
	    }
	}
      else
	HMAC_Update (ctx, op->integ_src, op->integ_len);
      HMAC_Final (ctx, buffer, &out_len);

      if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	{
	  if ((memcmp (op->digest, buffer, sz)))
	    {
	      n_fail++;
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      continue;
	    }
	}
      else
	clib_memcpy_fast (op->digest, buffer, sz);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
}

static_always_inline void *
openssl_ctx_cipher (vnet_crypto_key_t *key, vnet_crypto_key_op_t kop,
		    vnet_crypto_key_index_t idx, const EVP_CIPHER *cipher,
		    int is_gcm)
{
  EVP_CIPHER_CTX *ctx;
  openssl_per_thread_data_t *ptd;

  if (VNET_CRYPTO_KEY_OP_ADD == kop)
    {
      for (ptd = per_thread_data; ptd - per_thread_data < num_threads; ptd++)
	{
	  vec_validate_aligned (ptd->evp_cipher_enc_ctx, idx,
				CLIB_CACHE_LINE_BYTES);
	  vec_validate_aligned (ptd->evp_cipher_dec_ctx, idx,
				CLIB_CACHE_LINE_BYTES);

	  ctx = EVP_CIPHER_CTX_new ();
	  EVP_CIPHER_CTX_set_padding (ctx, 0);
	  EVP_EncryptInit_ex (ctx, cipher, NULL, NULL, NULL);
	  if (is_gcm)
	    EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
	  EVP_EncryptInit_ex (ctx, 0, 0, key->data, 0);
	  ptd->evp_cipher_enc_ctx[idx] = ctx;

	  ctx = EVP_CIPHER_CTX_new ();
	  EVP_CIPHER_CTX_set_padding (ctx, 0);
	  EVP_DecryptInit_ex (ctx, cipher, 0, 0, 0);
	  if (is_gcm)
	    EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0);
	  EVP_DecryptInit_ex (ctx, 0, 0, key->data, 0);
	  ptd->evp_cipher_dec_ctx[idx] = ctx;
	}
    }
  else if (VNET_CRYPTO_KEY_OP_MODIFY == kop)
    {
      for (ptd = per_thread_data; ptd - per_thread_data < num_threads; ptd++)
	{
	  ctx = ptd->evp_cipher_enc_ctx[idx];
	  EVP_EncryptInit_ex (ctx, cipher, NULL, NULL, NULL);
	  if (is_gcm)
	    EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
	  EVP_EncryptInit_ex (ctx, 0, 0, key->data, 0);

	  ctx = ptd->evp_cipher_dec_ctx[idx];
	  EVP_DecryptInit_ex (ctx, cipher, 0, 0, 0);
	  if (is_gcm)
	    EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0);
	  EVP_DecryptInit_ex (ctx, 0, 0, key->data, 0);
	}
    }
  else if (VNET_CRYPTO_KEY_OP_DEL == kop)
    {
      for (ptd = per_thread_data; ptd - per_thread_data < num_threads; ptd++)
	{
	  ctx = ptd->evp_cipher_enc_ctx[idx];
	  EVP_CIPHER_CTX_free (ctx);
	  ptd->evp_cipher_enc_ctx[idx] = NULL;

	  ctx = ptd->evp_cipher_dec_ctx[idx];
	  EVP_CIPHER_CTX_free (ctx);
	  ptd->evp_cipher_dec_ctx[idx] = NULL;
	}
    }
  return NULL;
}

static_always_inline void *
openssl_ctx_hmac (vnet_crypto_key_t *key, vnet_crypto_key_op_t kop,
		  vnet_crypto_key_index_t idx, const EVP_MD *md)
{
  HMAC_CTX *ctx;
  openssl_per_thread_data_t *ptd;
  if (VNET_CRYPTO_KEY_OP_ADD == kop)
    {
      for (ptd = per_thread_data; ptd - per_thread_data < num_threads; ptd++)
	{
	  vec_validate_aligned (ptd->hmac_ctx, idx, CLIB_CACHE_LINE_BYTES);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	  ctx = HMAC_CTX_new ();
	  HMAC_Init_ex (ctx, key->data, key->length, md, NULL);
	  ptd->hmac_ctx[idx] = ctx;
#else
	  HMAC_CTX_init (&(ptd->_hmac_ctx));
	  ptd->hmac_ctx[idx] = &ptd->_hmac_ctx;
#endif
	}
    }
  else if (VNET_CRYPTO_KEY_OP_MODIFY == kop)
    {
      for (ptd = per_thread_data; ptd - per_thread_data < num_threads; ptd++)
	{
	  ctx = ptd->hmac_ctx[idx];
	  HMAC_Init_ex (ctx, key->data, key->length, md, NULL);
	}
    }
  else if (VNET_CRYPTO_KEY_OP_DEL == kop)
    {
      for (ptd = per_thread_data; ptd - per_thread_data < num_threads; ptd++)
	{
	  ctx = ptd->hmac_ctx[idx];
	  HMAC_CTX_free (ctx);
	  ptd->hmac_ctx[idx] = NULL;
	}
    }
  return NULL;
}

static void
crypto_openssl_key_handler (vnet_crypto_key_op_t kop,
			    vnet_crypto_key_index_t idx)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  crypto_openssl_main_t *cm = &crypto_openssl_main;

  /** TODO: add linked alg support **/
  if (key->is_link)
    return;

  if (cm->ctx_fn[key->alg] == 0)
    return;

  cm->ctx_fn[key->alg](key, kop, idx);
}

#define _(m, a, b, f, l)                                                      \
  static u32 openssl_ops_enc_##a (vlib_main_t *vm, vnet_crypto_op_t *ops[],   \
				  u32 n_ops)                                  \
  {                                                                           \
    return openssl_ops_enc_##m (vm, ops, 0, n_ops, b (), f, l);               \
  }                                                                           \
                                                                              \
  u32 openssl_ops_dec_##a (vlib_main_t *vm, vnet_crypto_op_t *ops[],          \
			   u32 n_ops)                                         \
  {                                                                           \
    return openssl_ops_dec_##m (vm, ops, 0, n_ops, b (), f, l);               \
  }                                                                           \
                                                                              \
  static u32 openssl_ops_enc_chained_##a (                                    \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return openssl_ops_enc_##m (vm, ops, chunks, n_ops, b (), f, l);          \
  }                                                                           \
                                                                              \
  static u32 openssl_ops_dec_chained_##a (                                    \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return openssl_ops_dec_##m (vm, ops, chunks, n_ops, b (), f, l);          \
  }                                                                           \
  static void *openssl_ctx_##a (vnet_crypto_key_t *key,                       \
				vnet_crypto_key_op_t kop,                     \
				vnet_crypto_key_index_t idx)                  \
  {                                                                           \
    int is_gcm = ((VNET_CRYPTO_ALG_AES_128_GCM <= key->alg) &&                \
		  (VNET_CRYPTO_ALG_AES_256_NULL_GMAC >= key->alg)) ?          \
		   1 :                                                        \
		   0;                                                         \
    return openssl_ctx_cipher (key, kop, idx, b (), is_gcm);                  \
  }

foreach_openssl_evp_op;
#undef _

#define _(a)                                                                  \
  static u32 openssl_ops_enc_##a (vlib_main_t *vm, vnet_crypto_op_t *ops[],   \
				  u32 n_ops)                                  \
  {                                                                           \
    return openssl_ops_enc_cbc_hmac (vm, ops, n_ops);                         \
  }                                                                           \
                                                                              \
  u32 openssl_ops_dec_##a (vlib_main_t *vm, vnet_crypto_op_t *ops[],          \
			   u32 n_ops)                                         \
  {                                                                           \
    return openssl_ops_hmac_dec_cbc (vm, ops, n_ops);                         \
  }                                                                           \
                                                                              \
  static u32 openssl_ops_enc_chained_##a (                                    \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return openssl_ops_enc_cbc_hmac_chained (vm, ops, chunks, n_ops);         \
  }                                                                           \
                                                                              \
  static u32 openssl_ops_dec_chained_##a (                                    \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return openssl_ops_hmac_dec_cbc_chained (vm, ops, chunks, n_ops);         \
  }

foreach_openssl_linked_evp_op;
#undef _

#define _(a, b)                                                               \
  static u32 openssl_ops_hash_##a (vlib_main_t *vm, vnet_crypto_op_t *ops[],  \
				   u32 n_ops)                                 \
  {                                                                           \
    return openssl_ops_hash (vm, ops, 0, n_ops, b ());                        \
  }                                                                           \
  static u32 openssl_ops_hash_chained_##a (                                   \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return openssl_ops_hash (vm, ops, chunks, n_ops, b ());                   \
  }

  foreach_openssl_hash_op;
#undef _

#define _(a, b)                                                               \
  static u32 openssl_ops_hmac_##a (vlib_main_t *vm, vnet_crypto_op_t *ops[],  \
				   u32 n_ops)                                 \
  {                                                                           \
    return openssl_ops_hmac (vm, ops, 0, n_ops, b ());                        \
  }                                                                           \
  static u32 openssl_ops_hmac_chained_##a (                                   \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return openssl_ops_hmac (vm, ops, chunks, n_ops, b ());                   \
  }                                                                           \
  static void *openssl_ctx_hmac_##a (vnet_crypto_key_t *key,                  \
				     vnet_crypto_key_op_t kop,                \
				     vnet_crypto_key_index_t idx)             \
  {                                                                           \
    return openssl_ctx_hmac (key, kop, idx, b ());                            \
  }

foreach_openssl_hmac_op;
#undef _

static char *
crypto_openssl_init (vnet_crypto_engine_registration_t *r)
{
  crypto_openssl_main_t *cm = &crypto_openssl_main;
  u8 seed[32];

  if (syscall (SYS_getrandom, &seed, sizeof (seed), 0) != sizeof (seed))
    return "getrandom() failed";

  num_threads = r->num_threads;

  RAND_seed (seed, sizeof (seed));

#define _(m, a, b, f, l)                                                                           \
  cm->ctx_fn[VNET_CRYPTO_ALG_##a] = openssl_ctx_##a;                                               \
  r->key_data_sz[VNET_CRYPTO_ALG_##a] = sizeof (openssl_per_thread_data_t);
  foreach_openssl_evp_op;
#undef _

#define _(a, b)                                                                                    \
  cm->ctx_fn[VNET_CRYPTO_ALG_HMAC_##a] = openssl_ctx_hmac_##a;                                     \
  r->key_data_sz[VNET_CRYPTO_ALG_HMAC_##a] = sizeof (openssl_per_thread_data_t);
  foreach_openssl_hmac_op;
#undef _

  per_thread_data = r->per_thread_data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  for (u32 i = 0; i < r->num_threads; i++)
    per_thread_data[i].hash_ctx = EVP_MD_CTX_create ();
#endif
  return 0;
}

vnet_crypto_engine_op_handlers_t op_handlers[] = {
#define _(m, a, b, f, l)                                                      \
  {                                                                           \
    .opt = VNET_CRYPTO_OP_##a##_ENC,                                          \
    .fn = openssl_ops_enc_##a,                                                \
    .cfn = openssl_ops_enc_chained_##a,                                       \
  },                                                                          \
    { .opt = VNET_CRYPTO_OP_##a##_DEC,                                        \
      .fn = openssl_ops_dec_##a,                                              \
      .cfn = openssl_ops_dec_chained_##a },
  foreach_openssl_evp_op
#undef _
#define _(a)                                                                  \
  {                                                                           \
    .opt = VNET_CRYPTO_OP_##a##_ENC,                                          \
    .fn = openssl_ops_enc_##a,                                                \
    .cfn = openssl_ops_enc_chained_##a,                                       \
  },                                                                          \
    { .opt = VNET_CRYPTO_OP_##a##_DEC,                                        \
      .fn = openssl_ops_dec_##a,                                              \
      .cfn = openssl_ops_dec_chained_##a },
    foreach_openssl_linked_evp_op
#undef _
#define _(a, b)                                                               \
  { .opt = VNET_CRYPTO_OP_##a##_HMAC,                                         \
    .fn = openssl_ops_hmac_##a,                                               \
    .cfn = openssl_ops_hmac_chained_##a },
      foreach_openssl_hmac_op
#undef _
#define _(a, b)                                                               \
  { .opt = VNET_CRYPTO_OP_##a##_HASH,                                         \
    .fn = openssl_ops_hash_##a,                                               \
    .cfn = openssl_ops_hash_chained_##a },
	foreach_openssl_hash_op
#undef _
  {}
};

VNET_CRYPTO_ENGINE_REGISTRATION () = {
  .name = "openssl",
  .desc = "OpenSSL",
  .prio = 50,
  .per_thread_data_sz = sizeof (openssl_per_thread_data_t),
  .init_fn = crypto_openssl_init,
  .key_handler = crypto_openssl_key_handler,
  .op_handlers = op_handlers,
};
