/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#ifndef included_vnet_crypto_crypto_h
#define included_vnet_crypto_crypto_h

#include <vlib/vlib.h>
#include <vnet/buffer.h>

typedef struct
{
  u32 cipher_data_len;
  u32 auth_data_len;
  i16 cipher_data_start_off;
  i16 auth_data_start_off;
  i16 iv_off;
  i16 icv_off;
  i16 aad_off;
  u8 aad_len;
  u8 icv_len;
  u8 is_hmac_check : 1;
  u8 is_chained_buffers : 1;
} vnet_crypto_buffer_metadata_t;

STATIC_ASSERT_SIZEOF (vnet_crypto_buffer_metadata_t, 6 * sizeof (u32));

static_always_inline vnet_crypto_buffer_metadata_t *
vnet_crypto_buffer_get_metadata (vlib_buffer_t *b)
{
  return (void *) vnet_buffer2 (b)->unused;
}

static_always_inline u8 *
vnet_crypto_buffer_metadata_get_ptr (vlib_main_t *vm, vlib_buffer_t *b, i16 off)
{
  i16 current_length = b->current_length;

  if (PREDICT_TRUE (off < current_length))
    return vlib_buffer_get_current (b) + off;

  off -= current_length;
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      current_length = b->current_length;
      if (off < current_length)
	return vlib_buffer_get_current (b) + off;
      off -= current_length;
    }

  ASSERT (off == 0);
  return vlib_buffer_get_tail (b);
}

static_always_inline i16
vnet_crypto_buffer_metadata_pre_data_off (vlib_buffer_t *b)
{
  return -b->current_data - VLIB_BUFFER_PRE_DATA_SIZE;
}

#ifdef VNET_CRYPTO_LOG_MACROS
#define log_debug(f, ...)  vlib_log (VLIB_LOG_LEVEL_DEBUG, crypto_log.class, f, ##__VA_ARGS__)
#define log_notice(f, ...) vlib_log (VLIB_LOG_LEVEL_NOTICE, crypto_log.class, f, ##__VA_ARGS__)
#define log_err(f, ...)	   vlib_log (VLIB_LOG_LEVEL_ERR, crypto_log.class, f, ##__VA_ARGS__)
#endif

#define VNET_CRYPTO_FRAME_SIZE 64
#define VNET_CRYPTO_FRAME_POOL_SIZE 1024

/* CRYPTO_ID, PRETTY_NAME, FAMILY, KEY_LEN, BLOCK_LEN */
#define foreach_crypto_cipher_alg_non_ctr                                                          \
  _ (DES_CBC, "des-cbc", DES_CBC, 7, 8)                                                            \
  _ (3DES_CBC, "3des-cbc", TDES_CBC, 24, 8)                                                        \
  _ (AES_128_CBC, "aes-128-cbc", AES_CBC, 16, 16)                                                  \
  _ (AES_192_CBC, "aes-192-cbc", AES_CBC, 24, 16)                                                  \
  _ (AES_256_CBC, "aes-256-cbc", AES_CBC, 32, 16)

#define foreach_crypto_cipher_alg_ctr                                                              \
  _ (AES_128_CTR, "aes-128-ctr", AES_CTR, 16, 16)                                                  \
  _ (AES_192_CTR, "aes-192-ctr", AES_CTR, 24, 16)                                                  \
  _ (AES_256_CTR, "aes-256-ctr", AES_CTR, 32, 16)

/* CRYPTO_ID, PRETTY_NAME, FAMILY, KEY_LEN, BLOCK_LEN */
#define foreach_crypto_aead_alg                                                                    \
  _ (AES_128_GCM, "aes-128-gcm", AES_GCM, 16, 16)                                                  \
  _ (AES_192_GCM, "aes-192-gcm", AES_GCM, 24, 16)                                                  \
  _ (AES_256_GCM, "aes-256-gcm", AES_GCM, 32, 16)                                                  \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac", AES_NULL_GMAC, 16, 16)                                \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac", AES_NULL_GMAC, 24, 16)                                \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac", AES_NULL_GMAC, 32, 16)                                \
  _ (CHACHA20_POLY1305, "chacha20-poly1305", CHACHA20_POLY1305, 32, 64)

#define foreach_crypto_hash_alg                                                                    \
  _ (MD5, "md5", NONE, MD5, 16, 64)                                                                \
  _ (SHA1_160, "sha1-160", NONE, SHA1, 20, 64)                                                     \
  _ (SHA_224, "sha2-224", NONE, SHA2, 28, 64)                                                      \
  _ (SHA_256, "sha2-256", NONE, SHA2, 32, 64)                                                      \
  _ (SHA_384, "sha2-384", NONE, SHA2, 48, 128)                                                     \
  _ (SHA_512, "sha2-512", NONE, SHA2, 64, 128)

/* CRYPTO_ID, PRETTY_NAME, CIPHER_FAMILY, AUTH_FAMILY, ICV_LEN, BLOCK_LEN */
#define foreach_crypto_hash_fixed_alg                                                              \
  _ (MD5_ICV12, "md5-icv12", NONE, MD5, 12, 64)                                                    \
  _ (SHA1_160_ICV12, "sha1-160-icv12", NONE, SHA1, 12, 64)                                         \
  _ (SHA_256_ICV12, "sha2-256-icv12", NONE, SHA2, 12, 64)                                          \
  _ (SHA_256_ICV16, "sha2-256-icv16", NONE, SHA2, 16, 64)                                          \
  _ (SHA_384_ICV24, "sha2-384-icv24", NONE, SHA2, 24, 128)                                         \
  _ (SHA_512_ICV32, "sha2-512-icv32", NONE, SHA2, 32, 128)

#define foreach_crypto_op_type                                                                     \
  _ (ENCRYPT, "encrypt")                                                                           \
  _ (DECRYPT, "decrypt")                                                                           \
  _ (HMAC, "hmac")

typedef enum
{
#define _(n, s) VNET_CRYPTO_OP_TYPE_##n,
  foreach_crypto_op_type
#undef _
    VNET_CRYPTO_OP_N_TYPES,
} __clib_packed vnet_crypto_op_type_t;

typedef struct
{
  u16 next_node_index;
  vnet_crypto_op_type_t op_type;
} vnet_crypto_deq_scalar_data_t;

static_always_inline void
vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar (
  vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u64 *aux_data, u16 next_index,
  u32 count, vnet_crypto_deq_scalar_data_t *scalar_data)
{
  vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar_size (
    vm, node, buffers, aux_data, scalar_data, sizeof (*scalar_data), next_index, count);
}

#define foreach_crypto_op_status                                                                   \
  _ (0, UNPROCESSED, "unprocessed")                                                                \
  _ (1, PENDING, "pending")                                                                        \
  _ (2, WORK_IN_PROGRESS, "work-in-progress")                                                      \
  _ (3, COMPLETED, "completed")                                                                    \
  _ (4, FAIL_NO_HANDLER, "no-handler")                                                             \
  _ (5, FAIL_BAD_HMAC, "bad-hmac")                                                                 \
  _ (6, FAIL_ENGINE_ERR, "engine-error")

/** async crypto **/

/* CRYPTO_ID, PRETTY_NAME, FAMILY, KEY_LEN, ICV_LEN, AAD_LEN, BLOCK_LEN */
#define foreach_crypto_aead_async_alg                                                              \
  _ (AES_128_GCM, "aes-128-gcm-icv16-aad8", AES_GCM, 16, 16, 8, 16)                                \
  _ (AES_128_GCM, "aes-128-gcm-icv16-aad12", AES_GCM, 16, 16, 12, 16)                              \
  _ (AES_192_GCM, "aes-192-gcm-icv16-aad8", AES_GCM, 24, 16, 8, 16)                                \
  _ (AES_192_GCM, "aes-192-gcm-icv16-aad12", AES_GCM, 24, 16, 12, 16)                              \
  _ (AES_256_GCM, "aes-256-gcm-icv16-aad8", AES_GCM, 32, 16, 8, 16)                                \
  _ (AES_256_GCM, "aes-256-gcm-icv16-aad12", AES_GCM, 32, 16, 12, 16)                              \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac-icv16-aad8", AES_NULL_GMAC, 16, 16, 8, 16)              \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac-icv16-aad12", AES_NULL_GMAC, 16, 16, 12, 16)            \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac-icv16-aad8", AES_NULL_GMAC, 24, 16, 8, 16)              \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac-icv16-aad12", AES_NULL_GMAC, 24, 16, 12, 16)            \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac-icv16-aad8", AES_NULL_GMAC, 32, 16, 8, 16)              \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac-icv16-aad12", AES_NULL_GMAC, 32, 16, 12, 16)            \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-icv16-aad8", CHACHA20_POLY1305, 32, 16, 8, 64)          \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-icv16-aad12", CHACHA20_POLY1305, 32, 16, 12, 64)        \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-icv16-aad0", CHACHA20_POLY1305, 32, 16, 0, 64)

/* CRYPTO_ID, AUTH_ID, PRETTY_NAME, CIPHER_FAMILY, AUTH_FAMILY, KEY_LEN, AUTH_LEN, AUTH_KEY_LEN,
   BLOCK_LEN */
#define foreach_crypto_combined_alg_non_ctr                                                        \
  _ (3DES_CBC, MD5, "3des-cbc-md5", TDES_CBC, MD5, 24, 16, 64, 8)                                  \
  _ (AES_128_CBC, MD5, "aes-128-cbc-md5", AES_CBC, MD5, 16, 16, 64, 16)                            \
  _ (AES_192_CBC, MD5, "aes-192-cbc-md5", AES_CBC, MD5, 24, 16, 64, 16)                            \
  _ (AES_256_CBC, MD5, "aes-256-cbc-md5", AES_CBC, MD5, 32, 16, 64, 16)                            \
  _ (3DES_CBC, SHA1_160, "3des-cbc-sha1-160", TDES_CBC, SHA1, 24, 20, 64, 8)                       \
  _ (AES_128_CBC, SHA1_160, "aes-128-cbc-sha1-160", AES_CBC, SHA1, 16, 20, 64, 16)                 \
  _ (AES_192_CBC, SHA1_160, "aes-192-cbc-sha1-160", AES_CBC, SHA1, 24, 20, 64, 16)                 \
  _ (AES_256_CBC, SHA1_160, "aes-256-cbc-sha1-160", AES_CBC, SHA1, 32, 20, 64, 16)                 \
  _ (3DES_CBC, SHA_224, "3des-cbc-sha2-224", TDES_CBC, SHA2, 24, 28, 64, 8)                        \
  _ (AES_128_CBC, SHA_224, "aes-128-cbc-sha2-224", AES_CBC, SHA2, 16, 28, 64, 16)                  \
  _ (AES_192_CBC, SHA_224, "aes-192-cbc-sha2-224", AES_CBC, SHA2, 24, 28, 64, 16)                  \
  _ (AES_256_CBC, SHA_224, "aes-256-cbc-sha2-224", AES_CBC, SHA2, 32, 28, 64, 16)                  \
  _ (3DES_CBC, SHA_256, "3des-cbc-sha2-256", TDES_CBC, SHA2, 24, 32, 64, 8)                        \
  _ (AES_128_CBC, SHA_256, "aes-128-cbc-sha2-256", AES_CBC, SHA2, 16, 32, 64, 16)                  \
  _ (AES_192_CBC, SHA_256, "aes-192-cbc-sha2-256", AES_CBC, SHA2, 24, 32, 64, 16)                  \
  _ (AES_256_CBC, SHA_256, "aes-256-cbc-sha2-256", AES_CBC, SHA2, 32, 32, 64, 16)                  \
  _ (3DES_CBC, SHA_384, "3des-cbc-sha2-384", TDES_CBC, SHA2, 24, 48, 128, 8)                       \
  _ (AES_128_CBC, SHA_384, "aes-128-cbc-sha2-384", AES_CBC, SHA2, 16, 48, 128, 16)                 \
  _ (AES_192_CBC, SHA_384, "aes-192-cbc-sha2-384", AES_CBC, SHA2, 24, 48, 128, 16)                 \
  _ (AES_256_CBC, SHA_384, "aes-256-cbc-sha2-384", AES_CBC, SHA2, 32, 48, 128, 16)                 \
  _ (3DES_CBC, SHA_512, "3des-cbc-sha2-512", TDES_CBC, SHA2, 24, 64, 128, 8)                       \
  _ (AES_128_CBC, SHA_512, "aes-128-cbc-sha2-512", AES_CBC, SHA2, 16, 64, 128, 16)                 \
  _ (AES_192_CBC, SHA_512, "aes-192-cbc-sha2-512", AES_CBC, SHA2, 24, 64, 128, 16)                 \
  _ (AES_256_CBC, SHA_512, "aes-256-cbc-sha2-512", AES_CBC, SHA2, 32, 64, 128, 16)

#define foreach_crypto_combined_alg_ctr                                                            \
  _ (AES_128_CTR, SHA1_160, "aes-128-ctr-sha1-160", AES_CTR, SHA1, 16, 20, 64, 16)                 \
  _ (AES_192_CTR, SHA1_160, "aes-192-ctr-sha1-160", AES_CTR, SHA1, 24, 20, 64, 16)                 \
  _ (AES_256_CTR, SHA1_160, "aes-256-ctr-sha1-160", AES_CTR, SHA1, 32, 20, 64, 16)                 \
  _ (AES_128_CTR, SHA_256, "aes-128-ctr-sha2-256", AES_CTR, SHA2, 16, 32, 64, 16)                  \
  _ (AES_192_CTR, SHA_256, "aes-192-ctr-sha2-256", AES_CTR, SHA2, 24, 32, 64, 16)                  \
  _ (AES_256_CTR, SHA_256, "aes-256-ctr-sha2-256", AES_CTR, SHA2, 32, 32, 64, 16)                  \
  _ (AES_128_CTR, SHA_384, "aes-128-ctr-sha2-384", AES_CTR, SHA2, 16, 48, 128, 16)                 \
  _ (AES_192_CTR, SHA_384, "aes-192-ctr-sha2-384", AES_CTR, SHA2, 24, 48, 128, 16)                 \
  _ (AES_256_CTR, SHA_384, "aes-256-ctr-sha2-384", AES_CTR, SHA2, 32, 48, 128, 16)                 \
  _ (AES_128_CTR, SHA_512, "aes-128-ctr-sha2-512", AES_CTR, SHA2, 16, 64, 128, 16)                 \
  _ (AES_192_CTR, SHA_512, "aes-192-ctr-sha2-512", AES_CTR, SHA2, 24, 64, 128, 16)                 \
  _ (AES_256_CTR, SHA_512, "aes-256-ctr-sha2-512", AES_CTR, SHA2, 32, 64, 128, 16)

#define foreach_crypto_combined_alg                                                                \
  foreach_crypto_combined_alg_non_ctr foreach_crypto_combined_alg_ctr

/* CRYPTO_ID, AUTH_ID, PRETTY_NAME, CIPHER_FAMILY, AUTH_FAMILY, KEY_LEN, AUTH_LEN, AUTH_KEY_LEN,
   BLOCK_LEN */
#define foreach_crypto_combined_fixed_alg_non_ctr                                                  \
  _ (3DES_CBC, MD5, "3des-cbc-md5-icv12", TDES_CBC, MD5, 24, 12, 64, 8)                            \
  _ (AES_128_CBC, MD5, "aes-128-cbc-md5-icv12", AES_CBC, MD5, 16, 12, 64, 16)                      \
  _ (AES_192_CBC, MD5, "aes-192-cbc-md5-icv12", AES_CBC, MD5, 24, 12, 64, 16)                      \
  _ (AES_256_CBC, MD5, "aes-256-cbc-md5-icv12", AES_CBC, MD5, 32, 12, 64, 16)                      \
  _ (3DES_CBC, SHA1_160, "3des-cbc-sha1-160-icv12", TDES_CBC, SHA1, 24, 12, 64, 8)                 \
  _ (AES_128_CBC, SHA1_160, "aes-128-cbc-sha1-160-icv12", AES_CBC, SHA1, 16, 12, 64, 16)           \
  _ (AES_192_CBC, SHA1_160, "aes-192-cbc-sha1-160-icv12", AES_CBC, SHA1, 24, 12, 64, 16)           \
  _ (AES_256_CBC, SHA1_160, "aes-256-cbc-sha1-160-icv12", AES_CBC, SHA1, 32, 12, 64, 16)           \
  _ (3DES_CBC, SHA_224, "3des-cbc-sha2-224-icv14", TDES_CBC, SHA2, 24, 14, 64, 8)                  \
  _ (AES_128_CBC, SHA_224, "aes-128-cbc-sha2-224-icv14", AES_CBC, SHA2, 16, 14, 64, 16)            \
  _ (AES_192_CBC, SHA_224, "aes-192-cbc-sha2-224-icv14", AES_CBC, SHA2, 24, 14, 64, 16)            \
  _ (AES_256_CBC, SHA_224, "aes-256-cbc-sha2-224-icv14", AES_CBC, SHA2, 32, 14, 64, 16)            \
  _ (3DES_CBC, SHA_256, "3des-cbc-sha2-256-icv12", TDES_CBC, SHA2, 24, 12, 64, 8)                  \
  _ (AES_128_CBC, SHA_256, "aes-128-cbc-sha2-256-icv12", AES_CBC, SHA2, 16, 12, 64, 16)            \
  _ (AES_192_CBC, SHA_256, "aes-192-cbc-sha2-256-icv12", AES_CBC, SHA2, 24, 12, 64, 16)            \
  _ (AES_256_CBC, SHA_256, "aes-256-cbc-sha2-256-icv12", AES_CBC, SHA2, 32, 12, 64, 16)            \
  _ (3DES_CBC, SHA_256, "3des-cbc-sha2-256-icv16", TDES_CBC, SHA2, 24, 16, 64, 8)                  \
  _ (AES_128_CBC, SHA_256, "aes-128-cbc-sha2-256-icv16", AES_CBC, SHA2, 16, 16, 64, 16)            \
  _ (AES_192_CBC, SHA_256, "aes-192-cbc-sha2-256-icv16", AES_CBC, SHA2, 24, 16, 64, 16)            \
  _ (AES_256_CBC, SHA_256, "aes-256-cbc-sha2-256-icv16", AES_CBC, SHA2, 32, 16, 64, 16)            \
  _ (3DES_CBC, SHA_384, "3des-cbc-sha2-384-icv24", TDES_CBC, SHA2, 24, 24, 128, 8)                 \
  _ (AES_128_CBC, SHA_384, "aes-128-cbc-sha2-384-icv24", AES_CBC, SHA2, 16, 24, 128, 16)           \
  _ (AES_192_CBC, SHA_384, "aes-192-cbc-sha2-384-icv24", AES_CBC, SHA2, 24, 24, 128, 16)           \
  _ (AES_256_CBC, SHA_384, "aes-256-cbc-sha2-384-icv24", AES_CBC, SHA2, 32, 24, 128, 16)           \
  _ (3DES_CBC, SHA_512, "3des-cbc-sha2-512-icv32", TDES_CBC, SHA2, 24, 32, 128, 8)                 \
  _ (AES_128_CBC, SHA_512, "aes-128-cbc-sha2-512-icv32", AES_CBC, SHA2, 16, 32, 128, 16)           \
  _ (AES_192_CBC, SHA_512, "aes-192-cbc-sha2-512-icv32", AES_CBC, SHA2, 24, 32, 128, 16)           \
  _ (AES_256_CBC, SHA_512, "aes-256-cbc-sha2-512-icv32", AES_CBC, SHA2, 32, 32, 128, 16)

#define foreach_crypto_combined_fixed_alg_ctr                                                      \
  _ (AES_128_CTR, SHA1_160, "aes-128-ctr-sha1-160-icv12", AES_CTR, SHA1, 16, 12, 64, 16)           \
  _ (AES_192_CTR, SHA1_160, "aes-192-ctr-sha1-160-icv12", AES_CTR, SHA1, 24, 12, 64, 16)           \
  _ (AES_256_CTR, SHA1_160, "aes-256-ctr-sha1-160-icv12", AES_CTR, SHA1, 32, 12, 64, 16)           \
  _ (AES_128_CTR, SHA_256, "aes-128-ctr-sha2-256-icv12", AES_CTR, SHA2, 16, 12, 64, 16)            \
  _ (AES_192_CTR, SHA_256, "aes-192-ctr-sha2-256-icv12", AES_CTR, SHA2, 24, 12, 64, 16)            \
  _ (AES_256_CTR, SHA_256, "aes-256-ctr-sha2-256-icv12", AES_CTR, SHA2, 32, 12, 64, 16)            \
  _ (AES_128_CTR, SHA_256, "aes-128-ctr-sha2-256-icv16", AES_CTR, SHA2, 16, 16, 64, 16)            \
  _ (AES_192_CTR, SHA_256, "aes-192-ctr-sha2-256-icv16", AES_CTR, SHA2, 24, 16, 64, 16)            \
  _ (AES_256_CTR, SHA_256, "aes-256-ctr-sha2-256-icv16", AES_CTR, SHA2, 32, 16, 64, 16)            \
  _ (AES_128_CTR, SHA_384, "aes-128-ctr-sha2-384-icv24", AES_CTR, SHA2, 16, 24, 128, 16)           \
  _ (AES_192_CTR, SHA_384, "aes-192-ctr-sha2-384-icv24", AES_CTR, SHA2, 24, 24, 128, 16)           \
  _ (AES_256_CTR, SHA_384, "aes-256-ctr-sha2-384-icv24", AES_CTR, SHA2, 32, 24, 128, 16)           \
  _ (AES_128_CTR, SHA_512, "aes-128-ctr-sha2-512-icv32", AES_CTR, SHA2, 16, 32, 128, 16)           \
  _ (AES_192_CTR, SHA_512, "aes-192-ctr-sha2-512-icv32", AES_CTR, SHA2, 24, 32, 128, 16)           \
  _ (AES_256_CTR, SHA_512, "aes-256-ctr-sha2-512-icv32", AES_CTR, SHA2, 32, 32, 128, 16)

#define foreach_crypto_combined_fixed_alg                                                          \
  foreach_crypto_combined_fixed_alg_non_ctr foreach_crypto_combined_fixed_alg_ctr

#define foreach_crypto_alg_family                                                                  \
  _ (DES_CBC, "des-cbc")                                                                           \
  _ (TDES_CBC, "3des-cbc")                                                                         \
  _ (AES_CBC, "aes-cbc")                                                                           \
  _ (AES_CTR, "aes-ctr")                                                                           \
  _ (AES_GCM, "aes-gcm")                                                                           \
  _ (AES_NULL_GMAC, "aes-null-gmac")                                                               \
  _ (CHACHA20_POLY1305, "chacha20-poly1305")                                                       \
  _ (MD5, "md5")                                                                                   \
  _ (SHA1, "sha-1")                                                                                \
  _ (SHA2, "sha-2")

typedef enum
{
#define _(v, n, s) VNET_CRYPTO_OP_STATUS_##n = (v),
  foreach_crypto_op_status
#undef _
    VNET_CRYPTO_OP_N_STATUS,
} __clib_packed vnet_crypto_op_status_t;

#define foreach_crypto_handler_type                                                                \
  _ (SIMPLE, "simple")                                                                             \
  _ (CHAINED, "chained")                                                                           \
  _ (ASYNC, "async")

typedef enum
{
#define _(n, s) VNET_CRYPTO_HANDLER_TYPE_##n,
  foreach_crypto_handler_type
#undef _
    VNET_CRYPTO_HANDLER_N_TYPES

} __clib_packed vnet_crypto_handler_type_t;

typedef enum
{
  VNET_CRYPTO_ALG_NONE = 0,
#define _(n, s, f, k, b) VNET_CRYPTO_ALG_##n,
  foreach_crypto_cipher_alg_non_ctr foreach_crypto_cipher_alg_ctr
#undef _
#define _(n, s, f, k, b) VNET_CRYPTO_ALG_##n,
    foreach_crypto_aead_alg
#undef _
#define _(n, s, cf, inf, d, b) VNET_CRYPTO_ALG_##n,
      foreach_crypto_hash_alg
#undef _
#define _(n, s, cf, inf, d, b) VNET_CRYPTO_ALG_##n,
	foreach_crypto_hash_fixed_alg
#undef _
#define _(n, s, f, k, t, a, b) VNET_CRYPTO_ALG_##n##_ICV##t##_AAD##a,
	  foreach_crypto_aead_async_alg
#undef _
#define _(c, h, s, cf, inf, k, d, ak, b) VNET_CRYPTO_ALG_##c##_##h,
	    foreach_crypto_combined_alg
#undef _
#define _(c, h, s, cf, inf, k, d, ak, b) VNET_CRYPTO_ALG_##c##_##h##_ICV##d,
	      foreach_crypto_combined_fixed_alg
#undef _
		VNET_CRYPTO_N_ALGS,
} __clib_packed vnet_crypto_alg_t;

typedef enum
{
  VNET_CRYPTO_ALG_FAMILY_NONE = 0,
#define _(n, s) VNET_CRYPTO_ALG_FAMILY_##n,
  foreach_crypto_alg_family
#undef _
    VNET_CRYPTO_N_ALG_FAMILIES,
} __clib_packed vnet_crypto_alg_family_t;

typedef u8 vnet_crypto_engine_id_t;

#define VNET_CRYPTO_ENGINE_ID_NONE    ((vnet_crypto_engine_id_t) 0)
#define VNET_CRYPTO_ENGINE_ID_INVALID ((vnet_crypto_engine_id_t) ~0)

typedef struct
{
  u32 index;
  u16 cipher_key_sz;
  u16 auth_key_sz;
  u16 auth_key_offset;
  u16 cipher_key_offset;
  u16 key_data_offset[VNET_CRYPTO_HANDLER_N_TYPES];
  u16 key_data_stride[VNET_CRYPTO_HANDLER_N_TYPES];
  u16 total_data_sz;
  vnet_crypto_engine_id_t engine_index[VNET_CRYPTO_HANDLER_N_TYPES];
  void *handlers[VNET_CRYPTO_OP_N_TYPES][VNET_CRYPTO_HANDLER_N_TYPES];
  vnet_crypto_alg_t alg : 8;
  u8 indirect_auth_key : 1;
  u8 _data[] __clib_aligned (64);
} __clib_aligned (64)
vnet_crypto_ctx_t;

typedef struct
{
  u16 cipher_key_len;
  u16 auth_key_len;
  u16 key_data_offset[VNET_CRYPTO_HANDLER_N_TYPES];
  u16 key_data_size[VNET_CRYPTO_HANDLER_N_TYPES];
  u16 total_key_data_size;
} vnet_crypto_ctx_layout_t;

static_always_inline const u8 *
vnet_crypto_get_cipher_key (const vnet_crypto_ctx_t *ctx)
{
  return ctx->_data + ctx->cipher_key_offset;
}

static_always_inline const u8 *
vnet_crypto_get_auth_key (const vnet_crypto_ctx_t *ctx)
{
  if (ctx->indirect_auth_key)
    return *(u8 *const *) (ctx->_data + ctx->auth_key_offset);
  return ctx->_data + ctx->auth_key_offset;
}

typedef struct vnet_crypto_alg_data_t_ vnet_crypto_alg_data_t;
typedef enum
{
  VNET_CRYPTO_ALG_T_NONE = 0,
  VNET_CRYPTO_ALG_T_AEAD,
  VNET_CRYPTO_ALG_T_AUTH,
  VNET_CRYPTO_ALG_T_CIPHER,
  VNET_CRYPTO_ALG_T_COMBINED,
} __clib_packed vnet_crypto_alg_type_t;

typedef struct
{
  u8 *src;
  u8 *dst;
  u32 len;
} vnet_crypto_op_chunk_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 user_data;
  union
  {
    u32 len;

    /* valid if VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS is set */
    u16 n_chunks;
  };
  union
  {
    struct
    {
      u8 *src;
      u8 *dst;
    };

    /* valid if VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS is set */
    struct
    {
      u32 chunk_index;
      u32 auth_chunk_index;
    };
  };

  vnet_crypto_ctx_t *ctx;
  u8 *iv;

  union
  {
    u8 *auth_src;
    u8 *aad;
  };

  u8 *auth;
  union
  {
    u16 auth_src_len;
    u16 auth_n_chunks;
    u16 aad_len;
  };

  vnet_crypto_op_type_t type;
  u8 status : 4;
  u8 flags : 4;
#define VNET_CRYPTO_OP_FLAG_HMAC_CHECK	    (1 << 0)
#define VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS (1 << 1)

  u8 auth_len;
} vnet_crypto_op_t;

STATIC_ASSERT_SIZEOF (vnet_crypto_op_t, CLIB_CACHE_LINE_BYTES);

static_always_inline vnet_crypto_engine_id_t
vnet_crypto_ctx_get_engine (vnet_crypto_ctx_t *ctx, vnet_crypto_handler_type_t t)
{
  return ctx->engine_index[t];
}

typedef enum vnet_crypto_async_frame_state_t_
{
  VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED,
  /* frame waiting to be processed */
  VNET_CRYPTO_FRAME_STATE_PENDING,
  VNET_CRYPTO_FRAME_STATE_WORK_IN_PROGRESS,
  VNET_CRYPTO_FRAME_STATE_COMPLETED,
} __clib_packed vnet_crypto_async_frame_state_t;

#define VNET_CRYPTO_ASYNC_FRAME_BITMAP_N_UWORDS                                                    \
  (((VNET_CRYPTO_FRAME_SIZE + uword_bits - 1) & ~(uword_bits - 1)) / uword_bits)

typedef uword vnet_crypto_async_frame_bitmap_t[VNET_CRYPTO_ASYNC_FRAME_BITMAP_N_UWORDS];

static_always_inline u32
vnet_crypto_async_frame_bitmap_count_set_bits (vnet_crypto_async_frame_bitmap_t bitmap)
{
  return uword_bitmap_count_set_bits (bitmap, VNET_CRYPTO_ASYNC_FRAME_BITMAP_N_UWORDS);
}

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_async_frame_state_t state;
  vnet_crypto_alg_t alg : 8;
  vnet_crypto_op_type_t type : 8;
  u8 n_elts;
  vnet_crypto_ctx_t *ctxs[VNET_CRYPTO_FRAME_SIZE];
  u32 buffer_indices[VNET_CRYPTO_FRAME_SIZE];
  u16 next_node_index[VNET_CRYPTO_FRAME_SIZE];
  vnet_crypto_async_frame_bitmap_t bad_hmac_bitmap;
  vnet_crypto_async_frame_bitmap_t engine_error_bitmap;
  clib_thread_index_t enqueue_thread_index;
} vnet_crypto_async_frame_t;

static_always_inline void
vlib_crypto_async_frame_set_hmac_fail (vnet_crypto_async_frame_t *f, u32 elt_index)
{
  uword_bitmap_set_bits_at_index (f->bad_hmac_bitmap, elt_index, 1);
  ;
}

static_always_inline void
vlib_crypto_async_frame_set_engine_error (vnet_crypto_async_frame_t *f, u32 elt_index)
{
  uword_bitmap_set_bits_at_index (f->engine_error_bitmap, elt_index, 1);
  ;
}

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_async_frame_t *frame_pool;
  clib_spinlock_t free_frames_lock;
  clib_spinlock_t completed_frames_lock;
  vnet_crypto_async_frame_t **free_frames;
  vnet_crypto_async_frame_t **completed_frames;
  u32 *buffer_indices;
  u16 *nexts;
} vnet_crypto_thread_t;

typedef u32 (vnet_crypto_sync_op_fn_t) (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
					u32 n_ops, clib_thread_index_t thread_index);
typedef u8 *vnet_crypto_key_data_t __clib_aligned (64);
typedef u8 *vnet_crypto_thread_key_data_t __clib_aligned (16);

typedef enum
{
  VNET_CRYPTO_KEY_UNKNOWN_ACTION = 0,
  VNET_CRYPTO_KEY_DATA_ADD,
  VNET_CRYPTO_KEY_DATA_REMOVE,
  VNET_CRYPTO_THREAD_KEY_DATA_ADD,
  VNET_CRYPTO_THREAD_KEY_DATA_REMOVE,
} __clib_packed vnet_crypto_key_action_t;

typedef struct
{
  vnet_crypto_handler_type_t handler_type;
  vnet_crypto_key_action_t action;
  clib_thread_index_t thread_index;
  union
  {
    vnet_crypto_key_data_t key_data;
    vnet_crypto_thread_key_data_t thread_key_data;
  };
} vnet_crypto_key_change_args_t;

typedef void (vnet_crypto_key_change_fn_t) (vnet_crypto_ctx_t *ctx,
					    vnet_crypto_key_change_args_t *args);

typedef struct vnet_crypto_alg_data_t_
{
  char *name;
  u16 cipher_key_len;
  u16 auth_key_len;
  u8 block_len;
  vnet_crypto_alg_type_t alg_type;
  vnet_crypto_alg_family_t cipher_family;
  vnet_crypto_alg_family_t auth_family;
  u8 aad_len;
  u8 auth_len;
  u8 variable_aad_len : 1;
  u8 variable_auth_key_len : 1;
  vnet_crypto_key_change_fn_t *key_change_fn[VNET_CRYPTO_HANDLER_N_TYPES];
  u16 key_data_sz[VNET_CRYPTO_HANDLER_N_TYPES];
  vnet_crypto_engine_id_t key_fn_engine[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_alg_data_t;

#include <vnet/crypto/hash.h>

/** async crypto function handlers **/
typedef int (vnet_crypto_frame_enq_fn_t) (vlib_main_t *vm,
					  vnet_crypto_async_frame_t *frame);
typedef vnet_crypto_async_frame_t *(
  vnet_crypto_frame_dequeue_t) (vlib_main_t *vm, u32 *nb_elts_processed,
				clib_thread_index_t *enqueue_thread_idx);

vnet_crypto_engine_id_t vnet_crypto_register_engine (vlib_main_t *vm, char *name, int prio,
						     char *desc);
vnet_crypto_engine_id_t vnet_crypto_get_engine_index_by_name (const char *fmt, ...);

int vnet_crypto_register_key_change_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					     vnet_crypto_key_change_fn_t *key_change_fn,
					     u16 key_data_sz);

/** async crypto register functions */
u32 vnet_crypto_register_post_node (vlib_main_t * vm, char *post_node_name);

void vnet_crypto_register_enqueue_handler_by_alg (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
						  vnet_crypto_alg_t alg, vnet_crypto_op_type_t type,
						  vnet_crypto_frame_enq_fn_t *enq_fn);

void vnet_crypto_register_dequeue_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					   vnet_crypto_frame_dequeue_t *deq_fn);

typedef struct
{
  void *handlers[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_engine_op_t;

typedef struct
{
  void *handlers[2];
} vnet_crypto_engine_hash_op_t;

struct vnet_crypto_engine_registration;
typedef struct vnet_crypto_engine_registration vnet_crypto_engine_registration_t;

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_crypto_engine_op_t ops[VNET_CRYPTO_N_ALGS][VNET_CRYPTO_OP_N_TYPES];
  vnet_crypto_engine_hash_op_t hash_ops[VNET_CRYPTO_N_HASH_ALGS];
  vnet_crypto_key_change_fn_t *key_change_fn[VNET_CRYPTO_HANDLER_N_TYPES][VNET_CRYPTO_N_ALGS];
  u16 key_data_sz[VNET_CRYPTO_HANDLER_N_TYPES][VNET_CRYPTO_N_ALGS];
  u8 key_data_per_thread[VNET_CRYPTO_HANDLER_N_TYPES][VNET_CRYPTO_N_ALGS];
  vnet_crypto_frame_dequeue_t *dequeue_handler;
} vnet_crypto_engine_t;

typedef struct
{
  u32 node_idx;
  u32 next_idx;
} vnet_crypto_async_next_node_t;

typedef struct
{
  char *name;
  u8 is_disabled;
  u8 is_enabled;
} vnet_crypto_config_t;

typedef struct
{
  vnet_crypto_ctx_t **ctxs;
  u8 ctx_pool_lock;
  u32 crypto_node_index;
  vnet_crypto_thread_t *threads;
  vnet_crypto_frame_dequeue_t **dequeue_handlers;
  vnet_crypto_engine_t *engines;
  /* configs and hash by name */
  vnet_crypto_config_t *configs;
  uword *config_index_by_name;
  uword *engine_index_by_name;
  uword *alg_index_by_name;
  vnet_crypto_engine_registration_t *engine_registrations;
  vnet_crypto_async_next_node_t *next_nodes;
  u8 *engine_supports_alg[VNET_CRYPTO_N_ALGS][VNET_CRYPTO_HANDLER_N_TYPES];
  u8 *hash_engine_supports_alg[VNET_CRYPTO_N_HASH_ALGS][2];
  vnet_crypto_engine_id_t active_engine_index[VNET_CRYPTO_N_ALGS][VNET_CRYPTO_HANDLER_N_TYPES];
  vnet_crypto_ctx_layout_t ctx_layout[VNET_CRYPTO_N_ALGS];
  u8 layout_initialized;
  vnet_crypto_alg_data_t algs[VNET_CRYPTO_N_ALGS];
  vnet_crypto_hash_alg_data_t hash_algs[VNET_CRYPTO_N_HASH_ALGS];
  vnet_crypto_engine_id_t active_op_engine_index[VNET_CRYPTO_N_ALGS][VNET_CRYPTO_OP_N_TYPES]
						[VNET_CRYPTO_HANDLER_N_TYPES];
  vnet_crypto_engine_id_t active_hash_engine_index[VNET_CRYPTO_N_HASH_ALGS][2];
  u8 default_disabled;
} vnet_crypto_main_t;

extern vnet_crypto_main_t crypto_main;

void vnet_crypto_register_key_handler_for_alg (vnet_crypto_engine_id_t engine,
					       vnet_crypto_alg_t alg, vnet_crypto_handler_type_t t,
					       vnet_crypto_key_change_fn_t *key_change_fn,
					       u16 key_data_sz, u8 key_data_per_thread);

u32 vnet_crypto_process_ops (vlib_main_t *vm, vnet_crypto_op_t ops[],
			     vnet_crypto_op_chunk_t *chunks, u32 n_ops);
typedef struct
{
  char *handler_name;
  char *engine;
  u8 set_simple : 1;
  u8 set_chained : 1;
  u8 set_async : 1;
} vnet_crypto_set_handlers_args_t;

int vnet_crypto_set_handlers (vnet_crypto_set_handlers_args_t *);

vnet_crypto_ctx_t *vnet_crypto_ctx_create (vnet_crypto_alg_t alg);
int vnet_crypto_ctx_set_cipher_key (vnet_crypto_ctx_t *ctx, const u8 *cipher_key,
				    u16 cipher_key_len);
int vnet_crypto_ctx_set_auth_key (vnet_crypto_ctx_t *ctx, const u8 *auth_key, u16 auth_key_len);
void vnet_crypto_ctx_destroy (vlib_main_t *vm, vnet_crypto_ctx_t *ctx);
void vnet_crypto_ctx_set_engine (vnet_crypto_ctx_t *ctx, vnet_crypto_handler_type_t t,
				 vnet_crypto_engine_id_t engine);
void vnet_crypto_ctx_set_default_engine (vnet_crypto_ctx_t *ctx, vnet_crypto_handler_type_t t);

format_function_t format_vnet_crypto_alg;
format_function_t format_vnet_crypto_engine;
format_function_t format_crypto_op_type_short;
format_function_t format_vnet_crypto_op_type;
format_function_t format_vnet_crypto_op_status;
unformat_function_t unformat_vnet_crypto_alg;
unformat_function_t unformat_vnet_crypto_engine;

static_always_inline int
vnet_crypto_alg_has_op_type (vnet_crypto_alg_t alg, vnet_crypto_op_type_t type)
{
  vnet_crypto_alg_type_t alg_type;

  ASSERT (alg < VNET_CRYPTO_N_ALGS);
  ASSERT (type < VNET_CRYPTO_OP_N_TYPES);

  alg_type = crypto_main.algs[alg].alg_type;

  switch (alg_type)
    {
    case VNET_CRYPTO_ALG_T_CIPHER:
    case VNET_CRYPTO_ALG_T_AEAD:
    case VNET_CRYPTO_ALG_T_COMBINED:
      return type == VNET_CRYPTO_OP_TYPE_ENCRYPT || type == VNET_CRYPTO_OP_TYPE_DECRYPT;
    case VNET_CRYPTO_ALG_T_AUTH:
      return type == VNET_CRYPTO_OP_TYPE_HMAC;
    case VNET_CRYPTO_ALG_T_NONE:
      break;
    }

  return 0;
}

static_always_inline void
vnet_crypto_op_init (vnet_crypto_ctx_t *ctx, vnet_crypto_op_t *op)
{
  if (CLIB_DEBUG > 0)
    clib_memset (op, 0xfe, sizeof (*op));
  op->status = VNET_CRYPTO_OP_STATUS_UNPROCESSED;
  op->flags = 0;
  op->ctx = ctx;
  op->n_chunks = 0;
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_key_data (vnet_crypto_ctx_t *ctx, vnet_crypto_handler_type_t t,
			  uword per_thread_offset)
{
  u16 key_data_offset = ctx->key_data_offset[t];
  vnet_crypto_key_data_t key_data;

  key_data = ctx->_data + key_data_offset + per_thread_offset;
  if (per_thread_offset == 0)
    ASSERT ((pointer_to_uword (key_data) & (__alignof__ (vnet_crypto_key_data_t) - 1)) == 0);
  return key_data;
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_simple_key_data (vnet_crypto_ctx_t *ctx, uword per_thread_offset)
{
  return vnet_crypto_get_key_data (ctx, VNET_CRYPTO_HANDLER_TYPE_SIMPLE, per_thread_offset);
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_chained_key_data (vnet_crypto_ctx_t *ctx, uword per_thread_offset)
{
  return vnet_crypto_get_key_data (ctx, VNET_CRYPTO_HANDLER_TYPE_CHAINED, per_thread_offset);
}

static_always_inline vnet_crypto_thread_key_data_t
vnet_crypto_get_key_data_for_thread (vnet_crypto_ctx_t *ctx, vnet_crypto_handler_type_t t,
				     clib_thread_index_t thread_index)
{
  uword key_data_offset;
  vnet_crypto_thread_key_data_t key_data;

  ASSERT (ctx->key_data_stride[t] != 0);
  key_data_offset = thread_index * ctx->key_data_stride[t];
  key_data = vnet_crypto_get_key_data (ctx, t, key_data_offset);

  ASSERT ((pointer_to_uword (key_data) & (__alignof__ (vnet_crypto_thread_key_data_t) - 1)) == 0);
  return key_data;
}

static_always_inline vnet_crypto_thread_key_data_t
vnet_crypto_get_simple_key_data_for_thread (vnet_crypto_ctx_t *ctx,
					    clib_thread_index_t thread_index)
{
  return vnet_crypto_get_key_data_for_thread (ctx, VNET_CRYPTO_HANDLER_TYPE_SIMPLE, thread_index);
}

static_always_inline vnet_crypto_thread_key_data_t
vnet_crypto_get_chained_key_data_for_thread (vnet_crypto_ctx_t *ctx,
					     clib_thread_index_t thread_index)
{
  return vnet_crypto_get_key_data_for_thread (ctx, VNET_CRYPTO_HANDLER_TYPE_CHAINED, thread_index);
}

static_always_inline vnet_crypto_thread_key_data_t
vnet_crypto_get_async_key_data_for_thread (vnet_crypto_ctx_t *ctx, clib_thread_index_t thread_index)
{
  return vnet_crypto_get_key_data_for_thread (ctx, VNET_CRYPTO_HANDLER_TYPE_ASYNC, thread_index);
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_async_key_data (vnet_crypto_ctx_t *ctx)
{
  ASSERT (ctx->key_data_stride[VNET_CRYPTO_HANDLER_TYPE_ASYNC] == 0);
  return vnet_crypto_get_key_data (ctx, VNET_CRYPTO_HANDLER_TYPE_ASYNC, 0);
}

/** async crypto inline functions **/

static_always_inline vnet_crypto_async_frame_t *
vnet_crypto_async_get_frame (vlib_main_t *vm, vnet_crypto_alg_t alg, vnet_crypto_op_type_t type)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  vnet_crypto_async_frame_t *f = NULL;

  if (PREDICT_TRUE (pool_free_elts (ct->frame_pool)))
    {
      pool_get_aligned (ct->frame_pool, f, CLIB_CACHE_LINE_BYTES);
#if CLIB_DEBUG > 0
      clib_memset (f, 0xfe, sizeof (*f));
#endif
      f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
      f->alg = alg;
      f->type = type;
      f->n_elts = 0;
      clib_memset (f->bad_hmac_bitmap, 0, sizeof (f->bad_hmac_bitmap));
      clib_memset (f->engine_error_bitmap, 0, sizeof (f->engine_error_bitmap));
    }

  return f;
}

static_always_inline void
vnet_crypto_async_free_frame (vlib_main_t * vm,
			      vnet_crypto_async_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct;

  ct = cm->threads + frame->enqueue_thread_index;
  if (frame->enqueue_thread_index == vm->thread_index)
    {
      pool_put (ct->frame_pool, frame);
      return;
    }

  clib_spinlock_lock (&ct->free_frames_lock);
  vec_add1 (ct->free_frames, frame);
  clib_spinlock_unlock (&ct->free_frames_lock);
}

static_always_inline void
vnet_crypto_async_free_frames (vlib_main_t *vm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  vnet_crypto_async_frame_t **frames = 0;
  vnet_crypto_async_frame_t **f;

  clib_spinlock_lock (&ct->free_frames_lock);
  frames = ct->free_frames;
  ct->free_frames = 0;
  clib_spinlock_unlock (&ct->free_frames_lock);

  vec_foreach (f, frames)
    pool_put (ct->frame_pool, f[0]);

  vec_free (frames);
}

static_always_inline int
vnet_crypto_async_complete_frame (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + frame->enqueue_thread_index;

  if (frame->enqueue_thread_index == vm->thread_index)
    {
      vec_add1 (ct->completed_frames, frame);
      return 0;
    }

  clib_spinlock_lock (&ct->completed_frames_lock);
  vec_add1 (ct->completed_frames, frame);
  clib_spinlock_unlock (&ct->completed_frames_lock);
  return 0;
}

static_always_inline void
vnet_crypto_async_collect_completed_frames (vlib_main_t *vm, vnet_crypto_async_frame_t ***frames)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;

  clib_spinlock_lock (&ct->completed_frames_lock);
  *frames = ct->completed_frames;
  ct->completed_frames = 0;
  clib_spinlock_unlock (&ct->completed_frames_lock);
}

static_always_inline int
vnet_crypto_async_submit_open_frame (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_engine_id_t engine;
  vnet_crypto_frame_enq_fn_t *fn;
  u32 i;
  int ret;

  engine = vnet_crypto_ctx_get_engine (frame->ctxs[0], VNET_CRYPTO_HANDLER_TYPE_ASYNC);
  if (engine == VNET_CRYPTO_ENGINE_ID_NONE)
    {
      engine = cm->active_op_engine_index[frame->alg][frame->type][VNET_CRYPTO_HANDLER_TYPE_ASYNC];
      if (engine != VNET_CRYPTO_ENGINE_ID_NONE)
	{
	  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

	  fn = e->ops[frame->alg][frame->type].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC];
	}
      else
	fn = 0;
    }
  else
    {
      vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

      fn = e->ops[frame->alg][frame->type].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC];
    }

  frame->state = VNET_CRYPTO_FRAME_STATE_PENDING;
  frame->enqueue_thread_index = vm->thread_index;

  if (PREDICT_FALSE (fn == 0))
    {
      for (i = 0; i < frame->n_elts; i++)
	vlib_crypto_async_frame_set_engine_error (frame, i);
      frame->state = VNET_CRYPTO_FRAME_STATE_COMPLETED;
      vnet_crypto_async_complete_frame (vm, frame);
      vlib_node_set_interrupt_pending (vm, cm->crypto_node_index);
      return -1;
    }

  ret = fn (vm, frame);

  if (PREDICT_TRUE (ret == 0))
    {
      for (i = 0; i < tm->n_vlib_mains; i++)
	vlib_node_set_interrupt_pending (vlib_get_main_by_index (i), cm->crypto_node_index);
    }
  else
    {
      for (i = 0; i < frame->n_elts; i++)
	vlib_crypto_async_frame_set_engine_error (frame, i);
      frame->state = VNET_CRYPTO_FRAME_STATE_COMPLETED;
      vnet_crypto_async_complete_frame (vm, frame);
      vlib_node_set_interrupt_pending (vm, cm->crypto_node_index);
    }

  return ret;
}

static_always_inline u8 *
vnet_crypto_async_get_data_ptr (vlib_main_t *vm, vlib_buffer_t *b, i16 offset)
{
  i32 first_len;
  i32 space_left;

  if (offset == 0)
    return 0;

  first_len = b->current_data + b->current_length;
  if (offset < first_len)
    return b->data + offset;

  if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      space_left = vlib_buffer_space_left_at_end (vm, b);
      if (offset <= first_len + space_left)
	return b->data + offset;
    }

  offset -= first_len;

  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      if (offset < b->current_length)
	return vlib_buffer_get_current (b) + offset;

      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  space_left = vlib_buffer_space_left_at_end (vm, b);
	  if (offset <= b->current_length + space_left)
	    return vlib_buffer_get_current (b) + offset;
	}

      offset -= b->current_length;
    }

  return 0;
}

static_always_inline void
vnet_crypto_async_add_to_frame (vlib_main_t *vm, vnet_crypto_async_frame_t *f,
				vnet_crypto_ctx_t *ctx, u32 buffer_index, u16 next_node)
{
  u16 index;

  ASSERT (f->n_elts < VNET_CRYPTO_FRAME_SIZE);

  index = f->n_elts;
  f->n_elts++;
  f->ctxs[index] = ctx;
  f->buffer_indices[index] = buffer_index;
  f->next_node_index[index] = next_node;
}

static_always_inline void
vnet_crypto_async_reset_frame (vnet_crypto_async_frame_t * f)
{
  vnet_crypto_alg_t alg;
  vnet_crypto_op_type_t type;
  ASSERT (f != 0);
  ASSERT ((f->state == VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED ||
	   f->state == VNET_CRYPTO_FRAME_STATE_COMPLETED));
  alg = f->alg;
  type = f->type;
  if (CLIB_DEBUG > 0)
    clib_memset (f, 0xfe, sizeof (*f));
  f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
  f->alg = alg;
  f->type = type;
  f->n_elts = 0;
  clib_memset (f->bad_hmac_bitmap, 0, sizeof (f->bad_hmac_bitmap));
  clib_memset (f->engine_error_bitmap, 0, sizeof (f->engine_error_bitmap));
}

static_always_inline u8
vnet_crypto_async_frame_is_full (const vnet_crypto_async_frame_t *f)
{
  return (f->n_elts == VNET_CRYPTO_FRAME_SIZE);
}

#endif /* included_vnet_crypto_crypto_h */
