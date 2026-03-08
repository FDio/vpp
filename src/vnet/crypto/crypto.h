/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#ifndef included_vnet_crypto_crypto_h
#define included_vnet_crypto_crypto_h

#include <vlib/vlib.h>

#define VNET_CRYPTO_FRAME_SIZE 64
#define VNET_CRYPTO_FRAME_POOL_SIZE 1024

/* CRYPTO_ID, PRETTY_NAME, CIPHER_FAMILY, INTEG_FAMILY, KEY_LEN, BLOCK_LEN */
#define foreach_crypto_cipher_alg_non_ctr                                                          \
  _ (DES_CBC, "des-cbc", DES_CBC, NONE, 7, 8)                                                      \
  _ (3DES_CBC, "3des-cbc", TDES_CBC, NONE, 24, 8)                                                  \
  _ (AES_128_CBC, "aes-128-cbc", AES_CBC, NONE, 16, 16)                                            \
  _ (AES_192_CBC, "aes-192-cbc", AES_CBC, NONE, 24, 16)                                            \
  _ (AES_256_CBC, "aes-256-cbc", AES_CBC, NONE, 32, 16)

#define foreach_crypto_cipher_alg_ctr                                                              \
  _ (AES_128_CTR, "aes-128-ctr", AES_CTR, NONE, 16, 16)                                            \
  _ (AES_192_CTR, "aes-192-ctr", AES_CTR, NONE, 24, 16)                                            \
  _ (AES_256_CTR, "aes-256-ctr", AES_CTR, NONE, 32, 16)

/* CRYPTO_ID, PRETTY_NAME, CIPHER_FAMILY, INTEG_FAMILY, KEY_LEN, BLOCK_LEN */
#define foreach_crypto_aead_alg                                                                    \
  _ (AES_128_GCM, "aes-128-gcm", AES_GCM, AES_GCM, 16, 16)                                         \
  _ (AES_192_GCM, "aes-192-gcm", AES_GCM, AES_GCM, 24, 16)                                         \
  _ (AES_256_GCM, "aes-256-gcm", AES_GCM, AES_GCM, 32, 16)                                         \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac", AES_NULL_GMAC, AES_NULL_GMAC, 16, 16)                 \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac", AES_NULL_GMAC, AES_NULL_GMAC, 24, 16)                 \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac", AES_NULL_GMAC, AES_NULL_GMAC, 32, 16)                 \
  _ (CHACHA20_POLY1305, "chacha20-poly1305", CHACHA20_POLY1305, CHACHA20_POLY1305, 32, 64)

#define foreach_crypto_hash_alg                                                                    \
  _ (MD5, "md5", NONE, MD5, 16, 64)                                                                \
  _ (SHA1, "sha-1", NONE, SHA1, 20, 64)                                                            \
  _ (SHA224, "sha-224", NONE, SHA2, 28, 64)                                                        \
  _ (SHA256, "sha-256", NONE, SHA2, 32, 64)                                                        \
  _ (SHA384, "sha-384", NONE, SHA2, 48, 128)                                                       \
  _ (SHA512, "sha-512", NONE, SHA2, 64, 128)

#define foreach_crypto_op_type                                                \
  _ (ENCRYPT, "encrypt")                                                      \
  _ (DECRYPT, "decrypt")                                                      \
  _ (HMAC, "hmac")                                                            \
  _ (HASH, "hash")

typedef enum
{
#define _(n, s) VNET_CRYPTO_OP_TYPE_##n,
  foreach_crypto_op_type
#undef _
    VNET_CRYPTO_OP_N_TYPES,
} vnet_crypto_op_type_t;

#define foreach_crypto_op_status \
  _(IDLE, "idle") \
  _(PENDING, "pending") \
  _(WORK_IN_PROGRESS, "work-in-progress") \
  _(COMPLETED, "completed") \
  _(FAIL_NO_HANDLER, "no-handler") \
  _(FAIL_BAD_HMAC, "bad-hmac") \
  _(FAIL_ENGINE_ERR, "engine-error")

/** async crypto **/

/* CRYPTO_ID, PRETTY_NAME, CIPHER_FAMILY, INTEG_FAMILY, KEY_LEN, TAG_LEN, AAD_LEN, BLOCK_LEN */
#define foreach_crypto_aead_async_alg                                                              \
  _ (AES_128_GCM, "aes-128-gcm-aad8", AES_GCM, AES_GCM, 16, 16, 8, 16)                             \
  _ (AES_128_GCM, "aes-128-gcm-aad12", AES_GCM, AES_GCM, 16, 16, 12, 16)                           \
  _ (AES_192_GCM, "aes-192-gcm-aad8", AES_GCM, AES_GCM, 24, 16, 8, 16)                             \
  _ (AES_192_GCM, "aes-192-gcm-aad12", AES_GCM, AES_GCM, 24, 16, 12, 16)                           \
  _ (AES_256_GCM, "aes-256-gcm-aad8", AES_GCM, AES_GCM, 32, 16, 8, 16)                             \
  _ (AES_256_GCM, "aes-256-gcm-aad12", AES_GCM, AES_GCM, 32, 16, 12, 16)                           \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac-aad8", AES_NULL_GMAC, AES_NULL_GMAC, 16, 16, 8, 16)     \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac-aad12", AES_NULL_GMAC, AES_NULL_GMAC, 16, 16, 12, 16)   \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac-aad8", AES_NULL_GMAC, AES_NULL_GMAC, 24, 16, 8, 16)     \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac-aad12", AES_NULL_GMAC, AES_NULL_GMAC, 24, 16, 12, 16)   \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac-aad8", AES_NULL_GMAC, AES_NULL_GMAC, 32, 16, 8, 16)     \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac-aad12", AES_NULL_GMAC, AES_NULL_GMAC, 32, 16, 12, 16)   \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-aad8", CHACHA20_POLY1305, CHACHA20_POLY1305, 32, 16, 8, \
     64)                                                                                           \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-aad12", CHACHA20_POLY1305, CHACHA20_POLY1305, 32, 16,   \
     12, 64)                                                                                       \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-aad0", CHACHA20_POLY1305, CHACHA20_POLY1305, 32, 16, 0, \
     64)

/* CRYPTO_ID, INTEG_ID, PRETTY_NAME, CIPHER_FAMILY, INTEG_FAMILY, KEY_LEN, DIGEST_LEN, BLOCK_LEN */
#define foreach_crypto_combined_alg_non_ctr                                                        \
  _ (3DES_CBC, MD5, "3des-cbc-hmac-md5", TDES_CBC, MD5, 24, 16, 8)                                 \
  _ (AES_128_CBC, MD5, "aes-128-cbc-hmac-md5", AES_CBC, MD5, 16, 16, 16)                           \
  _ (AES_192_CBC, MD5, "aes-192-cbc-hmac-md5", AES_CBC, MD5, 24, 16, 16)                           \
  _ (AES_256_CBC, MD5, "aes-256-cbc-hmac-md5", AES_CBC, MD5, 32, 16, 16)                           \
  _ (3DES_CBC, SHA1, "3des-cbc-hmac-sha-1", TDES_CBC, SHA1, 24, 20, 8)                             \
  _ (AES_128_CBC, SHA1, "aes-128-cbc-hmac-sha-1", AES_CBC, SHA1, 16, 20, 16)                       \
  _ (AES_192_CBC, SHA1, "aes-192-cbc-hmac-sha-1", AES_CBC, SHA1, 24, 20, 16)                       \
  _ (AES_256_CBC, SHA1, "aes-256-cbc-hmac-sha-1", AES_CBC, SHA1, 32, 20, 16)                       \
  _ (3DES_CBC, SHA224, "3des-cbc-hmac-sha-224", TDES_CBC, SHA2, 24, 28, 8)                         \
  _ (AES_128_CBC, SHA224, "aes-128-cbc-hmac-sha-224", AES_CBC, SHA2, 16, 28, 16)                   \
  _ (AES_192_CBC, SHA224, "aes-192-cbc-hmac-sha-224", AES_CBC, SHA2, 24, 28, 16)                   \
  _ (AES_256_CBC, SHA224, "aes-256-cbc-hmac-sha-224", AES_CBC, SHA2, 32, 28, 16)                   \
  _ (3DES_CBC, SHA256, "3des-cbc-hmac-sha-256", TDES_CBC, SHA2, 24, 32, 8)                         \
  _ (AES_128_CBC, SHA256, "aes-128-cbc-hmac-sha-256", AES_CBC, SHA2, 16, 32, 16)                   \
  _ (AES_192_CBC, SHA256, "aes-192-cbc-hmac-sha-256", AES_CBC, SHA2, 24, 32, 16)                   \
  _ (AES_256_CBC, SHA256, "aes-256-cbc-hmac-sha-256", AES_CBC, SHA2, 32, 32, 16)                   \
  _ (3DES_CBC, SHA384, "3des-cbc-hmac-sha-384", TDES_CBC, SHA2, 24, 48, 8)                         \
  _ (AES_128_CBC, SHA384, "aes-128-cbc-hmac-sha-384", AES_CBC, SHA2, 16, 48, 16)                   \
  _ (AES_192_CBC, SHA384, "aes-192-cbc-hmac-sha-384", AES_CBC, SHA2, 24, 48, 16)                   \
  _ (AES_256_CBC, SHA384, "aes-256-cbc-hmac-sha-384", AES_CBC, SHA2, 32, 48, 16)                   \
  _ (3DES_CBC, SHA512, "3des-cbc-hmac-sha-512", TDES_CBC, SHA2, 24, 64, 8)                         \
  _ (AES_128_CBC, SHA512, "aes-128-cbc-hmac-sha-512", AES_CBC, SHA2, 16, 64, 16)                   \
  _ (AES_192_CBC, SHA512, "aes-192-cbc-hmac-sha-512", AES_CBC, SHA2, 24, 64, 16)                   \
  _ (AES_256_CBC, SHA512, "aes-256-cbc-hmac-sha-512", AES_CBC, SHA2, 32, 64, 16)

#define foreach_crypto_combined_alg_ctr                                                            \
  _ (AES_128_CTR, SHA1, "aes-128-ctr-hmac-sha-1", AES_CTR, SHA1, 16, 20, 16)                       \
  _ (AES_192_CTR, SHA1, "aes-192-ctr-hmac-sha-1", AES_CTR, SHA1, 24, 20, 16)                       \
  _ (AES_256_CTR, SHA1, "aes-256-ctr-hmac-sha-1", AES_CTR, SHA1, 32, 20, 16)                       \
  _ (AES_128_CTR, SHA256, "aes-128-ctr-hmac-sha-256", AES_CTR, SHA2, 16, 32, 16)                   \
  _ (AES_192_CTR, SHA256, "aes-192-ctr-hmac-sha-256", AES_CTR, SHA2, 24, 32, 16)                   \
  _ (AES_256_CTR, SHA256, "aes-256-ctr-hmac-sha-256", AES_CTR, SHA2, 32, 32, 16)                   \
  _ (AES_128_CTR, SHA384, "aes-128-ctr-hmac-sha-384", AES_CTR, SHA2, 16, 48, 16)                   \
  _ (AES_192_CTR, SHA384, "aes-192-ctr-hmac-sha-384", AES_CTR, SHA2, 24, 48, 16)                   \
  _ (AES_256_CTR, SHA384, "aes-256-ctr-hmac-sha-384", AES_CTR, SHA2, 32, 48, 16)                   \
  _ (AES_128_CTR, SHA512, "aes-128-ctr-hmac-sha-512", AES_CTR, SHA2, 16, 64, 16)                   \
  _ (AES_192_CTR, SHA512, "aes-192-ctr-hmac-sha-512", AES_CTR, SHA2, 24, 64, 16)                   \
  _ (AES_256_CTR, SHA512, "aes-256-ctr-hmac-sha-512", AES_CTR, SHA2, 32, 64, 16)

#define foreach_crypto_combined_alg                                                                \
  foreach_crypto_combined_alg_non_ctr foreach_crypto_combined_alg_ctr

/* CRYPTO_ID, INTEG_ID, PRETTY_NAME, CIPHER_FAMILY, INTEG_FAMILY, KEY_LEN, DIGEST_LEN, BLOCK_LEN */
#define foreach_crypto_combined_fixed_alg_non_ctr                                                  \
  _ (3DES_CBC, MD5, "3des-cbc-hmac-md5-tag12", TDES_CBC, MD5, 24, 12, 8)                           \
  _ (AES_128_CBC, MD5, "aes-128-cbc-hmac-md5-tag12", AES_CBC, MD5, 16, 12, 16)                     \
  _ (AES_192_CBC, MD5, "aes-192-cbc-hmac-md5-tag12", AES_CBC, MD5, 24, 12, 16)                     \
  _ (AES_256_CBC, MD5, "aes-256-cbc-hmac-md5-tag12", AES_CBC, MD5, 32, 12, 16)                     \
  _ (3DES_CBC, SHA1, "3des-cbc-hmac-sha-1-tag12", TDES_CBC, SHA1, 24, 12, 8)                       \
  _ (AES_128_CBC, SHA1, "aes-128-cbc-hmac-sha-1-tag12", AES_CBC, SHA1, 16, 12, 16)                 \
  _ (AES_192_CBC, SHA1, "aes-192-cbc-hmac-sha-1-tag12", AES_CBC, SHA1, 24, 12, 16)                 \
  _ (AES_256_CBC, SHA1, "aes-256-cbc-hmac-sha-1-tag12", AES_CBC, SHA1, 32, 12, 16)                 \
  _ (3DES_CBC, SHA224, "3des-cbc-hmac-sha-224-tag14", TDES_CBC, SHA2, 24, 14, 8)                   \
  _ (AES_128_CBC, SHA224, "aes-128-cbc-hmac-sha-224-tag14", AES_CBC, SHA2, 16, 14, 16)             \
  _ (AES_192_CBC, SHA224, "aes-192-cbc-hmac-sha-224-tag14", AES_CBC, SHA2, 24, 14, 16)             \
  _ (AES_256_CBC, SHA224, "aes-256-cbc-hmac-sha-224-tag14", AES_CBC, SHA2, 32, 14, 16)             \
  _ (3DES_CBC, SHA256, "3des-cbc-hmac-sha-256-tag16", TDES_CBC, SHA2, 24, 16, 8)                   \
  _ (AES_128_CBC, SHA256, "aes-128-cbc-hmac-sha-256-tag16", AES_CBC, SHA2, 16, 16, 16)             \
  _ (AES_192_CBC, SHA256, "aes-192-cbc-hmac-sha-256-tag16", AES_CBC, SHA2, 24, 16, 16)             \
  _ (AES_256_CBC, SHA256, "aes-256-cbc-hmac-sha-256-tag16", AES_CBC, SHA2, 32, 16, 16)             \
  _ (3DES_CBC, SHA384, "3des-cbc-hmac-sha-384-tag24", TDES_CBC, SHA2, 24, 24, 8)                   \
  _ (AES_128_CBC, SHA384, "aes-128-cbc-hmac-sha-384-tag24", AES_CBC, SHA2, 16, 24, 16)             \
  _ (AES_192_CBC, SHA384, "aes-192-cbc-hmac-sha-384-tag24", AES_CBC, SHA2, 24, 24, 16)             \
  _ (AES_256_CBC, SHA384, "aes-256-cbc-hmac-sha-384-tag24", AES_CBC, SHA2, 32, 24, 16)             \
  _ (3DES_CBC, SHA512, "3des-cbc-hmac-sha-512-tag32", TDES_CBC, SHA2, 24, 32, 8)                   \
  _ (AES_128_CBC, SHA512, "aes-128-cbc-hmac-sha-512-tag32", AES_CBC, SHA2, 16, 32, 16)             \
  _ (AES_192_CBC, SHA512, "aes-192-cbc-hmac-sha-512-tag32", AES_CBC, SHA2, 24, 32, 16)             \
  _ (AES_256_CBC, SHA512, "aes-256-cbc-hmac-sha-512-tag32", AES_CBC, SHA2, 32, 32, 16)

#define foreach_crypto_combined_fixed_alg_ctr                                                      \
  _ (AES_128_CTR, SHA1, "aes-128-ctr-hmac-sha-1-tag12", AES_CTR, SHA1, 16, 12, 16)                 \
  _ (AES_192_CTR, SHA1, "aes-192-ctr-hmac-sha-1-tag12", AES_CTR, SHA1, 24, 12, 16)                 \
  _ (AES_256_CTR, SHA1, "aes-256-ctr-hmac-sha-1-tag12", AES_CTR, SHA1, 32, 12, 16)                 \
  _ (AES_128_CTR, SHA256, "aes-128-ctr-hmac-sha-256-tag16", AES_CTR, SHA2, 16, 16, 16)             \
  _ (AES_192_CTR, SHA256, "aes-192-ctr-hmac-sha-256-tag16", AES_CTR, SHA2, 24, 16, 16)             \
  _ (AES_256_CTR, SHA256, "aes-256-ctr-hmac-sha-256-tag16", AES_CTR, SHA2, 32, 16, 16)             \
  _ (AES_128_CTR, SHA384, "aes-128-ctr-hmac-sha-384-tag24", AES_CTR, SHA2, 16, 24, 16)             \
  _ (AES_192_CTR, SHA384, "aes-192-ctr-hmac-sha-384-tag24", AES_CTR, SHA2, 24, 24, 16)             \
  _ (AES_256_CTR, SHA384, "aes-256-ctr-hmac-sha-384-tag24", AES_CTR, SHA2, 32, 24, 16)             \
  _ (AES_128_CTR, SHA512, "aes-128-ctr-hmac-sha-512-tag32", AES_CTR, SHA2, 16, 32, 16)             \
  _ (AES_192_CTR, SHA512, "aes-192-ctr-hmac-sha-512-tag32", AES_CTR, SHA2, 24, 32, 16)             \
  _ (AES_256_CTR, SHA512, "aes-256-ctr-hmac-sha-512-tag32", AES_CTR, SHA2, 32, 32, 16)

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
#define _(n, s) VNET_CRYPTO_OP_STATUS_##n,
  foreach_crypto_op_status
#undef _
    VNET_CRYPTO_OP_N_STATUS,
} __clib_packed vnet_crypto_op_status_t;

typedef enum
{
  VNET_CRYPTO_ALG_NONE = 0,
#define _(n, s, cf, inf, k, b) VNET_CRYPTO_ALG_##n,
  foreach_crypto_cipher_alg_non_ctr foreach_crypto_cipher_alg_ctr foreach_crypto_aead_alg
#undef _
#define _(n, s, cf, inf, d, b) VNET_CRYPTO_ALG_##n,
    foreach_crypto_hash_alg
#undef _
#define _(n, s, cf, inf, k, t, a, b) VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,
      foreach_crypto_aead_async_alg
#undef _
#define _(c, h, s, cf, inf, k, d, b) VNET_CRYPTO_ALG_##c##_##h,
	foreach_crypto_combined_alg
#undef _
#define _(c, h, s, cf, inf, k, d, b) VNET_CRYPTO_ALG_##c##_##h##_TAG##d,
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
  u16 integ_key_sz;
  u16 cipher_key_offset;
  u16 integ_key_offset;
  u16 simple_key_data_offset;
  u16 chained_key_data_offset;
  u16 async_key_data_offset;
  u16 simple_key_data_stride;
  u16 chained_key_data_stride;
  u16 async_key_data_stride;
  u16 total_data_sz;
  vnet_crypto_engine_id_t engine_index_simple;
  vnet_crypto_engine_id_t engine_index_chained;
  vnet_crypto_engine_id_t engine_index_async;
  vnet_crypto_alg_t alg : 8;
  u8 _data[];
} vnet_crypto_key_t;

static_always_inline const u8 *
vnet_crypto_get_cipher_key (const vnet_crypto_key_t *k)
{
  return k->_data + k->cipher_key_offset;
}

static_always_inline const u8 *
vnet_crypto_get_integ_key (const vnet_crypto_key_t *k)
{
  return k->_data + k->integ_key_offset;
}

typedef enum
{
  VNET_CRYPTO_OP_NONE = 0,
#define _(n, s, cf, inf, k, b) VNET_CRYPTO_OP_##n##_ENC, VNET_CRYPTO_OP_##n##_DEC,
  foreach_crypto_cipher_alg_non_ctr foreach_crypto_cipher_alg_ctr foreach_crypto_aead_alg
#undef _
#define _(n, s, cf, inf, d, b) VNET_CRYPTO_OP_##n##_HASH, VNET_CRYPTO_OP_##n##_HMAC,
    foreach_crypto_hash_alg
#undef _
#define _(n, s, cf, inf, k, t, a, b)                                                               \
  VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,
      foreach_crypto_aead_async_alg
#undef _
#define _(c, h, s, cf, inf, k, d, b) VNET_CRYPTO_OP_##c##_##h##_ENC, VNET_CRYPTO_OP_##c##_##h##_DEC,
	foreach_crypto_combined_alg
#undef _
#define _(c, h, s, cf, inf, k, d, b)                                                               \
  VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,
	  foreach_crypto_combined_fixed_alg
#undef _
	    VNET_CRYPTO_N_OP_IDS,
} __clib_packed vnet_crypto_op_id_t;

typedef struct vnet_crypto_alg_data_t_ vnet_crypto_alg_data_t;

typedef enum
{
  VNET_CRYPTO_ALG_T_NONE = 0,
  VNET_CRYPTO_ALG_T_AEAD,
  VNET_CRYPTO_ALG_T_INTEG,
  VNET_CRYPTO_ALG_T_CYPHER,
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
      u32 integ_chunk_index;
    };
  };

  vnet_crypto_key_t *key;
  u8 *iv;

  union
  {
    u8 *integ_src;
    u8 *aad;
  };

  union
  {
    u8 *tag;
    u8 *digest;
  };
  union
  {
    u16 integ_len;
    u16 integ_n_chunks;
    u16 aad_len;
  };

  vnet_crypto_op_id_t op;
  u8 status : 4;
  u8 flags : 4;
#define VNET_CRYPTO_OP_FLAG_HMAC_CHECK	    (1 << 0)
#define VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS (1 << 1)

  union
  {
    u8 digest_len;
    u8 tag_len;
  };
} vnet_crypto_op_t;

STATIC_ASSERT_SIZEOF (vnet_crypto_op_t, CLIB_CACHE_LINE_BYTES);

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

typedef struct
{
  i16 iv_offset;
  union
  {
    i16 digest_offset;
    i16 tag_offset;
  };
  i16 aad_offset;
  vnet_crypto_key_t *key;
  u32 crypto_total_length;
  i16 crypto_start_offset; /* first buffer offset */
  i16 integ_start_offset;
  /* adj total_length for integ, e.g.4 bytes for IPSec ESN */
  i16 integ_length_adj;
  vnet_crypto_op_status_t status : 8;
  u8 flags; /**< share same VNET_CRYPTO_OP_FLAG_* values */
  u8 aad_len;
  u8 digest_len;
} vnet_crypto_async_frame_elt_t;

/* Assert the size so the compiler will warn us when it changes */
STATIC_ASSERT_SIZEOF (vnet_crypto_async_frame_elt_t, 4 * sizeof (u64));

typedef enum vnet_crypto_async_frame_state_t_
{
  VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED,
  /* frame waiting to be processed */
  VNET_CRYPTO_FRAME_STATE_PENDING,
  VNET_CRYPTO_FRAME_STATE_WORK_IN_PROGRESS,
  VNET_CRYPTO_FRAME_STATE_SUCCESS,
  VNET_CRYPTO_FRAME_STATE_ELT_ERROR
} __clib_packed vnet_crypto_async_frame_state_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_async_frame_state_t state;
  vnet_crypto_op_id_t op : 8;
  u16 n_elts;
  vnet_crypto_async_frame_elt_t elts[VNET_CRYPTO_FRAME_SIZE];
  u32 buffer_indices[VNET_CRYPTO_FRAME_SIZE];
  u16 next_node_index[VNET_CRYPTO_FRAME_SIZE];
  clib_thread_index_t enqueue_thread_index;
} vnet_crypto_async_frame_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_async_frame_t *frame_pool;
  u32 *buffer_indices;
  u16 *nexts;
} vnet_crypto_thread_t;

typedef u32 vnet_crypto_key_index_t;

typedef u32 (vnet_crypto_chained_op_fn_t) (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
					   u32 n_ops, clib_thread_index_t thread_index);

typedef u32 (vnet_crypto_simple_op_fn_t) (vnet_crypto_op_t *ops[], u32 n_ops,
					  clib_thread_index_t thread_index);

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

typedef void (vnet_crypto_key_change_fn_t) (vnet_crypto_key_t *key,
					    vnet_crypto_key_change_args_t *args);

typedef void (vnet_crypto_async_key_data_fn_t) (vnet_crypto_key_t *key);

typedef struct vnet_crypto_alg_data_t_
{
  char *name;
  u16 key_len;
  u8 block_len;
  vnet_crypto_alg_type_t alg_type;
  vnet_crypto_alg_family_t cipher_family;
  vnet_crypto_alg_family_t integ_family;
  u8 aad_len;
  u8 digest_len;
  u8 variable_cypher_key_length : 1;
  u8 variable_integ_key_length : 1;
  u8 simple_key_data_per_thread : 1;
  u8 chained_key_data_per_thread : 1;
  vnet_crypto_op_id_t op_by_type[VNET_CRYPTO_OP_N_TYPES];
  vnet_crypto_key_change_fn_t *key_change_fn[VNET_CRYPTO_HANDLER_N_TYPES];
  u16 key_data_sz[VNET_CRYPTO_HANDLER_N_TYPES];
  vnet_crypto_engine_id_t key_fn_engine[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_alg_data_t;

static_always_inline void
vnet_crypto_alg_key_data_set_per_thread (vnet_crypto_alg_data_t *ad, vnet_crypto_handler_type_t t,
					 u8 is_per_thread)
{
  if (t == VNET_CRYPTO_HANDLER_TYPE_SIMPLE)
    ad->simple_key_data_per_thread = is_per_thread != 0;
  else if (t == VNET_CRYPTO_HANDLER_TYPE_CHAINED)
    ad->chained_key_data_per_thread = is_per_thread != 0;
}

/** async crypto function handlers **/
typedef int (vnet_crypto_frame_enq_fn_t) (vlib_main_t *vm,
					  vnet_crypto_async_frame_t *frame);
typedef vnet_crypto_async_frame_t *(
  vnet_crypto_frame_dequeue_t) (vlib_main_t *vm, u32 *nb_elts_processed,
				clib_thread_index_t *enqueue_thread_idx);

vnet_crypto_engine_id_t vnet_crypto_register_engine (vlib_main_t *vm, char *name, int prio,
						     char *desc);
vnet_crypto_engine_id_t vnet_crypto_get_engine_index_by_name (const char *fmt, ...);

void vnet_crypto_register_ops_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
				       vnet_crypto_op_id_t opt, vnet_crypto_simple_op_fn_t *oph);

void vnet_crypto_register_chained_ops_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					       vnet_crypto_op_id_t opt,
					       vnet_crypto_chained_op_fn_t *oph);

void vnet_crypto_register_ops_handlers (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					vnet_crypto_op_id_t opt, vnet_crypto_simple_op_fn_t *fn,
					vnet_crypto_chained_op_fn_t *cfn);

void vnet_crypto_register_key_change_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					      vnet_crypto_handler_type_t t,
					      vnet_crypto_key_change_fn_t *key_change_fn);
void vnet_crypto_register_async_key_add_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
						 vnet_crypto_async_key_data_fn_t *key_add_fn);
void vnet_crypto_register_async_key_del_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
						 vnet_crypto_async_key_data_fn_t *key_del_fn);
void vnet_crypto_register_async_key_change_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
						    vnet_crypto_key_change_fn_t *key_change_fn,
						    u16 key_data_sz);

/** async crypto register functions */
u32 vnet_crypto_register_post_node (vlib_main_t * vm, char *post_node_name);

void vnet_crypto_register_enqueue_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					   vnet_crypto_op_id_t opt,
					   vnet_crypto_frame_enq_fn_t *enq_fn);

void vnet_crypto_register_dequeue_handler (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					   vnet_crypto_frame_dequeue_t *deq_fn);

typedef struct
{
  void *handlers[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_engine_op_t;

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_crypto_engine_op_t ops[VNET_CRYPTO_N_OP_IDS];
  vnet_crypto_key_change_fn_t *key_change_fn[VNET_CRYPTO_HANDLER_N_TYPES][VNET_CRYPTO_N_ALGS];
  vnet_crypto_async_key_data_fn_t *async_key_add_fn;
  vnet_crypto_async_key_data_fn_t *async_key_del_fn;
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
  vnet_crypto_op_type_t type;
  vnet_crypto_alg_t alg;
  u8 is_aead : 1;
  u8 is_ctr : 1;
  u8 aad_len;
  u8 digest_len;
  vnet_crypto_engine_id_t active_engine_index[VNET_CRYPTO_HANDLER_N_TYPES];
  void *handlers[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_op_data_t;

typedef struct
{
  char *name;
  u8 is_disabled;
  u8 is_enabled;
} vnet_crypto_config_t;

typedef struct
{
  vnet_crypto_key_t **keys;
  u8 keys_lock;
  u32 crypto_node_index;
  vnet_crypto_thread_t *threads;
  vnet_crypto_frame_dequeue_t **dequeue_handlers;
  vnet_crypto_engine_t *engines;
  /* configs and hash by name */
  vnet_crypto_config_t *configs;
  uword *config_index_by_name;
  uword *engine_index_by_name;
  uword *alg_index_by_name;
  vnet_crypto_async_next_node_t *next_nodes;
  vnet_crypto_alg_data_t algs[VNET_CRYPTO_N_ALGS];
  vnet_crypto_op_data_t opt_data[VNET_CRYPTO_N_OP_IDS];
  u32 key_data_size[VNET_CRYPTO_HANDLER_N_TYPES];
  u32 key_data_offset[VNET_CRYPTO_HANDLER_N_TYPES];
  u8 default_disabled;
} vnet_crypto_main_t;

extern vnet_crypto_main_t crypto_main;

u32 vnet_crypto_process_chained_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
				     vnet_crypto_op_chunk_t * chunks,
				     u32 n_ops);
u32 vnet_crypto_process_chained_ops_with_engine (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
						 vnet_crypto_op_t ops[],
						 vnet_crypto_op_chunk_t *chunks, u32 n_ops);
u32 vnet_crypto_process_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
			     u32 n_ops);
u32 vnet_crypto_process_ops_with_engine (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					 vnet_crypto_op_t ops[], u32 n_ops);

void vnet_crypto_set_async_dispatch (u8 mode, u8 adaptive);

typedef struct
{
  char *handler_name;
  char *engine;
  u8 set_simple : 1;
  u8 set_chained : 1;
  u8 set_async : 1;
} vnet_crypto_set_handlers_args_t;

int vnet_crypto_set_handlers (vnet_crypto_set_handlers_args_t *);

vnet_crypto_key_t *vnet_crypto_key_add (vlib_main_t *vm, vnet_crypto_alg_t alg,
					const u8 *crypto_data, u16 crypto_length,
					const u8 *integ_data, u16 integ_length);
vnet_crypto_key_t *vnet_crypto_key_add_for_engine (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
						   vnet_crypto_alg_t alg, const u8 *crypto_data,
						   u16 crypto_length, const u8 *integ_data,
						   u16 integ_length);
vnet_crypto_key_t *vnet_crypto_key_add_for_async_engine (vlib_main_t *vm,
							 vnet_crypto_engine_id_t engine,
							 vnet_crypto_alg_t alg,
							 const u8 *crypto_data, u16 crypto_length,
							 const u8 *integ_data, u16 integ_length);
void vnet_crypto_key_del (vlib_main_t *vm, vnet_crypto_key_t *key);
void vnet_crypto_key_update (vlib_main_t *vm, vnet_crypto_key_t *key);

vnet_crypto_op_id_t *vnet_crypto_ops_from_alg (vnet_crypto_alg_t alg);

format_function_t format_vnet_crypto_alg;
format_function_t format_vnet_crypto_engine;
format_function_t format_vnet_crypto_op;
format_function_t format_crypto_op_type_short;
format_function_t format_vnet_crypto_op_type;
format_function_t format_vnet_crypto_op_status;
unformat_function_t unformat_vnet_crypto_alg;
unformat_function_t unformat_vnet_crypto_engine;

static_always_inline void
vnet_crypto_op_init (vnet_crypto_op_t * op, vnet_crypto_op_id_t type)
{
  if (CLIB_DEBUG > 0)
    clib_memset (op, 0xfe, sizeof (*op));
  op->op = type;
  op->flags = 0;
  op->key = 0;
  op->n_chunks = 0;
}

static_always_inline vnet_crypto_op_data_t *
vnet_crypto_get_op_data (vnet_crypto_op_id_t id)
{
  vnet_crypto_main_t *cm = &crypto_main;
  ASSERT (id < VNET_CRYPTO_N_OP_IDS);
  return cm->opt_data + id;
}

static_always_inline vnet_crypto_op_type_t
vnet_crypto_get_op_type (vnet_crypto_op_id_t id)
{
  vnet_crypto_op_data_t *od = vnet_crypto_get_op_data (id);
  return od->type;
}

static_always_inline vnet_crypto_key_t *
vnet_crypto_get_key (vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  return cm->keys[index];
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_simple_key_data_ptr (vnet_crypto_key_t *key, uword per_thread_offset)
{
  u16 key_data_offset = key->simple_key_data_offset;
  vnet_crypto_key_data_t key_data;

  key_data = key->_data + key_data_offset + per_thread_offset;
  ASSERT ((pointer_to_uword (key_data) & (__alignof__ (vnet_crypto_key_data_t) - 1)) == 0);
  return key_data;
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_chained_key_data_ptr (vnet_crypto_key_t *key, uword per_thread_offset)
{
  u16 key_data_offset = key->chained_key_data_offset;
  vnet_crypto_key_data_t key_data;

  key_data = key->_data + key_data_offset + per_thread_offset;
  ASSERT ((pointer_to_uword (key_data) & (__alignof__ (vnet_crypto_key_data_t) - 1)) == 0);
  return key_data;
}

static_always_inline vnet_crypto_thread_key_data_t
vnet_crypto_get_simple_key_data_for_thread (vnet_crypto_key_t *key,
					    clib_thread_index_t thread_index)
{
  uword key_data_offset;
  vnet_crypto_thread_key_data_t key_data;

  ASSERT (key->simple_key_data_stride != 0);
  key_data_offset = thread_index * key->simple_key_data_stride;
  key_data = vnet_crypto_get_simple_key_data_ptr (key, key_data_offset);
  ASSERT ((pointer_to_uword (key_data) & (__alignof__ (vnet_crypto_thread_key_data_t) - 1)) == 0);
  return key_data;
}

static_always_inline vnet_crypto_thread_key_data_t
vnet_crypto_get_chained_key_data_for_thread (vnet_crypto_key_t *key,
					     clib_thread_index_t thread_index)
{
  uword key_data_offset = 0;
  vnet_crypto_thread_key_data_t key_data;

  ASSERT (key->chained_key_data_stride != 0);
  key_data_offset = thread_index * key->chained_key_data_stride;
  key_data = vnet_crypto_get_chained_key_data_ptr (key, key_data_offset);
  ASSERT ((pointer_to_uword (key_data) & (__alignof__ (vnet_crypto_thread_key_data_t) - 1)) == 0);
  return key_data;
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_simple_key_data (vnet_crypto_key_t *key)
{
  ASSERT (key->simple_key_data_stride == 0);
  return key->_data + key->simple_key_data_offset;
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_chained_key_data (vnet_crypto_key_t *key)
{
  ASSERT (key->chained_key_data_stride == 0);
  return key->_data + key->chained_key_data_offset;
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_async_key_data_ptr (vnet_crypto_key_t *key, uword per_thread_offset)
{
  u16 key_data_offset = key->async_key_data_offset;
  vnet_crypto_key_data_t key_data;

  key_data = key->_data + key_data_offset + per_thread_offset;
  ASSERT ((pointer_to_uword (key_data) & (__alignof__ (vnet_crypto_key_data_t) - 1)) == 0);
  return key_data;
}

static_always_inline vnet_crypto_thread_key_data_t
vnet_crypto_get_async_key_data_for_thread (vnet_crypto_key_t *key, clib_thread_index_t thread_index)
{
  uword key_data_offset;
  vnet_crypto_thread_key_data_t key_data;

  ASSERT (key->async_key_data_stride != 0);
  key_data_offset = thread_index * key->async_key_data_stride;
  key_data = vnet_crypto_get_async_key_data_ptr (key, key_data_offset);
  ASSERT ((pointer_to_uword (key_data) & (__alignof__ (vnet_crypto_thread_key_data_t) - 1)) == 0);
  return key_data;
}

static_always_inline vnet_crypto_key_data_t
vnet_crypto_get_async_key_data (vnet_crypto_key_t *key)
{
  ASSERT (key->async_key_data_stride == 0);
  return key->_data + key->async_key_data_offset;
}

/** async crypto inline functions **/

static_always_inline vnet_crypto_async_frame_t *
vnet_crypto_async_get_frame (vlib_main_t *vm, vnet_crypto_op_id_t opt)
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
      f->op = opt;
      f->n_elts = 0;
    }

  return f;
}

static_always_inline void
vnet_crypto_async_free_frame (vlib_main_t * vm,
			      vnet_crypto_async_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  pool_put (ct->frame_pool, frame);
}

static_always_inline int
vnet_crypto_async_submit_open_frame_with_engine (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
						 vnet_crypto_async_frame_t *frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_op_id_t op = frame->op;
  vnet_crypto_frame_enq_fn_t *fn;
  u32 i;
  vlib_node_t *n;

  if (engine == VNET_CRYPTO_ENGINE_ID_NONE)
    fn = cm->opt_data[op].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC];
  else
    {
      vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
      fn = e->ops[op].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC];
    }

  frame->state = VNET_CRYPTO_FRAME_STATE_PENDING;
  frame->enqueue_thread_index = vm->thread_index;

  if (PREDICT_FALSE (fn == 0))
    {
      frame->state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
      return -1;
    }

  int ret = fn (vm, frame);

  if (PREDICT_TRUE (ret == 0))
    {
      n = vlib_get_node (vm, cm->crypto_node_index);
      if (n->state == VLIB_NODE_STATE_INTERRUPT)
	{
	  for (i = 0; i < tm->n_vlib_mains; i++)
	    vlib_node_set_interrupt_pending (vlib_get_main_by_index (i), cm->crypto_node_index);
	}
    }
  else
    {
      frame->state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
    }

  return ret;
}

static_always_inline int
vnet_crypto_async_submit_open_frame (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return vnet_crypto_async_submit_open_frame_with_engine (vm, VNET_CRYPTO_ENGINE_ID_NONE, frame);
}

static_always_inline u8 *
vnet_crypto_async_get_data_ptr (vlib_buffer_t *b, i16 offset)
{
  return offset ? b->data + offset : 0;
}

static_always_inline void
vnet_crypto_async_add_to_frame (vlib_main_t *vm, vnet_crypto_async_frame_t *f,
				vnet_crypto_key_t *key, u32 crypto_len, i16 integ_len_adj,
				i16 crypto_start_offset, i16 integ_start_offset, u32 buffer_index,
				u16 next_node, i16 iv_offset, i16 tag_offset, i16 aad_offset,
				u8 flags)
{
  vnet_crypto_async_frame_elt_t *fe;
  vnet_crypto_op_data_t *od;
  u16 index;

  ASSERT (f->n_elts < VNET_CRYPTO_FRAME_SIZE);

  index = f->n_elts;
  fe = &f->elts[index];
  od = vnet_crypto_get_op_data (f->op);
  f->n_elts++;
  fe->key = key;
  fe->crypto_total_length = crypto_len;
  fe->crypto_start_offset = crypto_start_offset;
  fe->integ_start_offset = integ_start_offset;
  fe->integ_length_adj = integ_len_adj;
  fe->iv_offset = iv_offset;
  fe->tag_offset = tag_offset;
  fe->aad_offset = aad_offset;
  fe->aad_len = od->aad_len;
  fe->digest_len = od->digest_len;
  fe->flags = flags;
  f->buffer_indices[index] = buffer_index;
  f->next_node_index[index] = next_node;
}

static_always_inline void
vnet_crypto_async_reset_frame (vnet_crypto_async_frame_t * f)
{
  vnet_crypto_op_id_t opt;
  ASSERT (f != 0);
  ASSERT ((f->state == VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED
	   || f->state == VNET_CRYPTO_FRAME_STATE_ELT_ERROR));
  opt = f->op;
  if (CLIB_DEBUG > 0)
    clib_memset (f, 0xfe, sizeof (*f));
  f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
  f->op = opt;
  f->n_elts = 0;
}

static_always_inline u8
vnet_crypto_async_frame_is_full (const vnet_crypto_async_frame_t *f)
{
  return (f->n_elts == VNET_CRYPTO_FRAME_SIZE);
}

#endif /* included_vnet_crypto_crypto_h */
