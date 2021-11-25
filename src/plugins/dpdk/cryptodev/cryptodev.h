/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 - 2021 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */
#ifndef included_cryptodev_h
#define included_cryptodev_h

#include <vnet/crypto/crypto.h>
#undef always_inline
#include <rte_cryptodev.h>

#define CRYPTODEV_NB_CRYPTO_OPS	   1024
#define CRYPTODEV_CACHE_QUEUE_SIZE VNET_CRYPTO_FRAME_POOL_SIZE
#define CRYPTODEV_CACHE_QUEUE_MASK (VNET_CRYPTO_FRAME_POOL_SIZE - 1)
#define CRYPTODEV_MAX_INFLIGHT	   (CRYPTODEV_NB_CRYPTO_OPS - 1)
#define CRYPTODEV_AAD_MASK	   (CRYPTODEV_NB_CRYPTO_OPS - 1)
#define CRYPTODEV_DEQ_CACHE_SZ	   32
#define CRYPTODEV_NB_SESSION	   4096
#define CRYPTODEV_MAX_IV_SIZE	   16
#define CRYPTODEV_MAX_AAD_SIZE	   16
#define CRYPTODEV_MAX_N_SGL	   8 /**< maximum number of segments */

#define CRYPTODEV_IV_OFFSET  (offsetof (cryptodev_op_t, iv))
#define CRYPTODEV_AAD_OFFSET (offsetof (cryptodev_op_t, aad))

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, IV_LEN, TAG_LEN, AAD_LEN, KEY_LEN
 */
#define foreach_vnet_aead_crypto_conversion                                   \
  _ (AES_128_GCM, AEAD, AES_GCM, 12, 16, 8, 16)                               \
  _ (AES_128_GCM, AEAD, AES_GCM, 12, 16, 12, 16)                              \
  _ (AES_192_GCM, AEAD, AES_GCM, 12, 16, 8, 24)                               \
  _ (AES_192_GCM, AEAD, AES_GCM, 12, 16, 12, 24)                              \
  _ (AES_256_GCM, AEAD, AES_GCM, 12, 16, 8, 32)                               \
  _ (AES_256_GCM, AEAD, AES_GCM, 12, 16, 12, 32)                              \
  _ (CHACHA20_POLY1305, AEAD, CHACHA20_POLY1305, 12, 16, 0, 32)               \
  _ (CHACHA20_POLY1305, AEAD, CHACHA20_POLY1305, 12, 16, 8, 32)               \
  _ (CHACHA20_POLY1305, AEAD, CHACHA20_POLY1305, 12, 16, 12, 32)

/**
 * crypto (alg, cryptodev_alg, key_size), hash (alg, digest-size)
 **/
#define foreach_cryptodev_link_async_alg                                      \
  _ (AES_128_CBC, AES_CBC, 16, MD5, 12)                                       \
  _ (AES_192_CBC, AES_CBC, 24, MD5, 12)                                       \
  _ (AES_256_CBC, AES_CBC, 32, MD5, 12)                                       \
  _ (AES_128_CBC, AES_CBC, 16, SHA1, 12)                                      \
  _ (AES_192_CBC, AES_CBC, 24, SHA1, 12)                                      \
  _ (AES_256_CBC, AES_CBC, 32, SHA1, 12)                                      \
  _ (AES_128_CBC, AES_CBC, 16, SHA224, 14)                                    \
  _ (AES_192_CBC, AES_CBC, 24, SHA224, 14)                                    \
  _ (AES_256_CBC, AES_CBC, 32, SHA224, 14)                                    \
  _ (AES_128_CBC, AES_CBC, 16, SHA256, 16)                                    \
  _ (AES_192_CBC, AES_CBC, 24, SHA256, 16)                                    \
  _ (AES_256_CBC, AES_CBC, 32, SHA256, 16)                                    \
  _ (AES_128_CBC, AES_CBC, 16, SHA384, 24)                                    \
  _ (AES_192_CBC, AES_CBC, 24, SHA384, 24)                                    \
  _ (AES_256_CBC, AES_CBC, 32, SHA384, 24)                                    \
  _ (AES_128_CBC, AES_CBC, 16, SHA512, 32)                                    \
  _ (AES_192_CBC, AES_CBC, 24, SHA512, 32)                                    \
  _ (AES_256_CBC, AES_CBC, 32, SHA512, 32)                                    \
  _ (AES_128_CTR, AES_CTR, 16, SHA1, 12)                                      \
  _ (AES_192_CTR, AES_CTR, 24, SHA1, 12)                                      \
  _ (AES_256_CTR, AES_CTR, 32, SHA1, 12)

typedef enum
{
  CRYPTODEV_OP_TYPE_ENCRYPT = 0,
  CRYPTODEV_OP_TYPE_DECRYPT,
  CRYPTODEV_N_OP_TYPES,
} cryptodev_op_type_t;

/* Cryptodev session data, one data per direction per numa */
typedef struct
{
  struct rte_cryptodev_sym_session ***keys;
} cryptodev_key_t;

/* Replicate DPDK rte_cryptodev_sym_capability structure with key size ranges
 * in favor of vpp vector */
typedef struct
{
  enum rte_crypto_sym_xform_type xform_type;
  union
  {
    struct
    {
      enum rte_crypto_auth_algorithm algo; /*auth algo */
      u32 *digest_sizes;		   /* vector of auth digest sizes */
    } auth;
    struct
    {
      enum rte_crypto_cipher_algorithm algo; /* cipher algo */
      u32 *key_sizes;			     /* vector of cipher key sizes */
    } cipher;
    struct
    {
      enum rte_crypto_aead_algorithm algo; /* aead algo */
      u32 *key_sizes;			   /*vector of aead key sizes */
      u32 *aad_sizes;			   /*vector of aad sizes */
      u32 *digest_sizes;		   /* vector of aead digest sizes */
    } aead;
  };
} cryptodev_capability_t;

/* Cryptodev instance data */
typedef struct
{
  u32 dev_id;
  u32 q_id;
  char *desc;
} cryptodev_inst_t;

typedef struct
{
  struct rte_mempool *sess_pool;
  struct rte_mempool *sess_priv_pool;
} cryptodev_session_pool_t;

typedef struct
{
  cryptodev_session_pool_t *sess_pools;
} cryptodev_numa_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct rte_crypto_op op;
  struct rte_crypto_sym_op sop;
  u8 iv[CRYPTODEV_MAX_IV_SIZE];
  u8 aad[CRYPTODEV_MAX_AAD_SIZE];
  vnet_crypto_async_frame_t *frame;
  u32 n_elts;
} cryptodev_op_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *b[VNET_CRYPTO_FRAME_SIZE];
  union
  {
    struct
    {
      cryptodev_op_t **cops;
      struct rte_mempool *cop_pool;
      struct rte_ring *ring;
    };
    struct
    {
      struct rte_crypto_raw_dp_ctx *ctx;
      struct rte_ring *cached_frame;
      u16 aad_index;
      u8 *aad_buf;
      u64 aad_phy_addr;
      struct rte_cryptodev_sym_session *reset_sess;
    };
  };
  u16 cryptodev_id;
  u16 cryptodev_q;
  u16 inflight;
} cryptodev_engine_thread_t;

typedef struct
{
  cryptodev_numa_data_t *per_numa_data;
  cryptodev_key_t *keys;
  cryptodev_engine_thread_t *per_thread_data;
  enum rte_iova_mode iova_mode;
  cryptodev_inst_t *cryptodev_inst;
  clib_bitmap_t *active_cdev_inst_mask;
  clib_spinlock_t tlock;
  cryptodev_capability_t *supported_caps;
  u32 sess_sz;
  u32 drivers_cnt;
  u8 is_raw_api;
} cryptodev_main_t;

extern cryptodev_main_t cryptodev_main;

static_always_inline void
cryptodev_mark_frame_err_status (vnet_crypto_async_frame_t *f,
				 vnet_crypto_op_status_t s)
{
  u32 n_elts = f->n_elts, i;

  for (i = 0; i < n_elts; i++)
    f->elts[i].status = s;
  f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
}

int cryptodev_session_create (vlib_main_t *vm, vnet_crypto_key_index_t idx,
			      u32 aad_len);

void cryptodev_sess_handler (vlib_main_t *vm, vnet_crypto_key_op_t kop,
			     vnet_crypto_key_index_t idx, u32 aad_len);

int cryptodev_check_cap_support (struct rte_cryptodev_sym_capability_idx *idx,
				 u32 key_size, u32 digest_size, u32 aad_size);

clib_error_t *cryptodev_register_cop_hdl (vlib_main_t *vm, u32 eidx);

clib_error_t *__clib_weak cryptodev_register_raw_hdl (vlib_main_t *vm,
						      u32 eidx);

clib_error_t *__clib_weak dpdk_cryptodev_init (vlib_main_t *vm);

#endif
