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
#define CRYPTODE_ENQ_MAX	   64
#define CRYPTODE_DEQ_MAX	   64
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

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
typedef void cryptodev_session_t;
#else
typedef struct rte_cryptodev_sym_session cryptodev_session_t;
#endif

/* Cryptodev session data, one data per direction per numa */
typedef struct
{
  cryptodev_session_t ***keys;
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
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 0)
  struct rte_mempool *sess_priv_pool;
#endif
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
  vnet_crypto_async_frame_t *f;
  union
  {
    struct
    {
      /* index of frame elt where enque to
       * the crypto engine is happening */
      u8 enq_elts_head;
      /* index of the frame elt where dequeue
       * from the crypto engine is happening */
      u8 deq_elts_tail;
      u8 elts_inflight;

      u8 op_type;
      u8 aad_len;
      u8 n_elts;
      u16 reserved;
    };
    u64 raw;
  };

  u64 frame_elts_errs_mask;
} cryptodev_cache_ring_elt_t;

typedef struct
{
  cryptodev_cache_ring_elt_t frames[VNET_CRYPTO_FRAME_POOL_SIZE];

  union
  {
    struct
    {
      /* head of the cache ring */
      u16 head;
      /* tail of the cache ring */
      u16 tail;
      /* index of the frame where enqueue
       * to the crypto engine is happening */
      u16 enq_head;
      /* index of the frame where dequeue
       * from the crypto engine is happening */
      u16 deq_tail;
    };
    u64 raw;
  };
} cryptodev_cache_ring_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *b[VNET_CRYPTO_FRAME_SIZE];
  union
  {
    struct rte_mempool *cop_pool;
    struct
    {
      struct rte_crypto_raw_dp_ctx *ctx;
      u16 aad_index;
      u8 *aad_buf;
      u64 aad_phy_addr;
      cryptodev_session_t *reset_sess;
    };
  };

  cryptodev_cache_ring_t cache_ring;
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
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
  u8 driver_id;
#endif
} cryptodev_main_t;

extern cryptodev_main_t cryptodev_main;

#define CRYPTODEV_CACHE_RING_GET_FRAME(r, i)                                  \
  ((r)->frames[(i) &CRYPTODEV_CACHE_QUEUE_MASK].f)

#define CRYPTODEV_CACHE_RING_GET_ERR_MASK(r, i)                               \
  ((r)->frames[(i) &CRYPTODEV_CACHE_QUEUE_MASK].frame_elts_errs_mask)

#define CRYPTODEV_CACHE_RING_GET_FRAME_ELTS_INFLIGHT(r, i)                    \
  (((r)->frames[(i) &CRYPTODEV_CACHE_QUEUE_MASK].enq_elts_head) -             \
   ((r)->frames[(i) &CRYPTODEV_CACHE_QUEUE_MASK].deq_elts_tail))

static_always_inline void
cryptodev_cache_ring_update_enq_head (cryptodev_cache_ring_t *r,
				      vnet_crypto_async_frame_t *f)
{
  if (r->frames[r->enq_head].enq_elts_head == f->n_elts)
    {
      r->enq_head++;
      r->enq_head &= CRYPTODEV_CACHE_QUEUE_MASK;
      f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
    }
}

static_always_inline bool
cryptodev_cache_ring_update_deq_tail (cryptodev_cache_ring_t *r,
				      u16 *const deq)
{
  if (r->frames[*deq].deq_elts_tail == r->frames[*deq].n_elts)
    {
      *deq += 1;
      *deq &= CRYPTODEV_CACHE_QUEUE_MASK;
      return 1;
    }

  return 0;
}
static_always_inline u64
cryptodev_mark_frame_fill_err (vnet_crypto_async_frame_t *f, u64 current_err,
			       u16 index, u16 n, vnet_crypto_op_status_t op_s)
{
  u64 err = current_err;
  u16 i;

  ERROR_ASSERT (index + n <= VNET_CRYPTO_FRAME_SIZE);
  ERROR_ASSERT (op_s != VNET_CRYPTO_OP_STATUS_COMPLETED);

  for (i = index; i < (index + n); i++)
    f->elts[i].status = op_s;

  err |= (~(~(0u) << n) << index);

  return err;
}

static_always_inline cryptodev_cache_ring_elt_t *
cryptodev_cache_ring_push (cryptodev_cache_ring_t *r,
			   vnet_crypto_async_frame_t *f)
{
  u16 head = r->head;
  cryptodev_cache_ring_elt_t *ring_elt = &r->frames[head];
  /**
   * in debug mode we do the ring sanity test when a frame is enqueued to
   * the ring.
   **/
#if CLIB_DEBUG > 0
  u16 tail = r->tail;
  u16 n_cached = (head >= tail) ? (head - tail) :
					(CRYPTODEV_CACHE_QUEUE_MASK - tail + head);
  ERROR_ASSERT (n_cached < VNET_CRYPTO_FRAME_POOL_SIZE);
  ERROR_ASSERT (r->raw == 0 && r->frames[head].raw == 0 &&
		r->frames[head].f == 0);
#endif
  ring_elt->f = f;
  ring_elt->n_elts = f->n_elts;
  /* update head */
  r->head++;
  r->head &= CRYPTODEV_CACHE_QUEUE_MASK;
  return ring_elt;
}

static_always_inline vnet_crypto_async_frame_t *
cryptodev_cache_ring_pop (cryptodev_cache_ring_t *r)
{
  vnet_crypto_async_frame_t *f;
  u16 tail = r->tail;
  cryptodev_cache_ring_elt_t *ring_elt = &r->frames[tail];

  ERROR_ASSERT (r->frames[r->head].raw == 0 ? r->head != tail : 1);
  ERROR_ASSERT (r->frames[tail].raw != 0);
  ERROR_ASSERT (ring_elt->deq_elts_tail == ring_elt->enq_elts_head &&
		ring_elt->deq_elts_tail == ring_elt->n_elts);

  f = CRYPTODEV_CACHE_RING_GET_FRAME (r, tail);
  f->state = CRYPTODEV_CACHE_RING_GET_ERR_MASK (r, r->tail) == 0 ?
		     VNET_CRYPTO_FRAME_STATE_SUCCESS :
		     VNET_CRYPTO_FRAME_STATE_ELT_ERROR;

  clib_memset (ring_elt, 0, sizeof (*ring_elt));
  r->tail++;
  r->tail &= CRYPTODEV_CACHE_QUEUE_MASK;

  return f;
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
