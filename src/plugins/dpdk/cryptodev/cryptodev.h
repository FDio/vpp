/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 - 2021 Intel and/or its affiliates.
 */

#ifndef included_cryptodev_h
#define included_cryptodev_h

#include <vnet/crypto/crypto.h>
#undef always_inline
#include <rte_cryptodev.h>

#define CRYPTODEV_NB_CRYPTO_OPS	   1024
#define CRYPTODEV_CACHE_QUEUE_SIZE	      1024
#define CRYPTODEV_CACHE_QUEUE_MASK	      (CRYPTODEV_CACHE_QUEUE_SIZE - 1)
#define CRYPTODEV_MAX_INFLIGHT	   (CRYPTODEV_NB_CRYPTO_OPS - 1)
#define CRYPTODEV_AAD_MASK	   (CRYPTODEV_NB_CRYPTO_OPS - 1)
#define CRYPTODE_ENQ_MAX	   64
#define CRYPTODE_DEQ_MAX	   64
#define CRYPTODEV_NB_SESSION	   4096
#define CRYPTODEV_MAX_IV_SIZE	   16
#define CRYPTODEV_MAX_AAD_SIZE	   16
#define CRYPTODEV_MAX_N_SGL	   8 /**< maximum number of segments */
#define CRYPTODEV_MAX_PROCESED_IN_CACHE_QUEUE 8

#define CRYPTODEV_IV_OFFSET  (offsetof (cryptodev_op_t, iv))
#define CRYPTODEV_AAD_OFFSET (offsetof (cryptodev_op_t, aad))

typedef vnet_crypto_op_type_t cryptodev_op_type_t;

typedef int (cryptodev_alg_supported_fn_t) (const vnet_crypto_alg_data_t *ad,
					    vnet_crypto_op_type_t op_type);

typedef void cryptodev_session_t;
typedef cryptodev_session_t *cryptodev_key_data_t;

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
} cryptodev_op_t;

#define CRYPTODEV_FRAME_BITMAP_N_U64 (VLIB_FRAME_SIZE / 64)

typedef struct
{
  vlib_frame_t *f; /* 0 if the element is free */
  u16 n_elts;
  /* index of the frame elt where enqueue to the crypto engine is happening */
  u16 enq_elts_head;
  /* index of the frame elt where dequeue from the crypto engine is happening */
  u16 deq_elts_tail;
  u8 op_type;
  u8 aad_len; /* 1 for linked algorithms */
  u8 is_traced;
  u64 engine_err[CRYPTODEV_FRAME_BITMAP_N_U64];
  u64 bad_hmac[CRYPTODEV_FRAME_BITMAP_N_U64];
} cryptodev_cache_ring_elt_t;

typedef struct
{
  cryptodev_cache_ring_elt_t frames[CRYPTODEV_CACHE_QUEUE_SIZE];
  /* head of the cache ring */
  u16 head;
  /* tail of the cache ring */
  u16 tail;
  /* index of the frame where enqueue to the crypto engine is happening */
  u16 enq_head;
  /* index of the frame where dequeue from the crypto engine is happening */
  u16 deq_tail;
} cryptodev_cache_ring_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *b[VLIB_FRAME_SIZE];
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
  cryptodev_engine_thread_t *per_thread_data;
  enum rte_iova_mode iova_mode;
  cryptodev_inst_t *cryptodev_inst;
  clib_bitmap_t *active_cdev_inst_mask;
  clib_spinlock_t tlock;
  u32 sess_sz;
  u32 drivers_cnt;
  u32 n_numa_nodes;
  u32 enq_node_index;
  u32 deq_node_index;
  /* data path specific, submits the elements of the frame at enq_head */
  void (*enqueue_frame) (vlib_main_t *vm, cryptodev_cache_ring_elt_t *ring_elt);
  /* data path specific, returns 1 if more can be dequeued */
  u8 (*dequeue) (vlib_main_t *vm);
  u8 is_raw_api;
  u8 driver_id;
} cryptodev_main_t;

extern cryptodev_main_t cryptodev_main;

static_always_inline cryptodev_key_data_t *
cryptodev_get_key_data (vnet_crypto_ctx_t *ctx)
{
  return (cryptodev_key_data_t *) vnet_crypto_get_async_key_data (ctx);
}

static_always_inline u32
cryptodev_session_index (u32 numa_node, vnet_crypto_op_type_t op_type)
{
  return numa_node * VNET_CRYPTO_OP_N_TYPES + op_type;
}

static_always_inline cryptodev_session_t *
cryptodev_session_get (cryptodev_key_data_t *key, u32 numa_node, vnet_crypto_op_type_t op_type)
{
  return __atomic_load_n (&key[cryptodev_session_index (numa_node, op_type)], __ATOMIC_ACQUIRE);
}

static_always_inline void
cryptodev_session_set (cryptodev_key_data_t *key, u32 numa_node, vnet_crypto_op_type_t op_type,
		       cryptodev_session_t *sess)
{
  __atomic_store_n (&key[cryptodev_session_index (numa_node, op_type)], sess, __ATOMIC_RELEASE);
}

static_always_inline vnet_crypto_ctx_t **
cryptodev_frame_ctxs (cryptodev_cache_ring_elt_t *ring_elt)
{
  return vlib_frame_aux_args (ring_elt->f);
}

static_always_inline u32 *
cryptodev_frame_buffer_indices (cryptodev_cache_ring_elt_t *ring_elt)
{
  return vlib_frame_vector_args (ring_elt->f);
}

static_always_inline void
cryptodev_cache_ring_update_enq_head (cryptodev_cache_ring_t *r)
{
  if (r->frames[r->enq_head].enq_elts_head == r->frames[r->enq_head].n_elts)
    {
      r->enq_head++;
      r->enq_head &= CRYPTODEV_CACHE_QUEUE_MASK;
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

static_always_inline void
cryptodev_mark_frame_err (cryptodev_cache_ring_elt_t *ring_elt, u16 index, u8 op_s)
{
  u64 *bmp =
    op_s == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC ? ring_elt->bad_hmac : ring_elt->engine_err;

  ERROR_ASSERT (op_s != VNET_CRYPTO_OP_STATUS_COMPLETED);
  bmp[index / 64] |= 1ULL << (index % 64);
}

static_always_inline void
cryptodev_mark_frame_fill_err (cryptodev_cache_ring_elt_t *ring_elt, u16 index, u16 n, u8 op_s)
{
  ERROR_ASSERT (index + n <= ring_elt->n_elts);

  for (u16 i = index; i < index + n; i++)
    cryptodev_mark_frame_err (ring_elt, i, op_s);
}

static_always_inline cryptodev_cache_ring_elt_t *
cryptodev_cache_ring_push (cryptodev_cache_ring_t *r, vlib_frame_t *f, u8 op_type, u8 aad_len)
{
  cryptodev_cache_ring_elt_t *ring_elt = &r->frames[r->head];

  /*the ring capacity is CRYPTODEV_CACHE_QUEUE_SIZE - 1*/
  if (PREDICT_FALSE (((r->head + 1) & CRYPTODEV_CACHE_QUEUE_MASK) == r->tail))
    return 0;

  ERROR_ASSERT (ring_elt->f == 0);

  *ring_elt = (cryptodev_cache_ring_elt_t) {
    .f = f,
    .n_elts = f->n_vectors,
    .op_type = op_type,
    .aad_len = aad_len,
  };
  r->head++;
  r->head &= CRYPTODEV_CACHE_QUEUE_MASK;
  return ring_elt;
}

int cryptodev_session_create (vlib_main_t *vm, vnet_crypto_ctx_t *ctx, u32 aad_len, u32 digest_len);

void cryptodev_sess_handler (vlib_main_t *vm, vnet_crypto_ctx_t *ctx);

int cryptodev_assign_resource_auto (cryptodev_engine_thread_t *cet);
int cryptodev_assign_resource_update (cryptodev_engine_thread_t *cet, u32 cryptodev_inst_index);

u32 cryptodev_register_async_algs (vlib_main_t *vm, u32 eidx,
				   cryptodev_alg_supported_fn_t *supported,
				   const char *backend_name);

clib_error_t *cryptodev_register_cop_hdl (vlib_main_t *vm, u32 eidx);
clib_error_t *cryptodev_register_raw_hdl (vlib_main_t *vm, u32 eidx);

#endif
