/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#pragma once

#ifndef included_vnet_crypto_crypto_h
#error "include <vnet/crypto/crypto.h> before <vnet/crypto/hash.h>"
#endif

typedef enum
{
  VNET_CRYPTO_HASH_ALG_NONE = 0,
#define _(n, s, cf, inf, d, b) VNET_CRYPTO_HASH_ALG_##n,
  foreach_crypto_hash_alg
#undef _
    VNET_CRYPTO_N_HASH_ALGS,
} __clib_packed vnet_crypto_hash_alg_t;

typedef struct
{
  vnet_crypto_engine_id_t engine_index[2];
  void *handlers[2];
  vnet_crypto_hash_alg_t alg : 8;
} vnet_crypto_hash_ctx_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_hash_ctx_t *ctx;
  u8 *digest;
  union
  {
    u8 *src;
    u32 chunk_index;
  };
  u32 user_data;
  union
  {
    u32 len;
    u16 n_chunks;
  };
  u8 status : 4;
  u8 flags : 4;
} vnet_crypto_hash_op_t;

STATIC_ASSERT_SIZEOF (vnet_crypto_hash_op_t, CLIB_CACHE_LINE_BYTES);

typedef u32 (vnet_crypto_hash_fn_t) (vnet_crypto_hash_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				     u32 n_ops, clib_thread_index_t thread_index);

typedef struct vnet_crypto_hash_alg_data_t_
{
  char *name;
  vnet_crypto_alg_family_t family;
  u8 digest_len;
  u8 block_len;
  vnet_crypto_alg_t alg;
} vnet_crypto_hash_alg_data_t;

u32 vnet_crypto_process_hash_ops (vlib_main_t *vm, vnet_crypto_hash_op_t ops[],
				  vnet_crypto_op_chunk_t *chunks, u32 n_ops);
vnet_crypto_hash_ctx_t *vnet_crypto_hash_ctx_create (vnet_crypto_hash_alg_t alg);
void vnet_crypto_hash_ctx_destroy (vnet_crypto_hash_ctx_t *ctx);
void vnet_crypto_hash_ctx_set_engine (vnet_crypto_hash_ctx_t *ctx, vnet_crypto_handler_type_t t,
				      vnet_crypto_engine_id_t engine);
void vnet_crypto_hash_ctx_set_default_engine (vnet_crypto_hash_ctx_t *ctx,
					      vnet_crypto_handler_type_t t);
void vnet_crypto_register_hash_handler_inline (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					       vnet_crypto_hash_alg_t alg,
					       vnet_crypto_hash_fn_t *fn,
					       vnet_crypto_hash_fn_t *cfn);

format_function_t format_vnet_crypto_hash_alg;

static_always_inline void
vnet_crypto_hash_op_init (vnet_crypto_hash_op_t *op)
{
  if (CLIB_DEBUG > 0)
    clib_memset (op, 0xfe, sizeof (*op));
  op->status = VNET_CRYPTO_OP_STATUS_UNPROCESSED;
  op->flags = 0;
  op->n_chunks = 0;
}
