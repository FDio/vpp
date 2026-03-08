/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#define VNET_CRYPTO_LOG_MACROS
#include <vnet/crypto/crypto.h>

static_always_inline int
vnet_crypto_hash_handler_index (vnet_crypto_handler_type_t t)
{
  ASSERT (t == VNET_CRYPTO_HANDLER_TYPE_SIMPLE || t == VNET_CRYPTO_HANDLER_TYPE_CHAINED);
  return t == VNET_CRYPTO_HANDLER_TYPE_CHAINED;
}

static_always_inline void
vnet_crypto_hash_register_handler (vnet_crypto_main_t *cm, vnet_crypto_engine_t *e,
				   vnet_crypto_hash_alg_t alg, vnet_crypto_handler_type_t t,
				   vnet_crypto_hash_fn_t *fn)
{
  vnet_crypto_engine_t *ae;
  vnet_crypto_engine_id_t engine;
  int ti;

  if (fn == 0)
    return;

  ti = vnet_crypto_hash_handler_index (t);
  engine = e - cm->engines;
  e->hash_ops[alg].handlers[ti] = fn;
  vec_validate_init_empty (cm->hash_engine_supports_alg[alg][ti], engine, 0);
  cm->hash_engine_supports_alg[alg][ti][engine] = 1;
  if (!cm->active_hash_engine_index[alg][ti])
    {
      cm->active_hash_engine_index[alg][ti] = engine;
      return;
    }

  ae = vec_elt_at_index (cm->engines, cm->active_hash_engine_index[alg][ti]);
  if (ae->priority <= e->priority)
    cm->active_hash_engine_index[alg][ti] = engine;
}

void
vnet_crypto_register_hash_handler_inline (vlib_main_t *vm __clib_unused,
					  vnet_crypto_engine_id_t engine,
					  vnet_crypto_hash_alg_t alg, vnet_crypto_hash_fn_t *fn,
					  vnet_crypto_hash_fn_t *cfn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

  vnet_crypto_hash_register_handler (cm, e, alg, VNET_CRYPTO_HANDLER_TYPE_SIMPLE, fn);
  vnet_crypto_hash_register_handler (cm, e, alg, VNET_CRYPTO_HANDLER_TYPE_CHAINED, cfn);
}

u8 *
format_vnet_crypto_hash_alg (u8 *s, va_list *args)
{
  vnet_crypto_hash_alg_t alg = va_arg (*args, int);
  vnet_crypto_main_t *cm = &crypto_main;

  if (alg >= VNET_CRYPTO_N_HASH_ALGS)
    return format (s, "unknown");

  return format (s, "%s", cm->hash_algs[alg].name);
}

static_always_inline u32
vnet_crypto_process_hash_ops_one_batch (vlib_main_t *vm, vnet_crypto_hash_op_t ops[],
					vnet_crypto_hash_op_t *op_queue[], u32 op_q_sz,
					vnet_crypto_op_chunk_t *chunks, u32 n_ops, u32 first_slot,
					u32 *n_left, u8 first_run)
{
  vnet_crypto_hash_fn_t *batch_fn;
  vnet_crypto_op_status_t bs;
  u32 slot, n_op_queue = 0;
  vnet_crypto_hash_op_t op = ops[first_slot];
  int is_chained = (op.flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS) != 0;

  ASSERT (op.ctx != 0);
  batch_fn = op.ctx->handlers[is_chained];
  bs = batch_fn ? VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS : VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER;
  ops[first_slot].status = bs;
  op_queue[n_op_queue++] = ops + first_slot;

  for (slot = first_slot + 1; slot < n_ops && n_op_queue < op_q_sz; slot++)
    {
      op = ops[slot];

      if (!first_run && op.status != VNET_CRYPTO_OP_STATUS_UNPROCESSED)
	continue;

      ASSERT (op.ctx != 0);
      if (op.ctx->handlers[(op.flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS) != 0] != batch_fn)
	{
	  if (first_run)
	    ops[slot].status = VNET_CRYPTO_OP_STATUS_UNPROCESSED;
	  continue;
	}

      ops[slot].status = bs;
      op_queue[n_op_queue++] = ops + slot;
    }

  *n_left -= n_op_queue;

  if (first_run && PREDICT_FALSE (slot < n_ops))
    for (; slot < n_ops; slot++)
      ops[slot].status = VNET_CRYPTO_OP_STATUS_UNPROCESSED;

  return batch_fn ? batch_fn (op_queue, chunks, n_op_queue, vm->thread_index) : 0;
}

u32
vnet_crypto_process_hash_ops (vlib_main_t *vm, vnet_crypto_hash_op_t ops[],
			      vnet_crypto_op_chunk_t *chunks, u32 n_ops)
{
  const int op_q_sz = VLIB_FRAME_SIZE;
  vnet_crypto_hash_op_t *queue[op_q_sz];
  u32 first_slot = 1;
  u32 n_left = n_ops;
  u32 rv = 0;

  ASSERT (n_ops >= 1);

  rv +=
    vnet_crypto_process_hash_ops_one_batch (vm, ops, queue, op_q_sz, chunks, n_ops, 0, &n_left, 1);

  while (n_left)
    {
      while (ops[first_slot].status != VNET_CRYPTO_OP_STATUS_UNPROCESSED)
	if (++first_slot == n_ops)
	  return rv;
      rv += vnet_crypto_process_hash_ops_one_batch (vm, ops, queue, op_q_sz, chunks, n_ops,
						    first_slot, &n_left, 0);
    }

  return rv;
}

vnet_crypto_hash_ctx_t *
vnet_crypto_hash_ctx_create (vnet_crypto_hash_alg_t alg)
{
  vnet_crypto_hash_ctx_t *ctx = clib_mem_alloc_aligned (sizeof (*ctx), CLIB_CACHE_LINE_BYTES);

  if (ctx == 0)
    return 0;

  clib_memset_u8 (ctx, 0, sizeof (*ctx));
  ctx->alg = alg;
  vnet_crypto_hash_ctx_set_default_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  vnet_crypto_hash_ctx_set_default_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_CHAINED);
  return ctx;
}

void
vnet_crypto_hash_ctx_destroy (vnet_crypto_hash_ctx_t *ctx)
{
  if (ctx)
    clib_mem_free (ctx);
}

void
vnet_crypto_hash_ctx_set_engine (vnet_crypto_hash_ctx_t *ctx, vnet_crypto_handler_type_t t,
				 vnet_crypto_engine_id_t engine)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e;
  int ti = vnet_crypto_hash_handler_index (t);

  ctx->engine_index[ti] = engine;
  if (engine == VNET_CRYPTO_ENGINE_ID_NONE)
    {
      ctx->handlers[ti] = 0;
      return;
    }

  e = vec_elt_at_index (cm->engines, engine);
  ctx->handlers[ti] = e->hash_ops[ctx->alg].handlers[ti];
}

void
vnet_crypto_hash_ctx_set_default_engine (vnet_crypto_hash_ctx_t *ctx, vnet_crypto_handler_type_t t)
{
  vnet_crypto_main_t *cm = &crypto_main;
  int ti = vnet_crypto_hash_handler_index (t);
  vnet_crypto_engine_id_t engine = cm->active_hash_engine_index[ctx->alg][ti];

  vnet_crypto_hash_ctx_set_engine (ctx, t, engine);
}
