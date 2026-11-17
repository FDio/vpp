/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/compress.h>

typedef enum
{
  CRYPTO_ENQ_ERROR_NO_HANDLER,
  CRYPTO_ENQ_N_ERROR,
} crypto_enq_error_t;

static char *crypto_enq_error_strings[] = {
  [CRYPTO_ENQ_ERROR_NO_HANDLER] = "no-handler",
};

/* sends buffers of one algorithm and engine to the engine, or to the consumer if the engine has
 * no handler */
static_always_inline void
crypto_enq_send (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_crypto_frame_scalar_data_t *s,
		 vnet_crypto_engine_id_t engine, u32 *bi, vnet_crypto_ctx_t **ctxs, u32 n)
{
  vnet_crypto_engine_op_t *op = &crypto_main.engines[engine].ops[s->alg][s->op_type];
  vlib_frame_t *f;

  if (PREDICT_TRUE (op->handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC] != 0))
    {
      vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar (vm, node, bi, (u64 *) ctxs,
								op->enq_next_index, n, s);
      return;
    }

  /* failure bitmap is per frame, so the consumer gets a frame of its own */
  f = vlib_get_frame_to_node (vm,
			      vlib_get_node (vm, node->node_index)->next_nodes[s->next_node_index]);
  f->n_vectors = n;
  vlib_buffer_copy_indices (vlib_frame_vector_args (f), bi, n);
  clib_memcpy_fast (vlib_frame_aux_args (f), ctxs, n * sizeof (ctxs[0]));
  *(vnet_crypto_frame_scalar_data_t *) vlib_frame_scalar_args (f) = *s;
  vlib_node_increment_counter (vm, node->node_index, CRYPTO_ENQ_ERROR_NO_HANDLER, n);
  vnet_crypto_frame_to_consumer (vm, node, f, VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
}

STATIC_ASSERT (sizeof (vnet_crypto_engine_id_t) == 1 && sizeof (vnet_crypto_alg_t) == 1,
	       "engine and algorithm pair is a u16 key");

static_always_inline vnet_crypto_engine_id_t
crypto_enq_ctx_engine (vnet_crypto_ctx_t *ctx, vnet_crypto_op_type_t type)
{
  vnet_crypto_handler_type_t t = VNET_CRYPTO_HANDLER_TYPE_ASYNC;
  vnet_crypto_engine_id_t engine = vnet_crypto_ctx_get_engine (ctx, t);

  if (engine == VNET_CRYPTO_ENGINE_ID_NONE)
    engine = crypto_main.active_op_engine_index[ctx->alg][type][t];
  return engine;
}

VLIB_NODE_FN (crypto_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  vnet_crypto_ctx_t **ctx = vlib_frame_aux_args (frame), *last = ctx[0];
  vnet_crypto_enq_scalar_data_t *scalar = vlib_frame_scalar_args (frame);
  vnet_crypto_frame_scalar_data_t s = {
    .next_node_index = scalar->next_node_index,
    .op_type = scalar->op_type,
  };
  u32 bi[VLIB_FRAME_SIZE], n_vectors = frame->n_vectors, n_left = n_vectors, off = 0;
  vnet_crypto_ctx_t *ctxs[VLIB_FRAME_SIZE];
  vlib_frame_bitmap_t mask, used = {};
  u16 keys[VLIB_FRAME_SIZE], key, first_key;
  u8 mixed = 0;

  /* engine and algorithm pair of each buffer, buffers of one SA share the ctx, so the engine is
   * looked up only when the ctx changes */
  key = first_key = crypto_enq_ctx_engine (last, s.op_type) << 8 | last->alg;
  for (u32 i = 0; i < n_vectors; i++)
    {
      if (ctx[i] != last)
	{
	  last = ctx[i];
	  key = crypto_enq_ctx_engine (last, s.op_type) << 8 | last->alg;
	  mixed |= key != first_key;
	}
      keys[i] = key;
    }

  s.alg = first_key & 0xff;
  if (PREDICT_TRUE (mixed == 0))
    {
      crypto_enq_send (vm, node, &s, first_key >> 8, from, ctx, n_vectors);
      return n_vectors;
    }

  /* buffers of each engine and algorithm pair go out together */
  for (key = first_key;;)
    {
      u32 n;

      clib_mask_compare_u16 (key, keys, mask, n_vectors);
      n = clib_compress_u32 (bi, from, mask, n_vectors);
      clib_compress_u64 ((u64 *) ctxs, (u64 *) ctx, mask, n_vectors);
      s.alg = key & 0xff;
      crypto_enq_send (vm, node, &s, key >> 8, bi, ctxs, n);

      n_left -= n;
      if (n_left == 0)
	break;

      vlib_frame_bitmap_or (used, mask);
      while (used[off] == ~0)
	off++;
      key = keys[off * uword_bits + count_trailing_zeros (~used[off])];
    }

  return n_vectors;
}

VLIB_REGISTER_NODE (crypto_enq_node) = {
  .name = "crypto-enq",
  .vector_size = sizeof (u32),
  .scalar_size = sizeof (vnet_crypto_enq_scalar_data_t),
  .aux_size = sizeof (vnet_crypto_ctx_t *),
  .n_errors = CRYPTO_ENQ_N_ERROR,
  .error_strings = crypto_enq_error_strings,
  .sibling_of = "crypto-async",
};

/* never dispatched, its siblings share its next nodes and consumers take its frame layout */
VLIB_NODE_FN (crypto_async_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return 0; }

VLIB_REGISTER_NODE (crypto_async_node) = {
  .name = "crypto-async",
  .vector_size = sizeof (u32),
  .scalar_size = sizeof (vnet_crypto_frame_scalar_data_t),
  .aux_size = sizeof (vnet_crypto_ctx_t *),
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
