/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

typedef enum
{
  CRYPTO_ENQ_ERROR_NO_HANDLER,
  CRYPTO_ENQ_N_ERROR,
} crypto_enq_error_t;

static char *crypto_enq_error_strings[] = {
  [CRYPTO_ENQ_ERROR_NO_HANDLER] = "no-handler",
};

typedef enum
{
  CRYPTO_ENQ_NEXT_DROP,
  CRYPTO_ENQ_N_NEXT,
} crypto_enq_next_t;

VLIB_NODE_FN (crypto_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_handler_type_t t = VNET_CRYPTO_HANDLER_TYPE_ASYNC;
  u32 *from = vlib_frame_vector_args (frame);
  vnet_crypto_ctx_t **ctx = vlib_frame_aux_args (frame);
  vnet_crypto_deq_scalar_data_t *scalar = vlib_frame_scalar_args (frame);
  vnet_crypto_op_type_t type = scalar->op_type;
  vnet_crypto_engine_id_t engines[VLIB_FRAME_SIZE];
  u32 bi[VLIB_FRAME_SIZE], drop_bi[VLIB_FRAME_SIZE];
  vnet_crypto_ctx_t *ctxs[VLIB_FRAME_SIZE];
  u32 n_vectors = frame->n_vectors, n_left = n_vectors, n_drop = 0;
  u8 done[VLIB_FRAME_SIZE] = {};

  for (u32 i = 0; i < n_vectors; i++)
    {
      engines[i] = vnet_crypto_ctx_get_engine (ctx[i], t);
      if (engines[i] == VNET_CRYPTO_ENGINE_ID_NONE)
	engines[i] = cm->active_op_engine_index[ctx[i]->alg][type][t];
    }

  /* buffers of each algorithm and engine pair go out together */
  for (u32 first = 0; n_left; first++)
    {
      vnet_crypto_alg_t alg;
      vnet_crypto_engine_t *e;
      u32 n = 0;

      if (done[first])
	continue;

      alg = ctx[first]->alg;
      for (u32 i = first; i < n_vectors; i++)
	if (done[i] == 0 && ctx[i]->alg == alg && engines[i] == engines[first])
	  {
	    bi[n] = from[i];
	    ctxs[n++] = ctx[i];
	    done[i] = 1;
	  }
      n_left -= n;

      e = vec_elt_at_index (cm->engines, engines[first]);
      if (PREDICT_FALSE (e->ops[alg][type].handlers[t] == 0))
	{
	  vlib_node_increment_counter (vm, node->node_index, CRYPTO_ENQ_ERROR_NO_HANDLER, n);
	  clib_memcpy_fast (drop_bi + n_drop, bi, n * sizeof (bi[0]));
	  n_drop += n;
	}
      else
	{
	  vnet_crypto_deq_scalar_data_t s = {
	    .next_node_index = scalar->next_node_index,
	    .op_type = type,
	    .alg = alg,
	  };

	  vlib_buffer_enqueue_to_single_next_with_aux64_and_scalar (
	    vm, node, bi, (u64 *) ctxs, e->ops[alg][type].enq_next_index, n, &s);
	}
    }

  if (n_drop)
    vlib_buffer_enqueue_to_single_next (vm, node, drop_bi, CRYPTO_ENQ_NEXT_DROP, n_drop);

  return n_vectors;
}

VLIB_REGISTER_NODE (crypto_enq_node) = {
  .name = "crypto-enq",
  .vector_size = sizeof (u32),
  .scalar_size = sizeof (vnet_crypto_deq_scalar_data_t),
  .aux_size = sizeof (vnet_crypto_ctx_t *),
  .n_errors = CRYPTO_ENQ_N_ERROR,
  .error_strings = crypto_enq_error_strings,
  .n_next_nodes = CRYPTO_ENQ_N_NEXT,
  .next_nodes = {
    [CRYPTO_ENQ_NEXT_DROP] = "error-drop",
  },
};
