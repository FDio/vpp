/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vnet/dev/dev.h>

static_always_inline void *
vnet_dev_get_crypto_queue_data (vnet_dev_crypto_queue_t *cq)
{
  return cq->data;
}

static_always_inline vnet_dev_crypto_queue_t *
vnet_dev_crypto_queue_from_data (void *p)
{
  return (void *) ((u8 *) p - STRUCT_OFFSET_OF (vnet_dev_crypto_queue_t, data));
}

static_always_inline vnet_dev_crypto_engine_t *
vnet_dev_crypto_get_engine (vnet_crypto_engine_id_t engine)
{
  u8 *index_by_id = vnet_dev_main.crypto_engine_index_by_id;

  if (engine >= vec_len (index_by_id) || index_by_id[engine] == CLIB_U8_MAX)
    return 0;
  return vnet_dev_main.crypto_engines[index_by_id[engine]];
}

static_always_inline vnet_dev_crypto_queue_t **
vnet_dev_crypto_get_thread_queues (vnet_dev_crypto_engine_t *e, clib_thread_index_t ti)
{
  return e->thread_queues ? e->thread_queues[ti] : 0;
}

/* for groups without multi_queue_per_thread, where a thread has at most one queue */
static_always_inline vnet_dev_crypto_queue_t *
vnet_dev_crypto_get_thread_queue (vnet_dev_crypto_engine_t *e, clib_thread_index_t ti)
{
  vnet_dev_crypto_queue_t **qs = vnet_dev_crypto_get_thread_queues (e, ti);

  return vec_len (qs) ? qs[0] : 0;
}

/* least loaded queue of the thread, all queues of an engine can do the same algorithms */
static_always_inline vnet_dev_crypto_queue_t *
vnet_dev_crypto_get_least_loaded_queue (vnet_dev_crypto_engine_t *e, clib_thread_index_t ti)
{
  vnet_dev_crypto_queue_t **qs = vnet_dev_crypto_get_thread_queues (e, ti);
  vnet_dev_crypto_queue_t *best;

  if (PREDICT_TRUE (vec_len (qs) == 1))
    return qs[0];

  if (vec_len (qs) == 0)
    return 0;

  best = qs[0];
  for (u32 i = 1; i < vec_len (qs); i++)
    if (qs[i]->enq_req - qs[i]->deq_req < best->enq_req - best->deq_req)
      best = qs[i];

  return best;
}

/* sends the buffers of a completed frame to the next node and frees the frame, status is per
 * frame element, 0 if all elements completed */
static_always_inline void
vnet_dev_crypto_frame_done (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
			    vnet_crypto_op_status_t *status)
{
  vnet_crypto_deq_scalar_data_t *sd = vlib_frame_scalar_args (frame);
  u32 *bi = vlib_frame_vector_args (frame), n = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE];

  if (PREDICT_TRUE (status == 0))
    {
      vlib_buffer_enqueue_to_single_next (vm, node, bi, sd->next_node_index, n);
      vlib_frame_free (vm, frame);
      return;
    }

  for (u32 i = 0; i < n; i++)
    {
      vlib_buffer_t *b;

      nexts[i] = sd->next_node_index;
      if (PREDICT_TRUE (status[i] == VNET_CRYPTO_OP_STATUS_COMPLETED))
	continue;

      b = vlib_get_buffer (vm, bi[i]);
      b->error = node->errors[status[i] == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC ?
				VNET_DEV_CRYPTO_ERROR_BAD_HMAC :
				VNET_DEV_CRYPTO_ERROR_ENGINE_ERROR];
      nexts[i] = 0;
    }

  vlib_buffer_enqueue_to_next (vm, node, bi, nexts, n);
  vlib_frame_free (vm, frame);
}

static_always_inline vnet_dev_crypto_engine_t *
vnet_dev_crypto_node_engine (vlib_node_runtime_t *node)
{
  return vnet_dev_main.crypto_engines[*(u32 *) node->runtime_data];
}
