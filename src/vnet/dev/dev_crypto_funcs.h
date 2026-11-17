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

/* queue of the thread which takes new requests */
static_always_inline vnet_dev_crypto_queue_t *
vnet_dev_crypto_get_enq_thread_queue (vnet_dev_crypto_engine_t *e, clib_thread_index_t ti)
{
  vnet_dev_crypto_queue_t *cq = vnet_dev_crypto_get_thread_queue (e, ti);

  return cq && cq->stopping == 0 ? cq : 0;
}

/* least loaded queue of the thread which takes new requests, all queues of an engine can do the
 * same algorithms */
static_always_inline vnet_dev_crypto_queue_t *
vnet_dev_crypto_get_least_loaded_queue (vnet_dev_crypto_engine_t *e, clib_thread_index_t ti)
{
  vnet_dev_crypto_queue_t **qs = vnet_dev_crypto_get_thread_queues (e, ti);
  vnet_dev_crypto_queue_t *best = 0;

  if (PREDICT_TRUE (vec_len (qs) == 1))
    return qs[0]->stopping ? 0 : qs[0];

  for (u32 i = 0; i < vec_len (qs); i++)
    if (qs[i]->stopping == 0 &&
	(best == 0 || qs[i]->enq_req - qs[i]->deq_req < best->enq_req - best->deq_req))
      best = qs[i];

  return best;
}

/* hands a completed frame over to the consumer, status is per frame element, 0 if all elements
 * completed */
static_always_inline void
vnet_dev_crypto_frame_done (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
			    vnet_crypto_op_status_t *status)
{
  if (PREDICT_FALSE (status != 0))
    vnet_crypto_frame_set_statuses (vm, frame, status);

  vnet_crypto_frame_to_consumer (vm, node, frame, VNET_CRYPTO_OP_STATUS_COMPLETED);
}

static_always_inline vnet_dev_crypto_engine_t *
vnet_dev_crypto_node_engine (vlib_node_runtime_t *node)
{
  return vnet_dev_main.crypto_engines[*(u32 *) node->runtime_data];
}

/* hands a frame enqueued on a thread without a queue of the engine over to the consumer */
static_always_inline u32
vnet_dev_crypto_frame_no_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_crypto_node_engine (node)->enq_no_queue[vm->thread_index] += frame->n_vectors;
  return vnet_crypto_frame_to_consumer (vm, node, frame, VNET_CRYPTO_OP_STATUS_FAIL_NO_QUEUE);
}
