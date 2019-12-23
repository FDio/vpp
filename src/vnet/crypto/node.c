/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

#define foreach_vnet_async_crypto_error                         \
  _(AVAILABLE, "available")                                     \
  _(READY, "ready")                                             \
  _(PENDING, "pending")                                         \
  _(WORK_IN_PROGRESS, "work-in-progress")                       \
  _(COMPLETED, "async crypto op completed")                     \
  _(FAIL_NO_HANDLER, "no-handler (packet dropped)")             \
  _(FAIL_BAD_HMAC, "bad-hmac (packet dropped)")                 \
  _(ENGINE_ERR, "engine error (packet dropped)")

typedef enum
{
#define _(sym,str) VNET_CRYPTO_ASYNC_ERROR_##sym,
  foreach_vnet_async_crypto_error
#undef _
    VNET_CRYPTO_ASYNC_N_ERROR,
} vnet_crypto_async_error_t;

static char *vnet_crypto_async_error_strings[] = {
#define _(sym,string) string,
  foreach_vnet_async_crypto_error
#undef _
};

#define foreach_crypto_dispatch_next \
  _(ERR_DROP, "error-drop")

typedef enum
{
#define _(n, s) CRYPTO_DISPATCH_NEXT_##n,
  foreach_crypto_dispatch_next
#undef _
    CRYPTO_DISPATCH_N_NEXT,
} crypto_dispatch_next_t;

static_always_inline u32
crypto_dispatch_node_one_queue (vlib_main_t * vm, u32 thread_idx, u32 qidx)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = vec_elt_at_index (cm->threads, thread_idx);
  vnet_crypto_queue_t *q = &ct->queues[qidx];

  if (cm->queue_handlers && cm->queue_handlers[qidx])
    return (cm->queue_handlers[qidx]) (vm, thread_idx, q);

  return 0;
}

static_always_inline u32
crypto_dequeue_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vnet_crypto_thread_t * ct, u32 qidx,
		    u32 * bis, u16 * nexts, u32 * current_index)
{
  vnet_crypto_queue_t *q = &ct->queues[qidx];
  u32 head = q->head;
  u32 tail = q->tail;
  u32 n_deq = 0, n_err = 0;
  u32 i = *current_index;
  u32 *bi = bis + i;
  u16 *next = nexts + i;

  while (n_deq < VLIB_FRAME_SIZE)
    {
      vnet_crypto_op_t *op;

      if (head == tail)
	{
	  CLIB_MEMORY_STORE_BARRIER ();
	  clib_bitmap_set_no_check (ct->act_queues, qidx, 0);
	  break;
	}
      op = vnet_crypto_async_get_op (q, tail & VNET_CRYPTO_QUEUE_MASK);
      if (op->status <= VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS)
	break;

      if (PREDICT_FALSE (op->status > VNET_CRYPTO_OP_STATUS_COMPLETED))
	{
	  next[0] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	  vlib_node_increment_counter (vm, node->node_index, op->status, 1);
	  n_err++;
	}
      else
	next[0] = op->next;

      bi[0] = op->bi;
      op->status = VNET_CRYPTO_OP_STATUS_AVAILABLE;
      tail++;
      n_deq++;
      next++;
      bi++;
      i++;
      if (PREDICT_FALSE (i >= VLIB_FRAME_SIZE))
	{
	  vlib_buffer_enqueue_to_next (vm, node, bis, nexts, i);
	  i = 0;
	  next = nexts;
	  bi = bis;
	}
    }

  if (n_deq)
    {
      q->tail = tail;
      *current_index = i;
    }

  return n_deq - n_err;
}

VLIB_NODE_FN (crypto_dispatch_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct;
  u32 bis[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  u32 i, j, current_index = 0;
  u32 n_dispatched = 0;

  /* *INDENT-OFF* */
  vec_foreach_index (i, cm->threads)
  {
    ct = vec_elt_at_index (cm->threads, i);

    clib_bitmap_foreach (j, ct->act_queues,
    ({
      crypto_dispatch_node_one_queue (vm, i, j);
    }));
  }
  /* *INDENT-ON* */

  ct = vec_elt_at_index (cm->threads, vm->thread_index);
  clib_bitmap_foreach (j, ct->act_queues, (
					    {
					    n_dispatched +=
					    crypto_dequeue_ops (vm, node, ct,
								j, bis, nexts,
								&current_index);
					    }
		       ));

  if (n_dispatched)
    {
      vlib_node_increment_counter (vm, node->node_index,
				   VNET_CRYPTO_ASYNC_ERROR_COMPLETED,
				   n_dispatched);
      if (current_index)
	vlib_buffer_enqueue_to_next (vm, node, bis, nexts, current_index);
    }

  return n_dispatched;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (crypto_dispatch_node) = {
  .name = "crypto-dispatch",
  .type = VLIB_NODE_TYPE_INPUT,

  .n_errors = ARRAY_LEN(vnet_crypto_async_error_strings),
  .error_strings = vnet_crypto_async_error_strings,

  .n_next_nodes = CRYPTO_DISPATCH_N_NEXT,
  .next_nodes = {
#define _(n, s) \
  [CRYPTO_DISPATCH_NEXT_##n] = s,
      foreach_crypto_dispatch_next
#undef _
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
