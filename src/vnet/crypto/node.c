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

static_always_inline u32
crypto_dispatch_node_one_queue (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vnet_crypto_thread_t * ct, u32 qidx)
{
  vnet_crypto_op_t *j;
  vnet_crypto_main_t *cm = &crypto_main;
  u32 n_total = 0;
  vnet_crypto_queue_t *q = ct->queues[qidx];

  j = (cm->queue_handlers[qidx]) (vm, q);
  if (j)
    n_total += 1;

  return n_total;
}

static_always_inline u32
crypto_enqueue_to_next (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vnet_crypto_thread_t * ct, u32 qi)
{
  u32 n_deq = 0;
  u32 opi = 0;
  vnet_crypto_queue_t *q;
  q = ct->queues[qi];
  u32 mask = q->size - 1;
  vnet_crypto_op_t *ops[VLIB_FRAME_SIZE];
  vnet_crypto_op_t *j;
  u32 head = q->head;

  while (1)
    {
      u32 tail = clib_atomic_load_acq_n (&q->tail);
      j = q->jobs[tail & mask];

      if (head == tail)
	{
	  clib_bitmap_set_no_check (ct->act_queues, qi, 0);
	  break;
	}

      if (j->status == VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  q->jobs[tail & mask] = 0;
	  clib_atomic_fetch_add (&q->tail, 1);
	  ops[n_deq++] = j;
	}
    }

  while (n_deq)
    {
      j = ops[opi];
      u16 next = j->next_node;
      u32 bi = j->user_data;
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      crypto_buffer_opaque (b)->next_index = j->next_index;

      vlib_set_next_frame_buffer (vm, node, next, bi);

      opi += 1;
      n_deq -= 1;
      clib_mem_free (j);
    }

  return opi;
}

VLIB_NODE_FN (crypto_dispatch_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct;
  vnet_crypto_queue_t *q;
  u32 i, n_dispatched = 0;

  /* *INDENT-OFF* */
  vec_foreach (ct, cm->threads)
    if (ct->act_queues)
      clib_bitmap_foreach (i, ct->act_queues,
	({
          q = ct->queues[i];
          if (q->head != q->tail)
	    n_dispatched += crypto_dispatch_node_one_queue (vm, node, ct, i);
        }));

  /* deactivate queues on the local thread which doesn't have pending jobs */
  ct = vec_elt_at_index (cm->threads, vm->thread_index);
  clib_bitmap_foreach (i, ct->act_queues,
    ({
      crypto_enqueue_to_next (vm, node, ct, i);
    }));
  /* *INDENT-ON* */

  return n_dispatched;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (crypto_dispatch_node) = {
  .name = "crypto-dispatch",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
