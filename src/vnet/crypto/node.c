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
crypto_enqueue_to_next (vlib_main_t * vm,
			u32 thread_idx, u32 qidx, vlib_node_runtime_t * node)
{
  vnet_crypto_op_t *ops[VLIB_FRAME_SIZE], *op;
  vlib_buffer_t *b;
  u16 next;
  u32 bi;
  u32 i, n_deq;

  n_deq = vnet_crypto_async_crypto_dequeue_ops (vm, qidx, ops,
						VLIB_FRAME_SIZE);

  for (i = 0; i < n_deq; i++)
    {
      op = ops[i];
      next = op->next_node;
      bi = op->user_data;
      b = vlib_get_buffer (vm, bi);
      crypto_buffer_opaque (b)->next_index = op->next_index;
      vlib_set_next_frame_buffer (vm, node, next, bi);
      clib_mem_free (op);
    }

  return n_deq;
}

VLIB_NODE_FN (crypto_dispatch_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_queue_t *q;
  u32 i, j;
  u32 n_dispatched = 0;

  return 0;
  /* *INDENT-OFF* */
  vec_foreach_index (i, cm->threads)
  {
    vnet_crypto_thread_t *ct = vec_elt_at_index (cm->threads, i);
    if (ct->act_queues)
      clib_bitmap_foreach (j, ct->act_queues,
	({
          q = ct->queues[j];
          if (q->head != q->tail)
            n_dispatched += vnet_crypto_async_dispatch_one_queue (vm, i, j);

          crypto_enqueue_to_next (vm, i, j, node);

        }));
  }
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
