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
crypto_dispatch_node_one_queue (vlib_main_t * vm, vnet_crypto_thread_t * ct,
				u32 qidx)
{
  vnet_async_crypto_op_t *j;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_queue_t *q;
  q = ct->queues[qidx];

  j = (cm->queue_handlers[qidx]) (vm, q);
  if (j)
    {
      /* enqueue finished job back to its original thread */
      vec_validate_init_empty_aligned(ct->jobs_done, j->next_node,
              NULL, CLIB_CACHE_LINE_BYTES);
      q = ct->jobs_done[j->next_node];

      if (PREDICT_FALSE (q == 0))
        {
          u32 sz = VNET_CRYPTO_RING_SIZE * sizeof (void *) + sizeof (*q);
          q = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
          ct->jobs_done[j->next_node] = q;
          clib_memset_u8 (q, 0, sz);
          q->size = VNET_CRYPTO_RING_SIZE;
        }

      u32 mask = q->size - 1;
      q->jobs[q->head & mask] = j;
      q->head += 1;
    }
  return j != NULL;
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
	    n_dispatched += crypto_dispatch_node_one_queue (vm, ct, i);
        }));

  /* deactivate queues on the local thread which doesn't have pending jobs */
  ct = vec_elt_at_index (cm->threads, vm->thread_index);
  clib_bitmap_foreach (i, ct->act_queues,
    ({
      q = ct->queues[i];
      if (q->head == q->tail)
        clib_bitmap_set_no_check (ct->act_queues, i, 0);
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
