/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

typedef enum
{
#define _(sym,str) VNET_CRYPTO_ASYNC_ERROR_##sym,
  foreach_crypto_op_status
#undef _
    VNET_CRYPTO_ASYNC_N_ERROR,
} vnet_crypto_async_error_t;

static char *vnet_crypto_async_error_strings[] = {
#define _(sym,string) string,
  foreach_crypto_op_status
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
vnet_crypto_post_process_ops (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vnet_crypto_async_op_data_t * odt,
			      vnet_crypto_op_t ** jobs, u32 * bis,
			      u16 * nexts, u32 n_job)
{
  vnet_crypto_op_t **job = jobs;
  u32 *bi = bis, n_left = n_job;
  u16 *next = nexts;

  if (n_left > 4)
    {
      CLIB_PREFETCH (job[0], sizeof (vnet_crypto_op_t), LOAD);
      CLIB_PREFETCH (job[1], sizeof (vnet_crypto_op_t), LOAD);
      CLIB_PREFETCH (job[2], sizeof (vnet_crypto_op_t), LOAD);
      CLIB_PREFETCH (job[3], sizeof (vnet_crypto_op_t), LOAD);
    }

  while (n_left > 8)
    {
      CLIB_PREFETCH (job[4], sizeof (vnet_crypto_op_t), LOAD);
      CLIB_PREFETCH (job[5], sizeof (vnet_crypto_op_t), LOAD);
      CLIB_PREFETCH (job[6], sizeof (vnet_crypto_op_t), LOAD);
      CLIB_PREFETCH (job[7], sizeof (vnet_crypto_op_t), LOAD);

      if (PREDICT_FALSE (job[0]->status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	{
	  next[0] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	  vlib_node_increment_counter (vm, node->node_index,
				       job[0]->status, 1);
	}
      else
	next[0] = job[0]->next;
      bi[0] = job[0]->bi;
      (odt->op_free) (vm, job[0]);

      if (PREDICT_FALSE (job[1]->status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	{
	  next[1] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	  vlib_node_increment_counter (vm, node->node_index,
				       job[1]->status, 1);
	}
      else
	next[1] = job[1]->next;
      bi[1] = job[1]->bi;
      (odt->op_free) (vm, job[1]);

      if (PREDICT_FALSE (job[2]->status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	{
	  next[2] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	  vlib_node_increment_counter (vm, node->node_index,
				       job[2]->status, 1);
	}
      else
	next[2] = job[2]->next;
      bi[2] = job[2]->bi;
      (odt->op_free) (vm, job[2]);

      if (PREDICT_FALSE (job[3]->status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	{
	  next[3] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	  vlib_node_increment_counter (vm, node->node_index,
				       job[3]->status, 1);
	}
      else
	next[3] = job[3]->next;
      bi[3] = job[3]->bi;
      (odt->op_free) (vm, job[3]);

      job += 4;
      bi += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      if (PREDICT_FALSE (job[0]->status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	{
	  next[0] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	  vlib_node_increment_counter (vm, node->node_index,
				       job[0]->status, 1);
	}
      else
	next[0] = job[0]->next;
      bi[0] = job[0]->bi;
      (odt->op_free) (vm, job[0]);

      job += 1;
      bi += 1;
      next += 1;
      n_left -= 1;
    }

  return n_job;
}

VLIB_NODE_FN (crypto_dispatch_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  u32 bis[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  u32 n_dispatched = 0;
  u32 index;
  vnet_crypto_op_t *jobs[VLIB_FRAME_SIZE];

  vec_foreach_index (index, cm->async_ops)
  {
    u32 inflight = ct->inflight[index], n_deq;
    if (!inflight)
      continue;
    vnet_crypto_async_op_data_t *odt = cm->async_ops + index;
    n_deq = (odt->dequeue_handler) (vm, jobs, VLIB_FRAME_SIZE);
    if (!n_deq)
      continue;

    ct->inflight[index] -= n_deq;

    vnet_crypto_post_process_ops (vm, node, odt, jobs, bis, nexts, n_deq);
    vlib_buffer_enqueue_to_next (vm, node, bis, nexts, n_deq);
    n_dispatched += n_deq;
  }

  return n_dispatched;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (crypto_dispatch_node) = {
  .name = "crypto-dispatch",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,

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
