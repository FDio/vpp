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

VLIB_NODE_FN (crypto_dispatch_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  u32 bis[VLIB_FRAME_SIZE], *bi;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vnet_crypto_op_async_data_t post_ops[VLIB_FRAME_SIZE], *post_op;
  u32 n_dispatched = 0;
  u32 index;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (index, cm->async_op_state, ({
    u32 inflight = ct->async_inflight[index], n, n_deq;
    if (!inflight)
      continue;
    n_deq = (cm->dequeue_handlers [index]) (vm, post_ops, VLIB_FRAME_SIZE);
    if (!n_deq)
      continue;
    post_op = post_ops;
    bi = bis;
    next = nexts;
    n = n_deq;
    while (n >= 4)
      {
	bi[0] = post_op[0].bi;
	if (PREDICT_FALSE (post_op[0].status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	  {
	    next[0] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	    vlib_node_increment_counter (vm, node->node_index,
					post_op[0].status, 1);
	  }
	else
	  {
	    next[0] = post_op[0].next;
	  }

	bi[1] = post_op[1].bi;
	if (PREDICT_FALSE (post_op[1].status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	  {
	    next[1] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	    vlib_node_increment_counter (vm, node->node_index,
					post_op[1].status, 1);
	  }
	else
	  {
	    next[1] = post_op[1].next;
	  }

	bi[2] = post_op[2].bi;
	if (PREDICT_FALSE (post_op[2].status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	  {
	    next[2] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	    vlib_node_increment_counter (vm, node->node_index,
					post_op[2].status, 1);
	  }
	else
	  {
	    next[2] = post_op[2].next;
	  }

	bi[3] = post_op[3].bi;
	if (PREDICT_FALSE (post_op[3].status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	  {
	    next[3] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	    vlib_node_increment_counter (vm, node->node_index,
					post_op[3].status, 1);
	  }
	else
	  {
	    next[3] = post_op[3].next;
	  }
	bi += 4;
	next += 4;
	post_op += 4;
	n -= 4;
      }

    while (n)
      {
	bi[0] = post_op[0].bi;
	if (PREDICT_FALSE (post_op[0].status != VNET_CRYPTO_OP_STATUS_COMPLETED))
	  {
	    next[0] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
	    vlib_node_increment_counter (vm, node->node_index,
					post_op[0].status, 1);
	  }
	else
	  {
	    next[0] = post_op[0].next;
	  }
	bi++;
	next++;
	post_op++;
	n--;
      }

    vlib_buffer_enqueue_to_next (vm, node, bis, nexts, n_deq);
    n_dispatched += n_deq;
    ct->async_inflight[index] -= n_deq;
  }));
  /* *INDENT-ON* */

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
