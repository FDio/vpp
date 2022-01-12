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

typedef struct
{
  vnet_crypto_op_status_t op_status;
  vnet_crypto_async_op_id_t op;
} crypto_dispatch_trace_t;

static u8 *
format_crypto_dispatch_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  crypto_dispatch_trace_t *t = va_arg (*args, crypto_dispatch_trace_t *);

  s = format (s, "%U: %U", format_vnet_crypto_async_op, t->op,
	      format_vnet_crypto_op_status, t->op_status);
  return s;
}

static void
vnet_crypto_async_add_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_buffer_t * b,
			     vnet_crypto_async_op_id_t op_id,
			     vnet_crypto_op_status_t status)
{
  crypto_dispatch_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
  tr->op_status = status;
  tr->op = op_id;
}

static_always_inline u32
crypto_dequeue_frame (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vnet_crypto_thread_t * ct,
		      vnet_crypto_frame_dequeue_t * hdl, u32 n_cache,
		      u32 * n_total)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 n_elts = 0;
  u32 enqueue_thread_idx = ~0;
  vnet_crypto_async_frame_t *cf = (hdl) (vm, &n_elts, &enqueue_thread_idx);
  *n_total += n_elts;

  while (cf || n_elts)
    {
      if (cf)
	{
	  vec_validate (ct->buffer_indices, n_cache + cf->n_elts);
	  vec_validate (ct->nexts, n_cache + cf->n_elts);
	  clib_memcpy_fast (ct->buffer_indices + n_cache, cf->buffer_indices,
			    sizeof (u32) * cf->n_elts);
	  if (cf->state == VNET_CRYPTO_FRAME_STATE_SUCCESS)
	    {
	      clib_memcpy_fast (ct->nexts + n_cache, cf->next_node_index,
				sizeof (u16) * cf->n_elts);
	    }
	  else
	    {
	      u32 i;
	      for (i = 0; i < cf->n_elts; i++)
		{
		  if (cf->elts[i].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
		    {
		      ct->nexts[i + n_cache] = CRYPTO_DISPATCH_NEXT_ERR_DROP;
		      vlib_node_increment_counter (vm, node->node_index,
						   cf->elts[i].status, 1);
		    }
		  else
		    ct->nexts[i + n_cache] = cf->next_node_index[i];
		}
	    }
	  n_cache += cf->n_elts;
	  if (n_cache >= VLIB_FRAME_SIZE)
	    {
	      vlib_buffer_enqueue_to_next_vec (vm, node, &ct->buffer_indices,
					       &ct->nexts, n_cache);
	      n_cache = 0;
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	    {
	      u32 i;

	      for (i = 0; i < cf->n_elts; i++)
		{
		  vlib_buffer_t *b = vlib_get_buffer (vm,
						      cf->buffer_indices[i]);
		  if (b->flags & VLIB_BUFFER_IS_TRACED)
		    vnet_crypto_async_add_trace (vm, node, b, cf->op,
						 cf->elts[i].status);
		}
	    }
	  vnet_crypto_async_free_frame (vm, cf);
	}
      /* signal enqueue-thread to dequeue the processed frame (n_elts>0) */
      if (cm->dispatch_mode == VNET_CRYPTO_ASYNC_DISPATCH_INTERRUPT
	  && n_elts > 0)
	{
	  vlib_node_set_interrupt_pending (
	    vlib_get_main_by_index (enqueue_thread_idx),
	    cm->crypto_node_index);
	}

      n_elts = 0;
      enqueue_thread_idx = 0;
      cf = (hdl) (vm, &n_elts, &enqueue_thread_idx);
      *n_total += n_elts;
    }

  return n_cache;
}

VLIB_NODE_FN (crypto_dispatch_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  u32 n_dispatched = 0, n_cache = 0, index;
  vec_foreach_index (index, cm->dequeue_handlers)
    {
      if (PREDICT_FALSE (cm->dequeue_handlers[index] == 0))
	continue;
      n_cache = crypto_dequeue_frame (
	vm, node, ct, cm->dequeue_handlers[index], n_cache, &n_dispatched);
    }
  /* *INDENT-ON* */
  if (n_cache)
    vlib_buffer_enqueue_to_next_vec (vm, node, &ct->buffer_indices, &ct->nexts,
				     n_cache);

  return n_dispatched;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (crypto_dispatch_node) = {
  .name = "crypto-dispatch",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .format_trace = format_crypto_dispatch_trace,

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
