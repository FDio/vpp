/*
 * l2_uu_fwd.c : Foward unknown unicast packets to BD's configured interface
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_input.h>

#define foreach_l2_uu_fwd_error					\
_(L2_UU_FWD,           "L2 UU fwd")

typedef enum
{
#define _(sym,str) L2_UU_FWD_ERROR_##sym,
  foreach_l2_uu_fwd_error
#undef _
    L2_UU_FWD_N_ERROR,
} l2_uu_fwd_error_t;

static char *l2_uu_fwd_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_uu_fwd_error
#undef _
};

typedef enum
{
  L2_UU_FWD_NEXT_DROP,
  L2_UU_FWD_NEXT_L2_OUTPUT,
  L2_UU_FWD_N_NEXT,
} l2_uu_fwd_next_t;

typedef struct
{
  u32 sw_if_index;
} l2_uu_fwd_trace_t;

/* packet trace format function */
static u8 *
format_l2_uu_fwd_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_uu_fwd_trace_t *t = va_arg (*args, l2_uu_fwd_trace_t *);

  s = format (s, "l2-uu-fwd: sw_if_index %d", t->sw_if_index);
  return s;
}

VLIB_NODE_FN (l2_uu_fwd_node) (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2_uu_fwd_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  const l2_bridge_domain_t *bdc0, *bdc1, *bdc2, *bdc3;
	  l2_uu_fwd_next_t next0, next1, next2, next3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 bi0, bi1, bi2, bi3;

	  {
	    vlib_buffer_t *b4, *b5, *b6, *b7;

	    b4 = vlib_get_buffer (vm, from[4]);
	    b5 = vlib_get_buffer (vm, from[5]);
	    b6 = vlib_get_buffer (vm, from[6]);
	    b7 = vlib_get_buffer (vm, from[7]);

	    vlib_prefetch_buffer_header (b4, STORE);
	    vlib_prefetch_buffer_header (b5, STORE);
	    vlib_prefetch_buffer_header (b6, STORE);
	    vlib_prefetch_buffer_header (b7, STORE);
	  }
	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  bi2 = to_next[2] = from[2];
	  bi3 = to_next[3] = from[3];

	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  next3 = next2 = next1 = next0 = L2_UU_FWD_NEXT_L2_OUTPUT;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  bdc0 = vec_elt_at_index (l2input_main.bd_configs,
				   vnet_buffer (b0)->l2.bd_index);
	  bdc1 = vec_elt_at_index (l2input_main.bd_configs,
				   vnet_buffer (b1)->l2.bd_index);
	  bdc2 = vec_elt_at_index (l2input_main.bd_configs,
				   vnet_buffer (b2)->l2.bd_index);
	  bdc3 = vec_elt_at_index (l2input_main.bd_configs,
				   vnet_buffer (b3)->l2.bd_index);

	  ASSERT (~0 != bdc0->uu_fwd_sw_if_index);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = bdc0->uu_fwd_sw_if_index;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = bdc1->uu_fwd_sw_if_index;
	  vnet_buffer (b2)->sw_if_index[VLIB_TX] = bdc2->uu_fwd_sw_if_index;
	  vnet_buffer (b3)->sw_if_index[VLIB_TX] = bdc3->uu_fwd_sw_if_index;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_uu_fwd_trace_t *t;

	      t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = bdc0->uu_fwd_sw_if_index;
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_uu_fwd_trace_t *t;

	      t = vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = bdc1->uu_fwd_sw_if_index;
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_uu_fwd_trace_t *t;

	      t = vlib_add_trace (vm, node, b2, sizeof (*t));
	      t->sw_if_index = bdc2->uu_fwd_sw_if_index;
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_uu_fwd_trace_t *t;

	      t = vlib_add_trace (vm, node, b3, sizeof (*t));
	      t->sw_if_index = bdc3->uu_fwd_sw_if_index;
	    }
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const l2_bridge_domain_t *bdc0;
	  l2_uu_fwd_next_t next0;
	  vlib_buffer_t *b0;
	  u32 bi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = L2_UU_FWD_NEXT_L2_OUTPUT;
	  b0 = vlib_get_buffer (vm, bi0);

	  bdc0 = vec_elt_at_index (l2input_main.bd_configs,
				   vnet_buffer (b0)->l2.bd_index);
	  ASSERT (~0 != bdc0->uu_fwd_sw_if_index);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = bdc0->uu_fwd_sw_if_index;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_uu_fwd_trace_t *t;

	      t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = bdc0->uu_fwd_sw_if_index;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       L2_UU_FWD_ERROR_L2_UU_FWD, frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_uu_fwd_node) = {
  .name = "l2-uu-fwd",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_uu_fwd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_uu_fwd_error_strings),
  .error_strings = l2_uu_fwd_error_strings,

  .n_next_nodes = L2_UU_FWD_N_NEXT,

  .next_nodes = {
        [L2_UU_FWD_NEXT_DROP] = "error-drop",
        [L2_UU_FWD_NEXT_L2_OUTPUT] = "l2-output",
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
