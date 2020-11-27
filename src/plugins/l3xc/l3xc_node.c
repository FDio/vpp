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

#include <plugins/l3xc/l3xc.h>
#include <vnet/feature/feature.h>

typedef enum l3xc_next_t_
{
  L3XC_NEXT_DROP,
  L3XC_N_NEXT,
} l3xc_next_t;

typedef struct l3xc_input_trace_t_
{
  index_t l3xci;
  index_t lbi;
} l3xc_input_trace_t;

typedef enum
{
#define l3xc_error(n,s) L3XC_ERROR_##n,
#include "l3xc_error.def"
#undef l3xc_error
  L3XC_N_ERROR,
} l3xc_error_t;

always_inline uword
l3xc_input_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame, fib_protocol_t fproto)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left, *from;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 8)
    {
      const l3xc_t *l3xc0, *l3xc1, *l3xc2, *l3xc3;
      u32 l3xci0, l3xci1, l3xci2, l3xci3;
      u32 next_u32;

      /* Prefetch next iteration. */
      {
	vlib_prefetch_buffer_header (b[4], LOAD);
	vlib_prefetch_buffer_header (b[5], LOAD);
	vlib_prefetch_buffer_header (b[6], LOAD);
	vlib_prefetch_buffer_header (b[7], LOAD);
      }

      l3xci0 =
	*(u32 *) vnet_feature_next_with_data (&next_u32, b[0],
					      sizeof (l3xci0));
      l3xci1 =
	*(u32 *) vnet_feature_next_with_data (&next_u32, b[1],
					      sizeof (l3xci1));
      l3xci2 =
	*(u32 *) vnet_feature_next_with_data (&next_u32, b[2],
					      sizeof (l3xci2));
      l3xci3 =
	*(u32 *) vnet_feature_next_with_data (&next_u32, b[3],
					      sizeof (l3xci3));

      l3xc0 = l3xc_get (l3xci0);
      l3xc1 = l3xc_get (l3xci1);
      l3xc2 = l3xc_get (l3xci2);
      l3xc3 = l3xc_get (l3xci3);

      next[0] = l3xc0->l3xc_dpo.dpoi_next_node;
      next[1] = l3xc1->l3xc_dpo.dpoi_next_node;
      next[2] = l3xc2->l3xc_dpo.dpoi_next_node;
      next[3] = l3xc3->l3xc_dpo.dpoi_next_node;

      vnet_buffer (b[0])->ip.adj_index = l3xc0->l3xc_dpo.dpoi_index;
      vnet_buffer (b[1])->ip.adj_index = l3xc1->l3xc_dpo.dpoi_index;
      vnet_buffer (b[2])->ip.adj_index = l3xc2->l3xc_dpo.dpoi_index;
      vnet_buffer (b[3])->ip.adj_index = l3xc3->l3xc_dpo.dpoi_index;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      l3xc_input_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      tr->l3xci = l3xci0;
	      tr->lbi = vnet_buffer (b[0])->ip.adj_index;
	    }
	  if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      l3xc_input_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b[1], sizeof (*tr));
	      tr->l3xci = l3xci1;
	      tr->lbi = vnet_buffer (b[1])->ip.adj_index;
	    }
	  if (PREDICT_FALSE (b[2]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      l3xc_input_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b[2], sizeof (*tr));
	      tr->l3xci = l3xci2;
	      tr->lbi = vnet_buffer (b[2])->ip.adj_index;
	    }
	  if (PREDICT_FALSE (b[3]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      l3xc_input_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b[3], sizeof (*tr));
	      tr->l3xci = l3xci3;
	      tr->lbi = vnet_buffer (b[3])->ip.adj_index;
	    }
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      u32 l3xci0, next_u32;
      const l3xc_t *l3xc0;

      l3xci0 =
	*(u32 *) vnet_feature_next_with_data (&next_u32, b[0],
					      sizeof (l3xci0));

      l3xc0 = l3xc_get (l3xci0);

      next[0] = l3xc0->l3xc_dpo.dpoi_next_node;

      vnet_buffer (b[0])->ip.adj_index = l3xc0->l3xc_dpo.dpoi_index;

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  l3xc_input_trace_t *tr;

	  tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->l3xci = l3xci0;
	  tr->lbi = vnet_buffer (b[0])->ip.adj_index;
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

static uword
l3xc_input_ip4 (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return l3xc_input_inline (vm, node, frame, FIB_PROTOCOL_IP4);
}

static uword
l3xc_input_ip6 (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return l3xc_input_inline (vm, node, frame, FIB_PROTOCOL_IP6);
}

static u8 *
format_l3xc_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l3xc_input_trace_t *t = va_arg (*args, l3xc_input_trace_t *);

  s = format (s, "l3xc-index:%d lb-index:%d", t->l3xci, t->lbi);
  return s;
}

static char *l3xc_error_strings[] = {
#define l3xc_error(n,s) s,
#include "l3xc_error.def"
#undef l3xc_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l3xc_ip4_node) =
{
  .function = l3xc_input_ip4,
  .name = "l3xc-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_l3xc_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = L3XC_N_ERROR,
  .error_strings = l3xc_error_strings,
  .n_next_nodes = L3XC_N_NEXT,
  .next_nodes =
  {
    [L3XC_NEXT_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (l3xc_ip6_node) =
{
  .function = l3xc_input_ip6,
  .name = "l3xc-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_l3xc_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = L3XC_N_NEXT,

  .next_nodes =
  {
    [L3XC_NEXT_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (l3xc_ip4_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "l3xc-input-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

VNET_FEATURE_INIT (l3xc_ip6_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "l3xc-input-ip6",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
