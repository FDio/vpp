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

#include <filter/filter_target_terminate.h>
#include <vnet/feature/feature.h>

typedef struct filter_target_terminate_trace_t_
{
} filter_target_terminate_trace_t;

/* packet trace format function */
static u8 *
format_filter_target_terminate_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  // filter_target_terminate_trace_t *t = va_arg (*args, filter_target_terminate_trace_t *);

  // s = format (s, "sclass:%d", t->sclass);

  return s;
}

always_inline uword
filter_target_terminate_inline (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame, dpo_proto_t dproto)
{
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left;

  n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);
  clib_memset_u16 (nexts, 0, n_left);

  next = nexts;
  b = bufs;

  /* while (n_left >= 4) */
  /*   { */
  /*     next[0] = filter_starts[dproto][fct].dpoi_next_node; */
  /*     next[1] = filter_starts[dproto][fct].dpoi_next_node; */

  /*     next += 2; */
  /*     b += 2; */
  /*     n_left -= 2; */
  /*   } */

  while (n_left > 0)
    {
      u32 next0;

      vnet_feature_next (&next0, b[0]);

      next[0] = next0;

      if (PREDICT_FALSE ((b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  filter_target_terminate_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	}

      next += 1;
      b += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (filter_target_terminate_input_ip4_node) (vlib_main_t * vm,
						       vlib_node_runtime_t *
						       node,
						       vlib_frame_t * frame)
{
  return (filter_target_terminate_inline (vm, node, frame, DPO_PROTO_IP4));
}

VLIB_NODE_FN (filter_target_terminate_input_ip6_node) (vlib_main_t * vm,
						       vlib_node_runtime_t *
						       node,
						       vlib_frame_t * frame)
{
  return (filter_target_terminate_inline (vm, node, frame, DPO_PROTO_IP6));
}

VLIB_NODE_FN (filter_target_terminate_output_ip4_node) (vlib_main_t * vm,
							vlib_node_runtime_t *
							node,
							vlib_frame_t * frame)
{
  return (filter_target_terminate_inline (vm, node, frame, DPO_PROTO_IP4));
}

VLIB_NODE_FN (filter_target_terminate_output_ip6_node) (vlib_main_t * vm,
							vlib_node_runtime_t *
							node,
							vlib_frame_t * frame)
{
  return (filter_target_terminate_inline (vm, node, frame, DPO_PROTO_IP6));
}

/* *INDENT-OFF* */

/*
 * the separation of input and output nodes is required because they must
 * be siblings of the feature arc start nodes so that they have the same
 * edges to follow the feature arc.
 */
VLIB_REGISTER_NODE (filter_target_terminate_input_ip4_node) = {
  .name = "filter-target-terminate-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_target_terminate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "filter-feature-input-ip4",
};

VLIB_REGISTER_NODE (filter_target_terminate_input_ip6_node) = {
  .name = "filter-target-terminate-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_target_terminate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "filter-feature-input-ip6",
};

VLIB_REGISTER_NODE (filter_target_terminate_output_ip4_node) = {
  .name = "filter-target-terminate-output-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_target_terminate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "filter-feature-output-ip4",
};

VLIB_REGISTER_NODE (filter_target_terminate_output_ip6_node) = {
  .name = "filter-target-terminate-output-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_target_terminate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "filter-feature-output-ip6",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
