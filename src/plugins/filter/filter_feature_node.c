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

#include <filter/filter_table.h>
#include <filter/filter_buffer.h>
#include <filter/filter_hook.h>
#include <vnet/feature/feature.h>

typedef struct filter_feature_trace_t_
{
  filter_hook_type_t fht;
  dpo_proto_t dproto;
} filter_feature_trace_t;

/* packet trace format function */
static u8 *
format_filter_feature_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  filter_feature_trace_t *t = va_arg (*args, filter_feature_trace_t *);

  s = format (s, "%U %U",
              format_dpo_proto, t->dproto,
              format_filter_hook_type, t->fht);

  return s;
}

always_inline uword
filter_feature_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame,
		       filter_hook_type_t fht, dpo_proto_t dproto)
{
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left, thread_index;

  n_left = frame->n_vectors;
  thread_index = vm->thread_index;

  vlib_get_buffers (vm, from, bufs, n_left);
  clib_memset_u16 (nexts, 0, n_left);

  next = nexts;
  b = bufs;

  /* while (n_left >= 4) */
  /*   { */
  /*     next[0] = filter_starts[dproto][fht].dpoi_next_node; */
  /*     next[1] = filter_starts[dproto][fht].dpoi_next_node; */

  /*     vnet_buffer(b[0])->ip.adj_index[VLIB_TX] = filter_starts[dproto][fht].dpoi_index; */
  /*     vnet_buffer(b[1])->ip.adj_index[VLIB_TX] = filter_starts[dproto][fht].dpoi_index; */

  /*     next += 2; */
  /*     b += 2; */
  /*     n_left -= 2; */
  /*   } */

  while (n_left > 0)
    {
      filter_buffer_meta_data_t *fbmd0;
      const dpo_id_t *root0;
      u32 bi0;

      root0 = filter_hook_root_get (dproto, fht);
      next[0] = root0->dpoi_next_node;

      fbmd0 = filter_buffer_meta_data_get (b[0]);

      fbmd0->fbmd_index = root0->dpoi_index;
      fbmd0->fbmd_hook = fht;

      bi0 = vlib_get_buffer_index (vm, b[0]);
      vec_validate_aligned (filter_buffer_main.
			    fbm_threads[thread_index].fptd_stack, bi0,
			    CLIB_CACHE_LINE_BYTES);
      vec_reset_length (filter_buffer_main.
			fbm_threads[thread_index].fptd_stack);

      if (PREDICT_FALSE ((b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  filter_feature_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
          t->fht = fht;
          t->dproto = dproto;
	}

      next += 1;
      b += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (filter_feature_input_ip4_node) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame)
{
  return (filter_feature_inline
	  (vm, node, frame, FILTER_HOOK_INPUT, DPO_PROTO_IP4));
}

VLIB_NODE_FN (filter_feature_input_ip6_node) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame)
{
  return (filter_feature_inline
	  (vm, node, frame, FILTER_HOOK_INPUT, DPO_PROTO_IP6));
}

VLIB_NODE_FN (filter_feature_output_ip4_node) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  return (filter_feature_inline
	  (vm, node, frame, FILTER_HOOK_OUTPUT, DPO_PROTO_IP4));
}

VLIB_NODE_FN (filter_feature_output_ip6_node) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  return (filter_feature_inline
	  (vm, node, frame, FILTER_HOOK_OUTPUT, DPO_PROTO_IP6));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (filter_feature_input_ip4_node) = {
  .name = "filter-feature-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_feature_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_REGISTER_NODE (filter_feature_input_ip6_node) = {
  .name = "filter-feature-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_feature_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_REGISTER_NODE (filter_feature_output_ip4_node) = {
  .name = "filter-feature-output-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_feature_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_REGISTER_NODE (filter_feature_output_ip6_node) = {
  .name = "filter-feature-output-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_feature_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VNET_FEATURE_INIT (filter_feature_input_ip4_feat_node, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "filter-feature-input-ip4",
};
VNET_FEATURE_INIT (filter_feature_input_ip6_feat_node, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "filter-feature-input-ip6",
};
VNET_FEATURE_INIT (filter_feature_output_ip4_feat_node, static) =
{
  .arc_name = "ip4-output",
  .node_name = "filter-feature-output-ip4",
};
VNET_FEATURE_INIT (filter_feature_output_ip6_feat_node, static) =
{
  .arc_name = "ip6-output",
  .node_name = "filter-feature-output-ip6",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
