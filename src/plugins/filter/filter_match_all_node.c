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

#include <filter/filter_match_all.h>
#include <filter/filter_chain.h>
#include <filter/filter_buffer.h>

typedef struct filter_match_all_trace_t_
{
  index_t rule;
  filter_match_res_t matched;
} filter_match_all_trace_t;

/* packet trace format function */
static u8 *
format_filter_match_all_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  filter_match_all_trace_t *t = va_arg (*args, filter_match_all_trace_t *);

  s = format (s, "rule:%d %U", t->rule, format_filter_match_res, t->matched);

  return s;
}

always_inline uword
filter_match_all_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * frame, dpo_proto_t dproto)
{
  //  vlib_combined_counter_main_t *cm = &filter_chain_counters;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left;			//, thread_index;

  //thread_index = vm->thread_index;
  n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);
  clib_memset_u16 (nexts, 0, n_left);

  next = nexts;
  b = bufs;

  while (n_left > 0)
    {
      filter_buffer_meta_data_t *fbmd0;
      filter_match_res_t matched0;
      filter_match_all_t *fma0;

      fbmd0 = filter_buffer_meta_data_get (b[0]);
      fma0 = filter_match_all_get (fbmd0->fbmd_index);

      /* vlib_increment_combined_counter */
      /*   (cm, thread_index, fma0->fma_base.fm_rule, 1, */
      /*    vlib_buffer_length_in_chain (vm, b[0])); */

      matched0 = FILTER_MATCH_YES;

      fbmd0->fbmd_index = fma0->fma_base.fm_results[matched0].dpoi_index;
      next[0] = fma0->fma_base.fm_results[matched0].dpoi_next_node;

      if (PREDICT_FALSE ((b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  filter_match_all_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->rule = fma0->fma_base.fm_rule;
	  t->matched = matched0;
	}

      next += 1;
      b += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (filter_match_all_ip4_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return (filter_match_all_inline (vm, node, frame, DPO_PROTO_IP4));
}

VLIB_NODE_FN (filter_match_all_ip6_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return (filter_match_all_inline (vm, node, frame, DPO_PROTO_IP6));
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (filter_match_all_ip4_node) = {
  .name = "filter-match-all-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_match_all_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (filter_match_all_ip6_node) = {
  .name = "filter-match-all-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_match_all_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
