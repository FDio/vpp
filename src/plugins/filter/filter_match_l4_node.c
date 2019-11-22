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

#include <filter/filter_match_l4.h>
#include <filter/filter_chain.h>
#include <filter/filter_buffer.h>

typedef struct filter_match_l4_trace_t_
{
  index_t rule;
  filter_match_res_t matched;
} filter_match_l4_trace_t;

/* packet trace format function */
static u8 *
format_filter_match_l4_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  filter_match_l4_trace_t *t = va_arg (*args, filter_match_l4_trace_t *);

  s = format (s, "rule:%d %U", t->rule, format_filter_match_res, t->matched);

  return s;
}

always_inline uword
filter_match_l4_inline (vlib_main_t * vm,
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
      filter_match_l4_t *fml0;
      ip4_header_t *ip4_0;
      // ip6_header_t *ip6_0;

      fbmd0 = filter_buffer_meta_data_get (b[0]);
      fml0 = filter_match_l4_get (fbmd0->fbmd_index);

      /* vlib_increment_combined_counter */
      /*   (cm, thread_index, fml0->fml_base.fm_rule, 1, */
      /*    vlib_buffer_length_in_chain (vm, b[0])); */

      // REMOVE ME
      matched0 = FILTER_MATCH_NO;

      if (DPO_PROTO_IP4 == dproto)
	{
	  ip4_0 = vlib_buffer_get_current (b[0]);

	  if (ip4_0->protocol == fml0->fml_iproto)
	    {
	      udp_header_t *l4_0 =
		(udp_header_t *) (((u8 *) ip4_0) + sizeof (*ip4_0));
	      if (FILTER_MATCH_SRC == fml0->fml_dir)
		{
		  if (l4_0->src_port == fml0->fml_port)
		    matched0 = FILTER_MATCH_YES;
		  else
		    matched0 = FILTER_MATCH_NO;
		}
	      else if (FILTER_MATCH_DST == fml0->fml_dir)
		{
		  if (l4_0->dst_port == fml0->fml_port)
		    matched0 = FILTER_MATCH_YES;
		  else
		    matched0 = FILTER_MATCH_NO;
		}
	    }
	  else
	    matched0 = FILTER_MATCH_NO;
	}

      fbmd0->fbmd_index = fml0->fml_base.fm_results[matched0].dpoi_index;
      next[0] = fml0->fml_base.fm_results[matched0].dpoi_next_node;

      if (PREDICT_FALSE ((b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  filter_match_l4_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->rule = fml0->fml_base.fm_rule;
	  t->matched = matched0;
	}

      next += 1;
      b += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (filter_match_l4_ip4_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return (filter_match_l4_inline (vm, node, frame, DPO_PROTO_IP4));
}

VLIB_NODE_FN (filter_match_l4_ip6_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return (filter_match_l4_inline (vm, node, frame, DPO_PROTO_IP6));
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (filter_match_l4_ip4_node) = {
  .name = "filter-match-l4-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_match_l4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (filter_match_l4_ip6_node) = {
  .name = "filter-match-l4-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_match_l4_trace,
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
