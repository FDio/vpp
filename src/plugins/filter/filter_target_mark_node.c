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

#include <filter/filter_target_mark.h>
#include <filter/filter_chain.h>
#include <filter/filter_buffer.h>

typedef struct filter_target_mark_trace_t_
{
  u32 mask, bits, result;
} filter_target_mark_trace_t;

/* packet trace format function */
static u8 *
format_filter_target_mark_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  filter_target_mark_trace_t *t =
    va_arg (*args, filter_target_mark_trace_t *);

  s = format (s, "mark: 0x%x/0x%x = 0x%x", t->mask, t->bits, t->result);

  return s;
}

always_inline uword
filter_target_mark_inline (vlib_main_t * vm,
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
      filter_buffer_meta_data_t *fbmd0;
      filter_target_mark_t *ftgm0;

      fbmd0 = filter_buffer_meta_data_get (b[0]);
      ftgm0 = filter_target_mark_get (fbmd0->fbmd_index);

      if (ftgm0->ftm_xor)
	fbmd0->fbmd_mark ^= (ftgm0->ftm_mask & ftgm0->ftm_bits);
      else
	fbmd0->fbmd_mark |= (ftgm0->ftm_mask & ftgm0->ftm_bits);

      fbmd0->fbmd_index = ftgm0->ftm_next.dpoi_index;
      next[0] = ftgm0->ftm_next.dpoi_next_node;

      if (PREDICT_FALSE ((b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  filter_target_mark_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->bits = ftgm0->ftm_bits;
	  t->mask = ftgm0->ftm_mask;
	  t->result = fbmd0->fbmd_mark;
	}

      next += 1;
      b += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (filter_target_mark_ip4_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return (filter_target_mark_inline (vm, node, frame, DPO_PROTO_IP4));
}

VLIB_NODE_FN (filter_target_mark_ip6_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return (filter_target_mark_inline (vm, node, frame, DPO_PROTO_IP6));
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (filter_target_mark_ip4_node) = {
  .name = "filter-target-mark-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_target_mark_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (filter_target_mark_ip6_node) = {
  .name = "filter-target-mark-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_target_mark_trace,
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
