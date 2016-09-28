/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>

#include <vnet/span/span.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

vlib_node_registration_t span_node;

/* packet trace format function */
u8 *
format_span_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  span_trace_t *t = va_arg (*args, span_trace_t *);

  vnet_main_t *vnm = &vnet_main;
  s = format (s, "SPAN: mirrored %U -> %U",
	      format_vnet_sw_if_index_name, vnm, t->src_sw_if_index,
	      format_vnet_sw_if_index_name, vnm, t->mirror_sw_if_index);

  return s;
}

#define foreach_span_error                      \
_(HITS, "SPAN incomming packets processed")

typedef enum
{
#define _(sym,str) SPAN_ERROR_##sym,
  foreach_span_error
#undef _
    SPAN_N_ERROR,
} span_error_t;

static char *span_error_strings[] = {
#define _(sym,string) string,
  foreach_span_error
#undef _
};

typedef enum
{
  SPAN_NEXT_ORIG_ETHERNET,
  SPAN_NEXT_COPY_INTERFACE_OUTPUT,
  SPAN_N_NEXT,
} span_next_t;

static uword
span_node_fn (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  span_main_t *sm = &span_main;
  u32 n_left_from, *from, *to_next, *to_c_next;
  u32 n_span_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      u32 n_left_to_c_next;

      vlib_get_next_frame (vm, node, SPAN_NEXT_ORIG_ETHERNET, to_next,
			   n_left_to_next);
      vlib_get_next_frame (vm, node, SPAN_NEXT_COPY_INTERFACE_OUTPUT,
			   to_c_next, n_left_to_c_next);

      while (n_left_from >= 4 && n_left_to_next >= 2 && n_left_to_c_next >= 2)
	{
	  u32 bi0, bi1;
	  u32 ci0, ci1;
	  vlib_buffer_t *b0, *b1;
	  vlib_buffer_t *c0, *c1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next += 2;
	  n_left_to_next -= 2;

	  if (n_left_to_next == 0)
	    {
	      vlib_put_next_frame (vm, node, SPAN_NEXT_ORIG_ETHERNET,
				   n_left_to_next);
	      vlib_get_next_frame (vm, node, SPAN_NEXT_ORIG_ETHERNET, to_next,
				   n_left_to_next);
	    }

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  u32 src_if0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  u32 src_if1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  uword *p0 = hash_get (sm->dst_sw_if_index_by_src, src_if0);
	  uword *p1 = hash_get (sm->dst_sw_if_index_by_src, src_if1);

	  // first packet
	  if (PREDICT_TRUE (p0 != 0))
	    {
	      c0 = span_duplicate_buffer (vm, b0, p0[0], 1);
	      ci0 = vlib_get_buffer_index (vm, c0);

	      to_c_next[0] = ci0;
	      to_c_next += 1;
	      n_left_to_c_next -= 1;

	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (c0->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  span_trace_t *t =
		    vlib_add_trace (vm, node, c0, sizeof (*t));
		  t->src_sw_if_index = src_if0;
		  t->mirror_sw_if_index = p0[0];
		}

	      ++n_span_packets;
	    }
	  else
	    {
	      clib_warning ("SPAN entry not found for this interface!");

	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  span_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->src_sw_if_index = src_if0;
		  t->mirror_sw_if_index = ~0;
		}
	    }

	  // second packet
	  if (PREDICT_TRUE (p1 != 0))
	    {
	      c1 = span_duplicate_buffer (vm, b1, p1[0], 1);
	      ASSERT (c1 != 0);
	      ci1 = vlib_get_buffer_index (vm, c1);

	      to_c_next[0] = ci1;
	      to_c_next += 1;
	      n_left_to_c_next -= 1;

	      if (n_left_to_c_next == 0)
		{
		  vlib_put_next_frame (vm, node,
				       SPAN_NEXT_COPY_INTERFACE_OUTPUT,
				       n_left_to_c_next);
		  vlib_get_next_frame (vm, node,
				       SPAN_NEXT_COPY_INTERFACE_OUTPUT,
				       to_c_next, n_left_to_c_next);
		}

	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (c1->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  span_trace_t *t =
		    vlib_add_trace (vm, node, c1, sizeof (*t));
		  t->src_sw_if_index = src_if1;
		  t->mirror_sw_if_index = p1[0];
		}

	      ++n_span_packets;
	    }
	  else
	    {
	      clib_warning ("SPAN entry not found for this interface!");

	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b1->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  span_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->src_sw_if_index = src_if1;
		  t->mirror_sw_if_index = ~0;
		}
	    }

	  from += 2;
	  n_left_from -= 2;
	}

      while (n_left_from > 0 && n_left_to_next > 0 && n_left_to_c_next > 0)
	{
	  u32 bi0;
	  u32 ci0;
	  vlib_buffer_t *b0;
	  vlib_buffer_t *c0;

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next += 1;
	  n_left_to_next -= 1;

	  if (n_left_to_next == 0)
	    {
	      vlib_put_next_frame (vm, node, SPAN_NEXT_ORIG_ETHERNET,
				   n_left_to_next);
	      vlib_get_next_frame (vm, node, SPAN_NEXT_ORIG_ETHERNET, to_next,
				   n_left_to_next);
	    }

	  b0 = vlib_get_buffer (vm, bi0);
	  u32 src_if0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  uword *p0 = hash_get (sm->dst_sw_if_index_by_src, src_if0);

	  if (PREDICT_TRUE (p0 != 0))
	    {
	      c0 = span_duplicate_buffer (vm, b0, p0[0], 1);
	      ASSERT (c0 != 0);
	      ci0 = vlib_get_buffer_index (vm, c0);

	      to_c_next[0] = ci0;
	      to_c_next++;
	      n_left_to_c_next--;

	      if (n_left_to_c_next == 0)
		{
		  vlib_put_next_frame (vm, node,
				       SPAN_NEXT_COPY_INTERFACE_OUTPUT,
				       n_left_to_c_next);
		  vlib_get_next_frame (vm, node,
				       SPAN_NEXT_COPY_INTERFACE_OUTPUT,
				       to_c_next, n_left_to_c_next);
		}

	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  span_trace_t *t =
		    vlib_add_trace (vm, node, c0, sizeof (*t));
		  t->src_sw_if_index = src_if0;
		  t->mirror_sw_if_index = p0[0];
		}

	      ++n_span_packets;
	    }
	  else
	    {
	      clib_warning ("SPAN entry not found for this interface!");

	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  span_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->src_sw_if_index = src_if0;
		  t->mirror_sw_if_index = ~0;
		}
	    }

	  from += 1;
	  n_left_from -= 1;
	}

      vlib_put_next_frame (vm, node, SPAN_NEXT_ORIG_ETHERNET, n_left_to_next);
      vlib_put_next_frame (vm, node, SPAN_NEXT_COPY_INTERFACE_OUTPUT,
			   n_left_to_c_next);
    }

  vlib_node_increment_counter (vm, span_node.index, SPAN_ERROR_HITS,
			       n_span_packets);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (span_node) = {
  .function = span_node_fn,
  .name = "span-input",
  .vector_size = sizeof (u32),
  .format_trace = format_span_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(span_error_strings),
  .error_strings = span_error_strings,

  .n_next_nodes = SPAN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SPAN_NEXT_ORIG_ETHERNET] = "ethernet-input",
    [SPAN_NEXT_COPY_INTERFACE_OUTPUT] = "interface-output",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (span_node, span_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
