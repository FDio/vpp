/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * interface_output.c: interface output node
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/vnet.h>
#include <vnet/feature/feature.h>

typedef struct
{
  u32 sw_if_index;
  u8 data[128 - sizeof (u32)];
}
interface_output_trace_t;

u8 *
format_vnet_interface_output_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  vlib_node_t *node = va_arg (*va, vlib_node_t *);
  interface_output_trace_t *t = va_arg (*va, interface_output_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  uword indent;

  if (t->sw_if_index != (u32) ~ 0)
    {
      indent = format_get_indent (s);

      if (pool_is_free_index
	  (vnm->interface_main.sw_interfaces, t->sw_if_index))
	{
	  /* the interface may have been deleted by the time the trace is printed */
	  s = format (s, "sw_if_index: %d\n%U%U",
		      t->sw_if_index,
		      format_white_space, indent,
		      node->format_buffer ? node->
		      format_buffer : format_hex_bytes, t->data,
		      sizeof (t->data));
	}
      else
	{
	  si = vnet_get_sw_interface (vnm, t->sw_if_index);

	  s = format (s, "%U\n%U%U",
		      format_vnet_sw_interface_name, vnm, si,
		      format_white_space, indent,
		      node->format_buffer ? node->
		      format_buffer : format_hex_bytes, t->data,
		      sizeof (t->data));
	}
    }
  return s;
}

static void
vnet_interface_output_trace (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * frame, uword n_buffers)
{
  u32 n_left, *from;

  n_left = n_buffers;
  from = vlib_frame_args (frame);

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      interface_output_trace_t *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

      bi0 = from[0];
      bi1 = from[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  clib_memcpy (t0->data, vlib_buffer_get_current (b0),
		       sizeof (t0->data));
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	  clib_memcpy (t1->data, vlib_buffer_get_current (b1),
		       sizeof (t1->data));
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      interface_output_trace_t *t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  clib_memcpy (t0->data, vlib_buffer_get_current (b0),
		       sizeof (t0->data));
	}
      from += 1;
      n_left -= 1;
    }
}

static never_inline u32
slow_path (vlib_main_t * vm,
	   u32 bi,
	   vlib_buffer_t * b,
	   u32 n_left_to_tx, u32 * to_tx, u32 * n_slow_bytes_result)
{
  /* We've already enqueued a single buffer. */
  u32 n_buffers = 0;
  u32 n_slow_bytes = 0;

  while (n_left_to_tx > 0)
    {
      to_tx[0] = bi;
      to_tx += 1;
      n_left_to_tx -= 1;
      n_buffers += 1;
      n_slow_bytes += vlib_buffer_length_in_chain (vm, b);

      /* Be grumpy about zero length buffers for benefit of
         driver tx function. */
      ASSERT (b->current_length > 0);

      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;

      bi = b->next_buffer;
      b = vlib_get_buffer (vm, bi);
    }

  /* Ran out of space in next frame trying to enqueue buffers? */
  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    return 0;

  *n_slow_bytes_result = n_slow_bytes;
  return n_buffers;
}

/*
 * Increment TX stats. Roll up consecutive increments to the same sw_if_index
 * into one increment.
 */
static_always_inline void
incr_output_stats (vnet_main_t * vnm,
		   u32 cpu_index,
		   u32 length,
		   u32 sw_if_index,
		   u32 * last_sw_if_index, u32 * n_packets, u32 * n_bytes)
{
  vnet_interface_main_t *im;

  if (PREDICT_TRUE (sw_if_index == *last_sw_if_index))
    {
      *n_packets += 1;
      *n_bytes += length;
    }
  else
    {
      if (PREDICT_TRUE (*last_sw_if_index != ~0))
	{
	  im = &vnm->interface_main;

	  vlib_increment_combined_counter (im->combined_sw_if_counters
					   + VNET_INTERFACE_COUNTER_TX,
					   cpu_index,
					   *last_sw_if_index,
					   *n_packets, *n_bytes);
	}
      *last_sw_if_index = sw_if_index;
      *n_packets = 1;
      *n_bytes = length;
    }
}


/* Interface output functions. */
uword
vnet_interface_output_node_flatten (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_output_runtime_t *rt = (void *) node->runtime_data;
  vnet_sw_interface_t *si;
  vnet_hw_interface_t *hi;
  u32 n_left_to_tx, *from, *from_end, *to_tx;
  u32 n_bytes, n_buffers, n_packets;
  u32 last_sw_if_index;
  u32 cpu_index = vm->cpu_index;

  n_buffers = frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vnet_interface_output_trace (vm, node, frame, n_buffers);

  from = vlib_frame_args (frame);

  if (rt->is_deleted)
    return vlib_error_drop_buffers (vm, node, from,
				    /* buffer stride */ 1,
				    n_buffers,
				    VNET_INTERFACE_OUTPUT_NEXT_DROP,
				    node->node_index,
				    VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DELETED);

  si = vnet_get_sw_interface (vnm, rt->sw_if_index);
  hi = vnet_get_sup_hw_interface (vnm, rt->sw_if_index);
  if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ||
      !(hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
    {
      vlib_simple_counter_main_t *cm;

      cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			     VNET_INTERFACE_COUNTER_TX_ERROR);
      vlib_increment_simple_counter (cm, cpu_index,
				     rt->sw_if_index, n_buffers);
      return vlib_error_drop_buffers (vm, node, from,
				      /* buffer stride */ 1,
				      n_buffers,
				      VNET_INTERFACE_OUTPUT_NEXT_DROP,
				      node->node_index,
				      VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DOWN);
    }

  from_end = from + n_buffers;

  /* Total byte count of all buffers. */
  n_bytes = 0;
  n_packets = 0;
  last_sw_if_index = ~0;

  while (from < from_end)
    {
      /* Get new next frame since previous incomplete frame may have less
         than VNET_FRAME_SIZE vectors in it. */
      vlib_get_new_next_frame (vm, node, VNET_INTERFACE_OUTPUT_NEXT_TX,
			       to_tx, n_left_to_tx);

      while (from + 4 <= from_end && n_left_to_tx >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;

	  /* Prefetch next iteration. */
	  vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
	  vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

	  bi0 = from[0];
	  bi1 = from[1];
	  to_tx[0] = bi0;
	  to_tx[1] = bi1;
	  from += 2;
	  to_tx += 2;
	  n_left_to_tx -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* Be grumpy about zero length buffers for benefit of
	     driver tx function. */
	  ASSERT (b0->current_length > 0);
	  ASSERT (b1->current_length > 0);

	  if (PREDICT_FALSE
	      ((b0->flags | b1->flags) & VLIB_BUFFER_NEXT_PRESENT))
	    {
	      u32 n_buffers, n_slow_bytes, i;

	      /* Undo. */
	      from -= 2;
	      to_tx -= 2;
	      n_left_to_tx += 2;

	      /* Do slow path two times. */
	      for (i = 0; i < 2; i++)
		{
		  u32 bi = i ? bi1 : bi0;
		  vlib_buffer_t *b = i ? b1 : b0;

		  n_buffers = slow_path (vm, bi, b,
					 n_left_to_tx, to_tx, &n_slow_bytes);

		  /* Not enough room for single packet? */
		  if (n_buffers == 0)
		    goto put;

		  from += 1;
		  to_tx += n_buffers;
		  n_left_to_tx -= n_buffers;
		  incr_output_stats (vnm, cpu_index, n_slow_bytes,
				     vnet_buffer (b)->sw_if_index[VLIB_TX],
				     &last_sw_if_index, &n_packets, &n_bytes);
		}
	    }
	  else
	    {
	      incr_output_stats (vnm, cpu_index,
				 vlib_buffer_length_in_chain (vm, b0),
				 vnet_buffer (b0)->sw_if_index[VLIB_TX],
				 &last_sw_if_index, &n_packets, &n_bytes);
	      incr_output_stats (vnm, cpu_index,
				 vlib_buffer_length_in_chain (vm, b0),
				 vnet_buffer (b1)->sw_if_index[VLIB_TX],
				 &last_sw_if_index, &n_packets, &n_bytes);
	    }
	}

      while (from + 1 <= from_end && n_left_to_tx >= 1)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  bi0 = from[0];
	  to_tx[0] = bi0;
	  from += 1;
	  to_tx += 1;
	  n_left_to_tx -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Be grumpy about zero length buffers for benefit of
	     driver tx function. */
	  ASSERT (b0->current_length > 0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_NEXT_PRESENT))
	    {
	      u32 n_buffers, n_slow_bytes;

	      /* Undo. */
	      from -= 1;
	      to_tx -= 1;
	      n_left_to_tx += 1;

	      n_buffers = slow_path (vm, bi0, b0,
				     n_left_to_tx, to_tx, &n_slow_bytes);

	      /* Not enough room for single packet? */
	      if (n_buffers == 0)
		goto put;

	      from += 1;
	      to_tx += n_buffers;
	      n_left_to_tx -= n_buffers;
	    }
	  incr_output_stats (vnm, cpu_index,
			     vlib_buffer_length_in_chain (vm, b0),
			     vnet_buffer (b0)->sw_if_index[VLIB_TX],
			     &last_sw_if_index, &n_packets, &n_bytes);
	}

    put:
      vlib_put_next_frame (vm, node, VNET_INTERFACE_OUTPUT_NEXT_TX,
			   n_left_to_tx);
    }

  /* Final update of interface stats. */
  incr_output_stats (vnm, cpu_index, 0, ~0,	/* ~0 will flush stats */
		     &last_sw_if_index, &n_packets, &n_bytes);

  return n_buffers;
}

VLIB_NODE_FUNCTION_MULTIARCH_CLONE (vnet_interface_output_node_flatten);
CLIB_MULTIARCH_SELECT_FN (vnet_interface_output_node_flatten);

uword
vnet_interface_output_node (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_output_runtime_t *rt = (void *) node->runtime_data;
  vnet_sw_interface_t *si;
  vnet_hw_interface_t *hi;
  u32 n_left_to_tx, *from, *from_end, *to_tx;
  u32 n_bytes, n_buffers, n_packets;
  u32 n_bytes_b0, n_bytes_b1;
  u32 cpu_index = vm->cpu_index;
  vnet_interface_main_t *im = &vnm->interface_main;
  u32 next_index = VNET_INTERFACE_OUTPUT_NEXT_TX;
  u32 current_config_index = ~0;
  u8 arc = im->output_feature_arc_index;

  n_buffers = frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vnet_interface_output_trace (vm, node, frame, n_buffers);

  from = vlib_frame_args (frame);

  if (rt->is_deleted)
    return vlib_error_drop_buffers (vm, node, from,
				    /* buffer stride */ 1,
				    n_buffers,
				    VNET_INTERFACE_OUTPUT_NEXT_DROP,
				    node->node_index,
				    VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DELETED);

  si = vnet_get_sw_interface (vnm, rt->sw_if_index);
  hi = vnet_get_sup_hw_interface (vnm, rt->sw_if_index);
  if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ||
      !(hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
    {
      vlib_simple_counter_main_t *cm;

      cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			     VNET_INTERFACE_COUNTER_TX_ERROR);
      vlib_increment_simple_counter (cm, cpu_index,
				     rt->sw_if_index, n_buffers);

      return vlib_error_drop_buffers (vm, node, from,
				      /* buffer stride */ 1,
				      n_buffers,
				      VNET_INTERFACE_OUTPUT_NEXT_DROP,
				      node->node_index,
				      VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DOWN);
    }

  from_end = from + n_buffers;

  /* Total byte count of all buffers. */
  n_bytes = 0;
  n_packets = 0;

  /* interface-output feature arc handling */
  if (PREDICT_FALSE (vnet_have_features (arc, rt->sw_if_index)))
    {
      vnet_feature_config_main_t *fcm;
      fcm = vnet_feature_get_config_main (arc);
      current_config_index = vnet_get_feature_config_index (arc,
							    rt->sw_if_index);
      vnet_get_config_data (&fcm->config_main, &current_config_index,
			    &next_index, 0);
    }

  while (from < from_end)
    {
      /* Get new next frame since previous incomplete frame may have less
         than VNET_FRAME_SIZE vectors in it. */
      vlib_get_new_next_frame (vm, node, next_index, to_tx, n_left_to_tx);

      while (from + 4 <= from_end && n_left_to_tx >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 tx_swif0, tx_swif1;

	  /* Prefetch next iteration. */
	  vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
	  vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

	  bi0 = from[0];
	  bi1 = from[1];
	  to_tx[0] = bi0;
	  to_tx[1] = bi1;
	  from += 2;
	  to_tx += 2;
	  n_left_to_tx -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* Be grumpy about zero length buffers for benefit of
	     driver tx function. */
	  ASSERT (b0->current_length > 0);
	  ASSERT (b1->current_length > 0);

	  n_bytes_b0 = vlib_buffer_length_in_chain (vm, b0);
	  n_bytes_b1 = vlib_buffer_length_in_chain (vm, b1);
	  tx_swif0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  tx_swif1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];

	  n_bytes += n_bytes_b0 + n_bytes_b1;
	  n_packets += 2;

	  if (PREDICT_FALSE (current_config_index != ~0))
	    {
	      b0->feature_arc_index = arc;
	      b1->feature_arc_index = arc;
	      b0->current_config_index = current_config_index;
	      b1->current_config_index = current_config_index;
	    }

	  if (PREDICT_FALSE (tx_swif0 != rt->sw_if_index))
	    {
	      /* update vlan subif tx counts, if required */
	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       cpu_index, tx_swif0, 1,
					       n_bytes_b0);
	    }

	  /* update vlan subif tx counts, if required */
	  if (PREDICT_FALSE (tx_swif1 != rt->sw_if_index))
	    {

	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       cpu_index, tx_swif1, 1,
					       n_bytes_b1);
	    }
	}

      while (from + 1 <= from_end && n_left_to_tx >= 1)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 tx_swif0;

	  bi0 = from[0];
	  to_tx[0] = bi0;
	  from += 1;
	  to_tx += 1;
	  n_left_to_tx -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Be grumpy about zero length buffers for benefit of
	     driver tx function. */
	  ASSERT (b0->current_length > 0);

	  n_bytes_b0 = vlib_buffer_length_in_chain (vm, b0);
	  tx_swif0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  n_bytes += n_bytes_b0;
	  n_packets += 1;

	  if (PREDICT_FALSE (current_config_index != ~0))
	    {
	      b0->feature_arc_index = arc;
	      b0->current_config_index = current_config_index;
	    }

	  if (PREDICT_FALSE (tx_swif0 != rt->sw_if_index))
	    {

	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       cpu_index, tx_swif0, 1,
					       n_bytes_b0);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_tx);
    }

  /* Update main interface stats. */
  vlib_increment_combined_counter (im->combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_TX,
				   cpu_index,
				   rt->sw_if_index, n_packets, n_bytes);
  return n_buffers;
}

VLIB_NODE_FUNCTION_MULTIARCH_CLONE (vnet_interface_output_node);
CLIB_MULTIARCH_SELECT_FN (vnet_interface_output_node);

/* Use buffer's sw_if_index[VNET_TX] to choose output interface. */
static uword
vnet_per_buffer_interface_output (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 n_left_to_next, *from, *to_next;
  u32 n_left_from, next_index;

  n_left_from = frame->n_vectors;

  from = vlib_frame_args (frame);
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1, next0, next1;
	  vlib_buffer_t *b0, *b1;
	  vnet_hw_interface_t *hi0, *hi1;

	  /* Prefetch next iteration. */
	  vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
	  vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  hi0 =
	    vnet_get_sup_hw_interface (vnm,
				       vnet_buffer (b0)->sw_if_index
				       [VLIB_TX]);
	  hi1 =
	    vnet_get_sup_hw_interface (vnm,
				       vnet_buffer (b1)->sw_if_index
				       [VLIB_TX]);

	  next0 = hi0->hw_if_index;
	  next1 = hi1->hw_if_index;

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0;
	  vnet_hw_interface_t *hi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  hi0 =
	    vnet_get_sup_hw_interface (vnm,
				       vnet_buffer (b0)->sw_if_index
				       [VLIB_TX]);

	  next0 = hi0->hw_if_index;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

always_inline u32
counter_index (vlib_main_t * vm, vlib_error_t e)
{
  vlib_node_t *n;
  u32 ci, ni;

  ni = vlib_error_get_node (e);
  n = vlib_get_node (vm, ni);

  ci = vlib_error_get_code (e);
  ASSERT (ci < n->n_errors);

  ci += n->error_heap_index;

  return ci;
}

static u8 *
format_vnet_error_trace (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vlib_error_t *e = va_arg (*va, vlib_error_t *);
  vlib_node_t *error_node;
  vlib_error_main_t *em = &vm->error_main;
  u32 i;

  error_node = vlib_get_node (vm, vlib_error_get_node (e[0]));
  i = counter_index (vm, e[0]);
  s = format (s, "%v: %s", error_node->name, em->error_strings_heap[i]);

  return s;
}

static void
trace_errors_with_buffers (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left, *buffers;

  buffers = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      vlib_error_t *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, buffers[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[3], LOAD);

      bi0 = buffers[0];
      bi1 = buffers[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0[0] = b0->error;
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1[0] = b1->error;
	}
      buffers += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      vlib_error_t *t0;

      bi0 = buffers[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0[0] = b0->error;
	}
      buffers += 1;
      n_left -= 1;
    }
}

static u8 *
validate_error (vlib_main_t * vm, vlib_error_t * e, u32 index)
{
  uword node_index = vlib_error_get_node (e[0]);
  uword code = vlib_error_get_code (e[0]);
  vlib_node_t *n;

  if (node_index >= vec_len (vm->node_main.nodes))
    return format (0, "[%d], node index out of range 0x%x, error 0x%x",
		   index, node_index, e[0]);

  n = vlib_get_node (vm, node_index);
  if (code >= n->n_errors)
    return format (0, "[%d], code %d out of range for node %v",
		   index, code, n->name);

  return 0;
}

static u8 *
validate_error_frame (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * f)
{
  u32 *buffers = vlib_frame_args (f);
  vlib_buffer_t *b;
  u8 *msg = 0;
  uword i;

  for (i = 0; i < f->n_vectors; i++)
    {
      b = vlib_get_buffer (vm, buffers[i]);
      msg = validate_error (vm, &b->error, i);
      if (msg)
	return msg;
    }

  return msg;
}

typedef enum
{
  VNET_ERROR_DISPOSITION_DROP,
  VNET_ERROR_DISPOSITION_PUNT,
  VNET_ERROR_N_DISPOSITION,
} vnet_error_disposition_t;

always_inline void
do_packet (vlib_main_t * vm, vlib_error_t a)
{
  vlib_error_main_t *em = &vm->error_main;
  u32 i = counter_index (vm, a);
  em->counters[i] += 1;
  vlib_error_elog_count (vm, i, 1);
}

static_always_inline uword
process_drop_punt (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame, vnet_error_disposition_t disposition)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_error_main_t *em = &vm->error_main;
  u32 *buffers, *first_buffer;
  vlib_error_t current_error;
  u32 current_counter_index, n_errors_left;
  u32 current_sw_if_index, n_errors_current_sw_if_index;
  u64 current_counter;
  vlib_simple_counter_main_t *cm;
  u32 cpu_index = vm->cpu_index;

  static vlib_error_t memory[VNET_ERROR_N_DISPOSITION];
  static char memory_init[VNET_ERROR_N_DISPOSITION];

  buffers = vlib_frame_args (frame);
  first_buffer = buffers;

  {
    vlib_buffer_t *b = vlib_get_buffer (vm, first_buffer[0]);

    if (!memory_init[disposition])
      {
	memory_init[disposition] = 1;
	memory[disposition] = b->error;
      }

    current_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
    n_errors_current_sw_if_index = 0;
  }

  current_error = memory[disposition];
  current_counter_index = counter_index (vm, memory[disposition]);
  current_counter = em->counters[current_counter_index];

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    trace_errors_with_buffers (vm, node, frame);

  n_errors_left = frame->n_vectors;
  cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			 (disposition == VNET_ERROR_DISPOSITION_PUNT
			  ? VNET_INTERFACE_COUNTER_PUNT
			  : VNET_INTERFACE_COUNTER_DROP));

  while (n_errors_left >= 2)
    {
      vlib_buffer_t *b0, *b1;
      vnet_sw_interface_t *sw_if0, *sw_if1;
      vlib_error_t e0, e1;
      u32 bi0, bi1;
      u32 sw_if_index0, sw_if_index1;

      bi0 = buffers[0];
      bi1 = buffers[1];

      buffers += 2;
      n_errors_left -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      e0 = b0->error;
      e1 = b1->error;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

      /* Speculate that sw_if_index == sw_if_index[01]. */
      n_errors_current_sw_if_index += 2;

      /* Speculatively assume all 2 (node, code) pairs are equal
         to current (node, code). */
      current_counter += 2;

      if (PREDICT_FALSE (e0 != current_error
			 || e1 != current_error
			 || sw_if_index0 != current_sw_if_index
			 || sw_if_index1 != current_sw_if_index))
	{
	  current_counter -= 2;
	  n_errors_current_sw_if_index -= 2;

	  vlib_increment_simple_counter (cm, cpu_index, sw_if_index0, 1);
	  vlib_increment_simple_counter (cm, cpu_index, sw_if_index1, 1);

	  /* Increment super-interface drop/punt counters for
	     sub-interfaces. */
	  sw_if0 = vnet_get_sw_interface (vnm, sw_if_index0);
	  vlib_increment_simple_counter
	    (cm, cpu_index, sw_if0->sup_sw_if_index,
	     sw_if0->sup_sw_if_index != sw_if_index0);

	  sw_if1 = vnet_get_sw_interface (vnm, sw_if_index1);
	  vlib_increment_simple_counter
	    (cm, cpu_index, sw_if1->sup_sw_if_index,
	     sw_if1->sup_sw_if_index != sw_if_index1);

	  em->counters[current_counter_index] = current_counter;
	  do_packet (vm, e0);
	  do_packet (vm, e1);

	  /* For 2 repeated errors, change current error. */
	  if (e0 == e1 && e1 != current_error)
	    {
	      current_error = e0;
	      current_counter_index = counter_index (vm, e0);
	    }
	  current_counter = em->counters[current_counter_index];
	}
    }

  while (n_errors_left >= 1)
    {
      vlib_buffer_t *b0;
      vnet_sw_interface_t *sw_if0;
      vlib_error_t e0;
      u32 bi0, sw_if_index0;

      bi0 = buffers[0];

      buffers += 1;
      n_errors_left -= 1;
      current_counter += 1;

      b0 = vlib_get_buffer (vm, bi0);
      e0 = b0->error;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      /* Increment drop/punt counters. */
      vlib_increment_simple_counter (cm, cpu_index, sw_if_index0, 1);

      /* Increment super-interface drop/punt counters for sub-interfaces. */
      sw_if0 = vnet_get_sw_interface (vnm, sw_if_index0);
      vlib_increment_simple_counter (cm, cpu_index, sw_if0->sup_sw_if_index,
				     sw_if0->sup_sw_if_index != sw_if_index0);

      if (PREDICT_FALSE (e0 != current_error))
	{
	  current_counter -= 1;

	  vlib_error_elog_count (vm, current_counter_index,
				 (current_counter
				  - em->counters[current_counter_index]));

	  em->counters[current_counter_index] = current_counter;

	  do_packet (vm, e0);
	  current_error = e0;
	  current_counter_index = counter_index (vm, e0);
	  current_counter = em->counters[current_counter_index];
	}
    }

  if (n_errors_current_sw_if_index > 0)
    {
      vnet_sw_interface_t *si;

      vlib_increment_simple_counter (cm, cpu_index, current_sw_if_index,
				     n_errors_current_sw_if_index);

      si = vnet_get_sw_interface (vnm, current_sw_if_index);
      if (si->sup_sw_if_index != current_sw_if_index)
	vlib_increment_simple_counter (cm, cpu_index, si->sup_sw_if_index,
				       n_errors_current_sw_if_index);
    }

  vlib_error_elog_count (vm, current_counter_index,
			 (current_counter
			  - em->counters[current_counter_index]));

  /* Return cached counter. */
  em->counters[current_counter_index] = current_counter;

  /* Save memory for next iteration. */
  memory[disposition] = current_error;

  if (disposition == VNET_ERROR_DISPOSITION_DROP || !vm->os_punt_frame)
    {
      vlib_buffer_free (vm, first_buffer, frame->n_vectors);

      /* If there is no punt function, free the frame as well. */
      if (disposition == VNET_ERROR_DISPOSITION_PUNT && !vm->os_punt_frame)
	vlib_frame_free (vm, node, frame);
    }
  else
    vm->os_punt_frame (vm, node, frame);

  return frame->n_vectors;
}

static inline void
pcap_drop_trace (vlib_main_t * vm,
		 vnet_interface_main_t * im, vlib_frame_t * f)
{
  u32 *from;
  u32 n_left = f->n_vectors;
  vlib_buffer_t *b0, *p1;
  u32 bi0;
  i16 save_current_data;
  u16 save_current_length;

  from = vlib_frame_vector_args (f);

  while (n_left > 0)
    {
      if (PREDICT_TRUE (n_left > 1))
	{
	  p1 = vlib_get_buffer (vm, from[1]);
	  vlib_prefetch_buffer_header (p1, LOAD);
	}

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      from++;
      n_left--;

      /* See if we're pointedly ignoring this specific error */
      if (im->pcap_drop_filter_hash
	  && hash_get (im->pcap_drop_filter_hash, b0->error))
	continue;

      /* Trace all drops, or drops received on a specific interface */
      if (im->pcap_sw_if_index == 0 ||
	  im->pcap_sw_if_index == vnet_buffer (b0)->sw_if_index[VLIB_RX])
	{
	  save_current_data = b0->current_data;
	  save_current_length = b0->current_length;

	  /*
	   * Typically, we'll need to rewind the buffer
	   */
	  if (b0->current_data > 0)
	    vlib_buffer_advance (b0, (word) - b0->current_data);

	  pcap_add_buffer (&im->pcap_main, vm, bi0, 512);

	  b0->current_data = save_current_data;
	  b0->current_length = save_current_length;
	}
    }
}

void
vnet_pcap_drop_trace_filter_add_del (u32 error_index, int is_add)
{
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;

  if (im->pcap_drop_filter_hash == 0)
    im->pcap_drop_filter_hash = hash_create (0, sizeof (uword));

  if (is_add)
    hash_set (im->pcap_drop_filter_hash, error_index, 1);
  else
    hash_unset (im->pcap_drop_filter_hash, error_index);
}

static uword
process_drop (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;

  if (PREDICT_FALSE (im->drop_pcap_enable))
    pcap_drop_trace (vm, im, frame);

  return process_drop_punt (vm, node, frame, VNET_ERROR_DISPOSITION_DROP);
}

static uword
process_punt (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return process_drop_punt (vm, node, frame, VNET_ERROR_DISPOSITION_PUNT);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (drop_buffers,static) = {
  .function = process_drop,
  .name = "error-drop",
  .flags = VLIB_NODE_FLAG_IS_DROP,
  .vector_size = sizeof (u32),
  .format_trace = format_vnet_error_trace,
  .validate_frame = validate_error_frame,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (drop_buffers, process_drop);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (punt_buffers,static) = {
  .function = process_punt,
  .flags = (VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH
	    | VLIB_NODE_FLAG_IS_PUNT),
  .name = "error-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_vnet_error_trace,
  .validate_frame = validate_error_frame,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (punt_buffers, process_punt);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vnet_per_buffer_interface_output_node,static) = {
  .function = vnet_per_buffer_interface_output,
  .name = "interface-output",
  .vector_size = sizeof (u32),
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (vnet_per_buffer_interface_output_node,
			      vnet_per_buffer_interface_output);

static uword
interface_tx_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 last_sw_if_index = ~0;
  vlib_frame_t *to_frame = 0;
  vnet_hw_interface_t *hw = 0;
  u32 *from, *to_next = 0;
  u32 n_left_from;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 sw_if_index0;

      bi0 = from[0];
      from++;
      n_left_from--;
      b0 = vlib_get_buffer (vm, bi0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      if (PREDICT_FALSE ((last_sw_if_index != sw_if_index0) || to_frame == 0))
	{
	  if (to_frame)
	    {
	      hw = vnet_get_sup_hw_interface (vnm, last_sw_if_index);
	      vlib_put_frame_to_node (vm, hw->tx_node_index, to_frame);
	    }
	  last_sw_if_index = sw_if_index0;
	  hw = vnet_get_sup_hw_interface (vnm, sw_if_index0);
	  to_frame = vlib_get_frame_to_node (vm, hw->tx_node_index);
	  to_next = vlib_frame_vector_args (to_frame);
	}

      to_next[0] = bi0;
      to_next++;
      to_frame->n_vectors++;
    }
  vlib_put_frame_to_node (vm, hw->tx_node_index, to_frame);
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (interface_tx, static) = {
  .function = interface_tx_node_fn,
  .name = "interface-tx",
  .vector_size = sizeof (u32),
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VNET_FEATURE_ARC_INIT (interface_output, static) =
{
  .arc_name  = "interface-output",
  .start_nodes = VNET_FEATURES (0),
  .end_node = "interface-tx",
  .arc_index_ptr = &vnet_main.interface_main.output_feature_arc_index,
};

VNET_FEATURE_INIT (span_tx, static) = {
  .arc_name = "interface-output",
  .node_name = "span-output",
  .runs_before = VNET_FEATURES ("interface-tx"),
};

VNET_FEATURE_INIT (interface_tx, static) = {
  .arc_name = "interface-output",
  .node_name = "interface-tx",
  .runs_before = 0,
};
/* *INDENT-ON* */

clib_error_t *
vnet_per_buffer_interface_output_hw_interface_add_del (vnet_main_t * vnm,
						       u32 hw_if_index,
						       u32 is_create)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  u32 next_index;

  next_index = vlib_node_add_next_with_slot
    (vnm->vlib_main, vnet_per_buffer_interface_output_node.index,
     hi->output_node_index,
     /* next_index */ hw_if_index);

  ASSERT (next_index == hw_if_index);

  return 0;
}

VNET_HW_INTERFACE_ADD_DEL_FUNCTION
  (vnet_per_buffer_interface_output_hw_interface_add_del);

static clib_error_t *
pcap_drop_trace_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  u8 *filename;
  u32 max;
  int matched = 0;
  clib_error_t *error = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "on"))
	{
	  if (im->drop_pcap_enable == 0)
	    {
	      if (im->pcap_filename == 0)
		im->pcap_filename = format (0, "/tmp/drop.pcap%c", 0);

	      memset (&im->pcap_main, 0, sizeof (im->pcap_main));
	      im->pcap_main.file_name = (char *) im->pcap_filename;
	      im->pcap_main.n_packets_to_capture = 100;
	      if (im->pcap_pkts_to_capture)
		im->pcap_main.n_packets_to_capture = im->pcap_pkts_to_capture;

	      im->pcap_main.packet_type = PCAP_PACKET_TYPE_ethernet;
	      im->drop_pcap_enable = 1;
	      matched = 1;
	      vlib_cli_output (vm, "pcap drop capture on...");
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap drop capture already on...");
	    }
	  matched = 1;
	}
      else if (unformat (input, "off"))
	{
	  matched = 1;

	  if (im->drop_pcap_enable)
	    {
	      vlib_cli_output (vm, "captured %d pkts...",
			       im->pcap_main.n_packets_captured);
	      if (im->pcap_main.n_packets_captured)
		{
		  im->pcap_main.n_packets_to_capture =
		    im->pcap_main.n_packets_captured;
		  error = pcap_write (&im->pcap_main);
		  if (error)
		    clib_error_report (error);
		  else
		    vlib_cli_output (vm, "saved to %s...", im->pcap_filename);
		}
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap drop capture already off...");
	    }

	  im->drop_pcap_enable = 0;
	}
      else if (unformat (input, "max %d", &max))
	{
	  im->pcap_pkts_to_capture = max;
	  matched = 1;
	}

      else if (unformat (input, "intfc %U",
			 unformat_vnet_sw_interface, vnm,
			 &im->pcap_sw_if_index))
	matched = 1;
      else if (unformat (input, "intfc any"))
	{
	  im->pcap_sw_if_index = 0;
	  matched = 1;
	}
      else if (unformat (input, "file %s", &filename))
	{
	  u8 *chroot_filename;
	  /* Brain-police user path input */
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      continue;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);
	  vec_free (filename);

	  if (im->pcap_filename)
	    vec_free (im->pcap_filename);
	  vec_add1 (filename, 0);
	  im->pcap_filename = chroot_filename;
	  matched = 1;
	}
      else if (unformat (input, "status"))
	{
	  if (im->drop_pcap_enable == 0)
	    {
	      vlib_cli_output (vm, "pcap drop capture is off...");
	      continue;
	    }

	  vlib_cli_output (vm, "pcap drop capture: %d of %d pkts...",
			   im->pcap_main.n_packets_captured,
			   im->pcap_main.n_packets_to_capture);
	  matched = 1;
	}

      else
	break;
    }

  if (matched == 0)
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pcap_trace_command, static) = {
  .path = "pcap drop trace",
  .short_help =
  "pcap drop trace on off max <nn> intfc <intfc> file <name> status",
  .function = pcap_drop_trace_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
