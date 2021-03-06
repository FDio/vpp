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
 * trace_funcs.h: VLIB trace buffer.
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

#ifndef included_vlib_trace_funcs_h
#define included_vlib_trace_funcs_h

extern u8 *vnet_trace_placeholder;

always_inline void
vlib_validate_trace (vlib_trace_main_t * tm, vlib_buffer_t * b)
{
  ASSERT (!pool_is_free_index (tm->trace_buffer_pool,
			       vlib_buffer_get_trace_index (b)));
}

int vlib_add_handoff_trace (vlib_main_t * vm, vlib_buffer_t * b);

always_inline void *
vlib_add_trace_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * r, vlib_buffer_t * b,
		       u32 n_data_bytes)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t *h;
  u32 n_data_words, trace_index;

  ASSERT (vnet_trace_placeholder);

  if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_IS_TRACED) == 0))
    return vnet_trace_placeholder;

  if (PREDICT_FALSE (tm->add_trace_callback != 0))
    {
      return tm->add_trace_callback ((struct vlib_main_t *) vm,
				     (struct vlib_node_runtime_t *) r,
				     (struct vlib_buffer_t *) b,
				     n_data_bytes);
    }
  else if (PREDICT_FALSE (tm->trace_enable == 0))
    {
      ASSERT (vec_len (vnet_trace_placeholder) >= n_data_bytes + sizeof (*h));
      return vnet_trace_placeholder;
    }

  /* Are we trying to trace a handoff case? */
  if (PREDICT_FALSE (vlib_buffer_get_trace_thread (b) != vm->thread_index))
    if (PREDICT_FALSE (!vlib_add_handoff_trace (vm, b)))
      return vnet_trace_placeholder;

  /*
   * there is a small chance of a race condition with 'clear trace' here: if a
   * buffer was set to be traced before the 'clear trace' and is still going
   * through the graph after the 'clear trace', its trace_index is staled as
   * the pool was destroyed.
   * The pool may have been re-allocated because of a new traced buffer, and
   * the trace_index might be valid by pure (bad) luck. In that case the trace
   * will be a mix of both buffer traces, but this should be acceptable.
   */
  trace_index = vlib_buffer_get_trace_index (b);
  if (PREDICT_FALSE (pool_is_free_index (tm->trace_buffer_pool, trace_index)))
    return vnet_trace_placeholder;

  n_data_bytes = round_pow2 (n_data_bytes, sizeof (h[0]));
  n_data_words = n_data_bytes / sizeof (h[0]);
  vec_add2_aligned (tm->trace_buffer_pool[trace_index], h, 1 + n_data_words,
		    sizeof (h[0]));

  h->time = vm->cpu_time_last_node_dispatch;
  h->n_data = n_data_words;
  h->node_index = r->node_index;

  return h->data;
}

/* Non-inline (typical use-case) version of the above */
void *vlib_add_trace (vlib_main_t * vm,
		      vlib_node_runtime_t * r, vlib_buffer_t * b,
		      u32 n_data_bytes);

always_inline vlib_trace_header_t *
vlib_trace_header_next (vlib_trace_header_t * h)
{
  return h + 1 + h->n_data;
}

always_inline void
vlib_free_trace (vlib_main_t * vm, vlib_buffer_t * b)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  u32 trace_index = vlib_buffer_get_trace_index (b);
  vlib_validate_trace (tm, b);
  _vec_len (tm->trace_buffer_pool[trace_index]) = 0;
  pool_put_index (tm->trace_buffer_pool, trace_index);
}

always_inline void
vlib_trace_next_frame (vlib_main_t * vm,
		       vlib_node_runtime_t * r, u32 next_index)
{
  vlib_next_frame_t *nf;
  nf = vlib_node_runtime_get_next_frame (vm, r, next_index);
  nf->flags |= VLIB_FRAME_TRACE;
}

void trace_apply_filter (vlib_main_t * vm);
int vnet_is_packet_traced (vlib_buffer_t * b,
			   u32 classify_table_index, int func);


/*
 * Mark buffer as traced and allocate trace buffer.
 * return 1 if the buffer is successfully traced, 0 if not
 * A buffer might not be traced if tracing is off or if the packet did not
 * match the filter.
 */
always_inline __clib_warn_unused_result int
vlib_trace_buffer (vlib_main_t * vm,
		   vlib_node_runtime_t * r,
		   u32 next_index, vlib_buffer_t * b, int follow_chain)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t **h;

  if (PREDICT_FALSE (tm->trace_enable == 0))
    return 0;

  /* Classifier filter in use? */
  if (PREDICT_FALSE (vlib_global_main.trace_filter.trace_filter_enable))
    {
      /* See if we're supposed to trace this packet... */
      if (vnet_is_packet_traced (
	    b, vlib_global_main.trace_filter.classify_table_index,
	    0 /* full classify */) != 1)
	return 0;
    }

  /*
   * Apply filter to existing traces to keep number of allocated traces low.
   * Performed each time around the main loop.
   */
  if (tm->last_main_loop_count != vm->main_loop_count)
    {
      tm->last_main_loop_count = vm->main_loop_count;
      trace_apply_filter (vm);

      if (tm->trace_buffer_callback)
	(tm->trace_buffer_callback) ((struct vlib_main_t *) vm,
				     (struct vlib_trace_main_t *) tm);
    }

  vlib_trace_next_frame (vm, r, next_index);

  pool_get (tm->trace_buffer_pool, h);

  do
    {
      b->flags |= VLIB_BUFFER_IS_TRACED;
      b->trace_handle = vlib_buffer_make_trace_handle
	(vm->thread_index, h - tm->trace_buffer_pool);
    }
  while (follow_chain && (b = vlib_get_next_buffer (vm, b)));

  return 1;
}

always_inline void
vlib_buffer_copy_trace_flag (vlib_main_t * vm, vlib_buffer_t * b,
			     u32 bi_target)
{
  vlib_buffer_t *b_target = vlib_get_buffer (vm, bi_target);
  b_target->flags |= b->flags & VLIB_BUFFER_IS_TRACED;
  b_target->trace_handle = b->trace_handle;
}

always_inline u32
vlib_get_trace_count (vlib_main_t * vm, vlib_node_runtime_t * rt)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_node_t *tn;

  if (rt->node_index >= vec_len (tm->nodes))
    return 0;
  tn = tm->nodes + rt->node_index;
  ASSERT (tn->count <= tn->limit);

  return tn->limit - tn->count;
}

always_inline void
vlib_set_trace_count (vlib_main_t * vm, vlib_node_runtime_t * rt, u32 count)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_node_t *tn = vec_elt_at_index (tm->nodes, rt->node_index);

  ASSERT (count <= tn->limit);
  tn->count = tn->limit - count;
}

/* Helper function for nodes which only trace buffer data. */
void
vlib_trace_frame_buffers_only (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       u32 * buffers,
			       uword n_buffers,
			       uword next_buffer_stride,
			       uword n_buffer_data_bytes_in_trace);

#endif /* included_vlib_trace_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
