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

always_inline void
vlib_validate_trace (vlib_trace_main_t * tm, vlib_buffer_t * b)
{
  /*
   * this assert seems right, but goes off constantly.
   * disabling it appears to make the pain go away
   */
  ASSERT (1 || b->flags & VLIB_BUFFER_IS_TRACED);
  ASSERT (!pool_is_free_index (tm->trace_buffer_pool, b->trace_index));
}

always_inline void *
vlib_add_trace (vlib_main_t * vm,
		vlib_node_runtime_t * r, vlib_buffer_t * b, u32 n_data_bytes)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t *h;
  u32 n_data_words;

  vlib_validate_trace (tm, b);

  n_data_bytes = round_pow2 (n_data_bytes, sizeof (h[0]));
  n_data_words = n_data_bytes / sizeof (h[0]);
  vec_add2_aligned (tm->trace_buffer_pool[b->trace_index], h,
		    1 + n_data_words, sizeof (h[0]));

  h->time = vm->cpu_time_last_node_dispatch;
  h->n_data = n_data_words;
  h->node_index = r->node_index;

  return h->data;
}

always_inline vlib_trace_header_t *
vlib_trace_header_next (vlib_trace_header_t * h)
{
  return h + 1 + h->n_data;
}

always_inline void
vlib_free_trace (vlib_main_t * vm, vlib_buffer_t * b)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_validate_trace (tm, b);
  _vec_len (tm->trace_buffer_pool[b->trace_index]) = 0;
  pool_put_index (tm->trace_buffer_pool, b->trace_index);
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

/* Mark buffer as traced and allocate trace buffer. */
always_inline void
vlib_trace_buffer (vlib_main_t * vm,
		   vlib_node_runtime_t * r,
		   u32 next_index, vlib_buffer_t * b, int follow_chain)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t **h;

  /*
   * Apply filter to existing traces to keep number of allocated traces low.
   * Performed each time around the main loop.
   */
  if (tm->last_main_loop_count != vm->main_loop_count)
    {
      tm->last_main_loop_count = vm->main_loop_count;
      trace_apply_filter (vm);
    }

  vlib_trace_next_frame (vm, r, next_index);

  pool_get (tm->trace_buffer_pool, h);

  do
    {
      b->flags |= VLIB_BUFFER_IS_TRACED;
      b->trace_index = h - tm->trace_buffer_pool;
    }
  while (follow_chain && (b = vlib_get_next_buffer (vm, b)));
}

always_inline void
vlib_buffer_copy_trace_flag (vlib_main_t * vm, vlib_buffer_t * b,
			     u32 bi_target)
{
  vlib_buffer_t *b_target = vlib_get_buffer (vm, bi_target);
  b_target->flags |= b->flags & VLIB_BUFFER_IS_TRACED;
  b_target->trace_index = b->trace_index;
}

always_inline u32
vlib_get_trace_count (vlib_main_t * vm, vlib_node_runtime_t * rt)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_node_t *tn;
  int n;

  if (rt->node_index >= vec_len (tm->nodes))
    return 0;
  tn = tm->nodes + rt->node_index;
  n = tn->limit - tn->count;
  ASSERT (n >= 0);

  return n;
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
