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
 * buffer_node.h: VLIB buffer handling node helper macros/inlines
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

#ifndef included_vlib_buffer_node_h
#define included_vlib_buffer_node_h

#define vlib_validate_buffer_enqueue_x2(vm,node,next_index,to_next,n_left_to_next,bi0,bi1,next0,next1) \
do {									\
  int enqueue_code = (next0 != next_index) + 2*(next1 != next_index);	\
									\
  if (PREDICT_FALSE (enqueue_code != 0))				\
    {									\
      switch (enqueue_code)						\
	{								\
	case 1:								\
	  /* A B A */							\
	  to_next[-2] = bi1;						\
	  to_next -= 1;							\
	  n_left_to_next += 1;						\
	  vlib_set_next_frame_buffer (vm, node, next0, bi0);		\
	  break;							\
									\
	case 2:								\
	  /* A A B */							\
	  to_next -= 1;							\
	  n_left_to_next += 1;						\
	  vlib_set_next_frame_buffer (vm, node, next1, bi1);		\
	  break;							\
									\
	case 3:								\
	  /* A B B or A B C */						\
	  to_next -= 2;							\
	  n_left_to_next += 2;						\
	  vlib_set_next_frame_buffer (vm, node, next0, bi0);		\
	  vlib_set_next_frame_buffer (vm, node, next1, bi1);		\
	  if (next0 == next1)						\
	    {								\
	      vlib_put_next_frame (vm, node, next_index,		\
				   n_left_to_next);			\
	      next_index = next1;					\
	      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next); \
	    }								\
	}								\
    }									\
} while (0)

#define vlib_validate_buffer_enqueue_x1(vm,node,next_index,to_next,n_left_to_next,bi0,next0) \
do {									\
  if (PREDICT_FALSE (next0 != next_index))				\
    {									\
      vlib_put_next_frame (vm, node, next_index, n_left_to_next + 1);	\
      next_index = next0;						\
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next); \
									\
      to_next[0] = bi0;							\
      to_next += 1;							\
      n_left_to_next -= 1;						\
    }									\
} while (0)

always_inline uword
generic_buffer_node_inline (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * frame,
			    uword sizeof_trace,
			    void * opaque1,
			    uword opaque2,
			    void (* two_buffers) (vlib_main_t * vm,
						  void * opaque1,
						  uword opaque2,
						  vlib_buffer_t * b0, vlib_buffer_t * b1,
						  u32 * next0, u32 * next1),
			    void (* one_buffer) (vlib_main_t * vm,
						 void * opaque1,
						 uword opaque2,
						 vlib_buffer_t * b0,
						 u32 * next0))
{
  u32 n_left_from, * from, * to_next;
  u32 next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1, sizeof_trace);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t * p0, * p1;
	  u32 pi0, next0;
	  u32 pi1, next1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 64, LOAD);
	    CLIB_PREFETCH (p3->data, 64, LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  two_buffers (vm, opaque1, opaque2, p0, p1, &next0, &next1);

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}
    
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  u32 pi0, next0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);

	  one_buffer (vm, opaque1, opaque2, p0, &next0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

#endif /* included_vlib_buffer_node_h */
