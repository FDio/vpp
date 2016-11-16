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

/** \file
    vlib buffer/node functions
*/

/** \brief Finish enqueueing two buffers forward in the graph.
 Standard dual loop boilerplate element. This is a MACRO,
 with MULTIPLE SIDE EFFECTS. In the ideal case,
 <code>next_index == next0 == next1</code>,
 which means that the speculative enqueue at the top of the dual loop
 has correctly dealt with both packets. In that case, the macro does
 nothing at all.

 @param vm vlib_main_t pointer, varies by thread
 @param node current node vlib_node_runtime_t pointer
 @param next_index speculated next index used for both packets
 @param to_next speculated vector pointer used for both packets
 @param n_left_to_next number of slots left in speculated vector
 @param bi0 first buffer index
 @param bi1 second buffer index
 @param next0 actual next index to be used for the first packet
 @param next1 actual next index to be used for the second packet

 @return @c next_index -- speculative next index to be used for future packets
 @return @c to_next -- speculative frame to be used for future packets
 @return @c n_left_to_next -- number of slots left in speculative frame
*/

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


/** \brief Finish enqueueing four buffers forward in the graph.
 Standard quad loop boilerplate element. This is a MACRO,
 with MULTIPLE SIDE EFFECTS. In the ideal case,
 <code>next_index == next0 == next1 == next2 == next3</code>,
 which means that the speculative enqueue at the top of the quad loop
 has correctly dealt with all four packets. In that case, the macro does
 nothing at all.

 @param vm vlib_main_t pointer, varies by thread
 @param node current node vlib_node_runtime_t pointer
 @param next_index speculated next index used for both packets
 @param to_next speculated vector pointer used for both packets
 @param n_left_to_next number of slots left in speculated vector
 @param bi0 first buffer index
 @param bi1 second buffer index
 @param bi2 third buffer index
 @param bi3 fourth buffer index
 @param next0 actual next index to be used for the first packet
 @param next1 actual next index to be used for the second packet
 @param next2 actual next index to be used for the third packet
 @param next3 actual next index to be used for the fourth packet

 @return @c next_index -- speculative next index to be used for future packets
 @return @c to_next -- speculative frame to be used for future packets
 @return @c n_left_to_next -- number of slots left in speculative frame
*/

#define vlib_validate_buffer_enqueue_x4(vm,node,next_index,to_next,n_left_to_next,bi0,bi1,bi2,bi3,next0,next1,next2,next3) \
do {                                                                    \
  /* After the fact: check the [speculative] enqueue to "next" */       \
  u32 fix_speculation = next_index != next0 || next_index != next1      \
    || next_index != next2 || next_index != next3;                      \
  if (PREDICT_FALSE(fix_speculation))                                   \
    {                                                                   \
      /* rewind... */                                                   \
      to_next -= 4;                                                     \
      n_left_to_next += 4;                                              \
                                                                        \
      /* If bi0 belongs to "next", send it there */                     \
      if (next_index == next0)                                          \
        {                                                               \
          to_next[0] = bi0;                                             \
          to_next++;                                                    \
          n_left_to_next --;                                            \
        }                                                               \
      else              /* send it where it needs to go */              \
        vlib_set_next_frame_buffer (vm, node, next0, bi0);              \
                                                                        \
      if (next_index == next1)                                          \
        {                                                               \
          to_next[0] = bi1;                                             \
          to_next++;                                                    \
          n_left_to_next --;                                            \
        }                                                               \
      else                                                              \
        vlib_set_next_frame_buffer (vm, node, next1, bi1);              \
                                                                        \
      if (next_index == next2)                                          \
        {                                                               \
          to_next[0] = bi2;                                             \
          to_next++;                                                    \
          n_left_to_next --;                                            \
        }                                                               \
      else                                                              \
        vlib_set_next_frame_buffer (vm, node, next2, bi2);              \
                                                                        \
      if (next_index == next3)                                          \
        {                                                               \
          to_next[0] = bi3;                                             \
          to_next++;                                                    \
          n_left_to_next --;                                            \
        }                                                               \
      else                                                              \
        vlib_set_next_frame_buffer (vm, node, next3, bi3);              \
                                                                        \
      /* Change speculation: last 2 packets went to the same node */    \
      if (next2 == next3)                                               \
        {                                                               \
          vlib_put_next_frame (vm, node, next_index, n_left_to_next);   \
          next_index = next3;                                           \
          vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next); \
        }                                                               \
    }                                                                   \
 } while(0);

/** \brief Finish enqueueing one buffer forward in the graph.
 Standard single loop boilerplate element. This is a MACRO,
 with MULTIPLE SIDE EFFECTS. In the ideal case,
 <code>next_index == next0</code>,
 which means that the speculative enqueue at the top of the single loop
 has correctly dealt with the packet in hand. In that case, the macro does
 nothing at all.

 @param vm vlib_main_t pointer, varies by thread
 @param node current node vlib_node_runtime_t pointer
 @param next_index speculated next index used for both packets
 @param to_next speculated vector pointer used for both packets
 @param n_left_to_next number of slots left in speculated vector
 @param bi0 first buffer index
 @param next0 actual next index to be used for the first packet

 @return @c next_index -- speculative next index to be used for future packets
 @return @c to_next -- speculative frame to be used for future packets
 @return @c n_left_to_next -- number of slots left in speculative frame
*/
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
			    void *opaque1,
			    uword opaque2,
			    void (*two_buffers) (vlib_main_t * vm,
						 void *opaque1,
						 uword opaque2,
						 vlib_buffer_t * b0,
						 vlib_buffer_t * b1,
						 u32 * next0, u32 * next1),
			    void (*one_buffer) (vlib_main_t * vm,
						void *opaque1, uword opaque2,
						vlib_buffer_t * b0,
						u32 * next0))
{
  u32 n_left_from, *from, *to_next;
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

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  u32 pi0, next0;
	  u32 pi1, next1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

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
	  vlib_buffer_t *p0;
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
