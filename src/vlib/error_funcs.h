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
 * error_funcs.h: VLIB error handling
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

#ifndef included_vlib_error_funcs_h
#define included_vlib_error_funcs_h

#include <vlib/node_funcs.h>

always_inline void
vlib_error_elog_count (vlib_main_t * vm, uword counter, uword increment)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  if (VLIB_ELOG_MAIN_LOOP > 0 && increment > 0)
    {
      elog_main_t *em = &vgm->elog_main;
      elog (em, vec_elt_at_index (vm->error_elog_event_types, counter),
	    increment);
    }
}

always_inline void
vlib_error_count (vlib_main_t * vm, uword node_index,
		  uword counter, uword increment)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_error_main_t *em = &vm->error_main;

  ASSERT (counter < n->n_errors);
  counter += n->error_heap_index;

  ASSERT (counter < vec_len (em->counters));
  em->counters[counter] += increment;

  vlib_error_elog_count (vm, counter, increment);
}

/* Drop all buffers in frame with given error code. */
uword
vlib_error_drop_buffers (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 u32 * buffers,
			 u32 next_buffer_stride,
			 u32 n_buffers,
			 u32 error_next_index,
			 u32 error_node, u32 error_code);

#endif /* included_vlib_error_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
