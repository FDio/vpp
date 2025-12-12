/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* error_funcs.h: VLIB error handling */

#ifndef included_vlib_error_funcs_h
#define included_vlib_error_funcs_h

#include <vlib/node_funcs.h>

always_inline void
vlib_error_elog_count (vlib_main_t * vm, uword counter, uword increment)
{
  if (VLIB_ELOG_MAIN_LOOP > 0 && increment > 0)
    {
      elog_main_t *em = vlib_get_elog_main ();
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
