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
 * node_funcs.h: processing nodes global functions/inlines
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

/** \file
    vlib node functions
*/


#ifndef included_vlib_node_funcs_h
#define included_vlib_node_funcs_h

#include <vppinfra/fifo.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

/** \brief Get vlib node by index.
 @warning This function will ASSERT if @c i is out of range.
 @param vm vlib_main_t pointer, varies by thread
 @param i node index.
 @return pointer to the requested vlib_node_t.
*/

always_inline vlib_node_t *
vlib_get_node (vlib_main_t * vm, u32 i)
{
  return vec_elt (vm->node_main.nodes, i);
}

/** \brief Get vlib node by graph arc (next) index.
 @param vm vlib_main_t pointer, varies by thread
 @param node_index index of original node
 @param next_index graph arc index
 @return pointer to the vlib_node_t at the end of the indicated arc
*/

always_inline vlib_node_t *
vlib_get_next_node (vlib_main_t * vm, u32 node_index, u32 next_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;

  n = vec_elt (nm->nodes, node_index);
  ASSERT (next_index < vec_len (n->next_nodes));
  return vlib_get_node (vm, n->next_nodes[next_index]);
}

/** \brief Get node runtime by node index.
 @param vm vlib_main_t pointer, varies by thread
 @param node_index index of node
 @return pointer to the indicated vlib_node_runtime_t
*/

always_inline vlib_node_runtime_t *
vlib_node_get_runtime (vlib_main_t * vm, u32 node_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vec_elt (nm->nodes, node_index);
  vlib_process_t *p;
  if (n->type != VLIB_NODE_TYPE_PROCESS)
    return vec_elt_at_index (nm->nodes_by_type[n->type], n->runtime_index);
  else
    {
      p = vec_elt (nm->processes, n->runtime_index);
      return &p->node_runtime;
    }
}

/** \brief Get node runtime private data by node index.
 @param vm vlib_main_t pointer, varies by thread
 @param node_index index of the node
 @return pointer to the indicated vlib_node_runtime_t private data
*/

always_inline void *
vlib_node_get_runtime_data (vlib_main_t * vm, u32 node_index)
{
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, node_index);
  return r->runtime_data;
}

/** \brief Set node runtime private data.
 @param vm vlib_main_t pointer, varies by thread
 @param node_index index of the node
 @param runtime_data arbitrary runtime private data
 @param n_runtime_data_bytes size of runtime private data
*/

always_inline void
vlib_node_set_runtime_data (vlib_main_t * vm, u32 node_index,
			    void *runtime_data, u32 n_runtime_data_bytes)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, node_index);

  n->runtime_data_bytes = n_runtime_data_bytes;
  vec_free (n->runtime_data);
  vec_add (n->runtime_data, runtime_data, n_runtime_data_bytes);

  ASSERT (vec_len (n->runtime_data) <= sizeof (vlib_node_runtime_t) -
	  STRUCT_OFFSET_OF (vlib_node_runtime_t, runtime_data));

  if (vec_len (n->runtime_data) > 0)
    clib_memcpy_fast (r->runtime_data, n->runtime_data,
		      vec_len (n->runtime_data));
}

/** \brief Set node dispatch state.
 @param vm vlib_main_t pointer, varies by thread
 @param node_index index of the node
 @param new_state new state for node, see vlib_node_state_t
*/
always_inline void
vlib_node_set_state (vlib_main_t * vm, u32 node_index,
		     vlib_node_state_t new_state)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  vlib_node_runtime_t *r;

  n = vec_elt (nm->nodes, node_index);
  if (n->type == VLIB_NODE_TYPE_PROCESS)
    {
      vlib_process_t *p = vec_elt (nm->processes, n->runtime_index);
      r = &p->node_runtime;

      /* When disabling make sure flags are cleared. */
      p->flags &= ~(VLIB_PROCESS_RESUME_PENDING
		    | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK
		    | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT);
    }
  else
    r = vec_elt_at_index (nm->nodes_by_type[n->type], n->runtime_index);

  ASSERT (new_state < VLIB_N_NODE_STATE);

  if (n->type == VLIB_NODE_TYPE_INPUT)
    {
      ASSERT (nm->input_node_counts_by_state[n->state] > 0);
      nm->input_node_counts_by_state[n->state] -= 1;
      nm->input_node_counts_by_state[new_state] += 1;
    }

  n->state = new_state;
  r->state = new_state;
}

/** \brief Get node dispatch state.
 @param vm vlib_main_t pointer, varies by thread
 @param node_index index of the node
 @return state for node, see vlib_node_state_t
*/
always_inline vlib_node_state_t
vlib_node_get_state (vlib_main_t * vm, u32 node_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  n = vec_elt (nm->nodes, node_index);
  return n->state;
}

always_inline void
vlib_node_set_interrupt_pending (vlib_main_t * vm, u32 node_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vec_elt (nm->nodes, node_index);
  ASSERT (n->type == VLIB_NODE_TYPE_INPUT);
  clib_spinlock_lock_if_init (&nm->pending_interrupt_lock);
  vec_add1 (nm->pending_interrupt_node_runtime_indices, n->runtime_index);
  clib_spinlock_unlock_if_init (&nm->pending_interrupt_lock);
}

always_inline vlib_process_t *
vlib_get_process_from_node (vlib_main_t * vm, vlib_node_t * node)
{
  vlib_node_main_t *nm = &vm->node_main;
  ASSERT (node->type == VLIB_NODE_TYPE_PROCESS);
  return vec_elt (nm->processes, node->runtime_index);
}

always_inline vlib_frame_t *
vlib_get_frame (vlib_main_t * vm, vlib_frame_t * f)
{
  ASSERT (f != NULL);
  ASSERT (f->frame_flags & VLIB_FRAME_IS_ALLOCATED);
  return f;
}

always_inline void
vlib_frame_no_append (vlib_frame_t * f)
{
  f->frame_flags |= VLIB_FRAME_NO_APPEND;
}

/* Byte alignment for vector arguments. */
#define VLIB_FRAME_VECTOR_ALIGN (1 << 4)

always_inline u32
vlib_frame_vector_byte_offset (u32 scalar_size)
{
  return round_pow2 (sizeof (vlib_frame_t) + scalar_size,
		     VLIB_FRAME_VECTOR_ALIGN);
}

/** \brief Get pointer to frame vector data.
 @param f vlib_frame_t pointer
 @return pointer to first vector element in frame
*/
always_inline void *
vlib_frame_vector_args (vlib_frame_t * f)
{
  return (void *) f + vlib_frame_vector_byte_offset (f->scalar_size);
}

/** \brief Get pointer to frame scalar data.

 @param f vlib_frame_t pointer

 @return arbitrary node scalar data

 @sa vlib_frame_vector_args
*/
always_inline void *
vlib_frame_scalar_args (vlib_frame_t * f)
{
  return vlib_frame_vector_args (f) - f->scalar_size;
}

always_inline vlib_next_frame_t *
vlib_node_runtime_get_next_frame (vlib_main_t * vm,
				  vlib_node_runtime_t * n, u32 next_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_next_frame_t *nf;

  ASSERT (next_index < n->n_next_nodes);
  nf = vec_elt_at_index (nm->next_frames, n->next_frame_index + next_index);

  if (CLIB_DEBUG > 0)
    {
      vlib_node_t *node, *next;
      node = vec_elt (nm->nodes, n->node_index);
      next = vec_elt (nm->nodes, node->next_nodes[next_index]);
      ASSERT (nf->node_runtime_index == next->runtime_index);
    }

  return nf;
}

/** \brief Get pointer to frame by (@c node_index, @c next_index).

 @warning This is not a function that you should call directly.
 See @ref vlib_get_next_frame instead.

 @param vm vlib_main_t pointer, varies by thread
 @param node_index index of the node
 @param next_index graph arc index

 @return pointer to the requested vlib_next_frame_t

 @sa vlib_get_next_frame
*/

always_inline vlib_next_frame_t *
vlib_node_get_next_frame (vlib_main_t * vm, u32 node_index, u32 next_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  vlib_node_runtime_t *r;

  n = vec_elt (nm->nodes, node_index);
  r = vec_elt_at_index (nm->nodes_by_type[n->type], n->runtime_index);
  return vlib_node_runtime_get_next_frame (vm, r, next_index);
}

vlib_frame_t *vlib_get_next_frame_internal (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    u32 next_index,
					    u32 alloc_new_frame);

#define vlib_get_next_frame_macro(vm,node,next_index,vectors,n_vectors_left,alloc_new_frame) \
do {									\
  vlib_frame_t * _f							\
    = vlib_get_next_frame_internal ((vm), (node), (next_index),		\
				    (alloc_new_frame));			\
  u32 _n = _f->n_vectors;						\
  (vectors) = vlib_frame_vector_args (_f) + _n * sizeof ((vectors)[0]); \
  (n_vectors_left) = VLIB_FRAME_SIZE - _n;				\
} while (0)


/** \brief Get pointer to next frame vector data by
    (@c vlib_node_runtime_t, @c next_index).
 Standard single/dual loop boilerplate element.
 @attention This is a MACRO, with SIDE EFFECTS.

 @param vm vlib_main_t pointer, varies by thread
 @param node current node vlib_node_runtime_t pointer
 @param next_index requested graph arc index

 @return @c vectors -- pointer to next available vector slot
 @return @c n_vectors_left -- number of vector slots available
*/
#define vlib_get_next_frame(vm,node,next_index,vectors,n_vectors_left)	\
  vlib_get_next_frame_macro (vm, node, next_index,			\
			     vectors, n_vectors_left,			\
			     /* alloc new frame */ 0)

#define vlib_get_new_next_frame(vm,node,next_index,vectors,n_vectors_left) \
  vlib_get_next_frame_macro (vm, node, next_index,			\
			     vectors, n_vectors_left,			\
			     /* alloc new frame */ 1)

/** \brief Release pointer to next frame vector data.
 Standard single/dual loop boilerplate element.
 @param vm vlib_main_t pointer, varies by thread
 @param r current node vlib_node_runtime_t pointer
 @param next_index graph arc index
 @param n_packets_left number of slots still available in vector
*/
void
vlib_put_next_frame (vlib_main_t * vm,
		     vlib_node_runtime_t * r,
		     u32 next_index, u32 n_packets_left);

/* Combination get plus put.  Returns vector argument just added. */
#define vlib_set_next_frame(vm,node,next_index,v)			\
({									\
  uword _n_left;							\
  vlib_get_next_frame ((vm), (node), (next_index), (v), _n_left);	\
  ASSERT (_n_left > 0);							\
  vlib_put_next_frame ((vm), (node), (next_index), _n_left - 1);	\
  (v);									\
})

always_inline void
vlib_set_next_frame_buffer (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    u32 next_index, u32 buffer_index)
{
  u32 *p;
  p = vlib_set_next_frame (vm, node, next_index, p);
  p[0] = buffer_index;
}

vlib_frame_t *vlib_get_frame_to_node (vlib_main_t * vm, u32 to_node_index);
void vlib_put_frame_to_node (vlib_main_t * vm, u32 to_node_index,
			     vlib_frame_t * f);

always_inline uword
vlib_in_process_context (vlib_main_t * vm)
{
  return vm->node_main.current_process_index != ~0;
}

always_inline vlib_process_t *
vlib_get_current_process (vlib_main_t * vm)
{
  vlib_node_main_t *nm = &vm->node_main;
  if (vlib_in_process_context (vm))
    return vec_elt (nm->processes, nm->current_process_index);
  return 0;
}

always_inline uword
vlib_current_process (vlib_main_t * vm)
{
  return vlib_get_current_process (vm)->node_runtime.node_index;
}

/** Returns TRUE if a process suspend time is less than 10us
    @param dt - remaining poll time in seconds
    @returns 1 if dt < 10e-6, 0 otherwise
*/
always_inline uword
vlib_process_suspend_time_is_zero (f64 dt)
{
  return dt < 10e-6;
}

/** Suspend a vlib cooperative multi-tasking thread for a period of time
    @param vm - vlib_main_t *
    @param dt - suspend interval in seconds
    @returns VLIB_PROCESS_RESUME_LONGJMP_RESUME, routinely ignored
*/

always_inline uword
vlib_process_suspend (vlib_main_t * vm, f64 dt)
{
  uword r;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p = vec_elt (nm->processes, nm->current_process_index);

  if (vlib_process_suspend_time_is_zero (dt))
    return VLIB_PROCESS_RESUME_LONGJMP_RESUME;

  p->flags |= VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK;
  r = clib_setjmp (&p->resume_longjmp, VLIB_PROCESS_RESUME_LONGJMP_SUSPEND);
  if (r == VLIB_PROCESS_RESUME_LONGJMP_SUSPEND)
    {
      /* expiration time in 10us ticks */
      p->resume_clock_interval = dt * 1e5;
      clib_longjmp (&p->return_longjmp, VLIB_PROCESS_RETURN_LONGJMP_SUSPEND);
    }

  return r;
}

always_inline void
vlib_process_free_event_type (vlib_process_t * p, uword t,
			      uword is_one_time_event)
{
  ASSERT (!pool_is_free_index (p->event_type_pool, t));
  pool_put_index (p->event_type_pool, t);
  if (is_one_time_event)
    p->one_time_event_type_bitmap =
      clib_bitmap_andnoti (p->one_time_event_type_bitmap, t);
}

always_inline void
vlib_process_maybe_free_event_type (vlib_process_t * p, uword t)
{
  ASSERT (!pool_is_free_index (p->event_type_pool, t));
  if (clib_bitmap_get (p->one_time_event_type_bitmap, t))
    vlib_process_free_event_type (p, t, /* is_one_time_event */ 1);
}

always_inline void *
vlib_process_get_event_data (vlib_main_t * vm,
			     uword * return_event_type_opaque)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p;
  vlib_process_event_type_t *et;
  uword t;
  void *event_data_vector;

  p = vec_elt (nm->processes, nm->current_process_index);

  /* Find first type with events ready.
     Return invalid type when there's nothing there. */
  t = clib_bitmap_first_set (p->non_empty_event_type_bitmap);
  if (t == ~0)
    return 0;

  p->non_empty_event_type_bitmap =
    clib_bitmap_andnoti (p->non_empty_event_type_bitmap, t);

  ASSERT (_vec_len (p->pending_event_data_by_type_index[t]) > 0);
  event_data_vector = p->pending_event_data_by_type_index[t];
  p->pending_event_data_by_type_index[t] = 0;

  et = pool_elt_at_index (p->event_type_pool, t);

  /* Return user's opaque value and possibly index. */
  *return_event_type_opaque = et->opaque;

  vlib_process_maybe_free_event_type (p, t);

  return event_data_vector;
}

/* Return event data vector for later reuse.  We reuse event data to avoid
   repeatedly allocating event vectors in cases where we care about speed. */
always_inline void
vlib_process_put_event_data (vlib_main_t * vm, void *event_data)
{
  vlib_node_main_t *nm = &vm->node_main;
  vec_add1 (nm->recycled_event_data_vectors, event_data);
}

/** Return the first event type which has occurred and a vector of per-event
    data of that type, or a timeout indication

    @param vm - vlib_main_t pointer
    @param data_vector - pointer to a (uword *) vector to receive event data
    @returns either an event type and a vector of per-event instance data,
    or ~0 to indicate a timeout.
*/

always_inline uword
vlib_process_get_events (vlib_main_t * vm, uword ** data_vector)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p;
  vlib_process_event_type_t *et;
  uword r, t, l;

  p = vec_elt (nm->processes, nm->current_process_index);

  /* Find first type with events ready.
     Return invalid type when there's nothing there. */
  t = clib_bitmap_first_set (p->non_empty_event_type_bitmap);
  if (t == ~0)
    return t;

  p->non_empty_event_type_bitmap =
    clib_bitmap_andnoti (p->non_empty_event_type_bitmap, t);

  l = _vec_len (p->pending_event_data_by_type_index[t]);
  if (data_vector)
    vec_add (*data_vector, p->pending_event_data_by_type_index[t], l);
  _vec_len (p->pending_event_data_by_type_index[t]) = 0;

  et = pool_elt_at_index (p->event_type_pool, t);

  /* Return user's opaque value. */
  r = et->opaque;

  vlib_process_maybe_free_event_type (p, t);

  return r;
}

always_inline uword
vlib_process_get_events_helper (vlib_process_t * p, uword t,
				uword ** data_vector)
{
  uword l;

  p->non_empty_event_type_bitmap =
    clib_bitmap_andnoti (p->non_empty_event_type_bitmap, t);

  l = _vec_len (p->pending_event_data_by_type_index[t]);
  if (data_vector)
    vec_add (*data_vector, p->pending_event_data_by_type_index[t], l);
  _vec_len (p->pending_event_data_by_type_index[t]) = 0;

  vlib_process_maybe_free_event_type (p, t);

  return l;
}

/* As above but query as specified type of event.  Returns number of
   events found. */
always_inline uword
vlib_process_get_events_with_type (vlib_main_t * vm, uword ** data_vector,
				   uword with_type_opaque)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p;
  uword t, *h;

  p = vec_elt (nm->processes, nm->current_process_index);
  h = hash_get (p->event_type_index_by_type_opaque, with_type_opaque);
  if (!h)
    /* This can happen when an event has not yet been
       signaled with given opaque type. */
    return 0;

  t = h[0];
  if (!clib_bitmap_get (p->non_empty_event_type_bitmap, t))
    return 0;

  return vlib_process_get_events_helper (p, t, data_vector);
}

always_inline uword *
vlib_process_wait_for_event (vlib_main_t * vm)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p;
  uword r;

  p = vec_elt (nm->processes, nm->current_process_index);
  if (clib_bitmap_is_zero (p->non_empty_event_type_bitmap))
    {
      p->flags |= VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT;
      r =
	clib_setjmp (&p->resume_longjmp, VLIB_PROCESS_RESUME_LONGJMP_SUSPEND);
      if (r == VLIB_PROCESS_RESUME_LONGJMP_SUSPEND)
	clib_longjmp (&p->return_longjmp,
		      VLIB_PROCESS_RETURN_LONGJMP_SUSPEND);
    }

  return p->non_empty_event_type_bitmap;
}

always_inline uword
vlib_process_wait_for_one_time_event (vlib_main_t * vm,
				      uword ** data_vector,
				      uword with_type_index)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p;
  uword r;

  p = vec_elt (nm->processes, nm->current_process_index);
  ASSERT (!pool_is_free_index (p->event_type_pool, with_type_index));
  while (!clib_bitmap_get (p->non_empty_event_type_bitmap, with_type_index))
    {
      p->flags |= VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT;
      r =
	clib_setjmp (&p->resume_longjmp, VLIB_PROCESS_RESUME_LONGJMP_SUSPEND);
      if (r == VLIB_PROCESS_RESUME_LONGJMP_SUSPEND)
	clib_longjmp (&p->return_longjmp,
		      VLIB_PROCESS_RETURN_LONGJMP_SUSPEND);
    }

  return vlib_process_get_events_helper (p, with_type_index, data_vector);
}

always_inline uword
vlib_process_wait_for_event_with_type (vlib_main_t * vm,
				       uword ** data_vector,
				       uword with_type_opaque)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p;
  uword r, *h;

  p = vec_elt (nm->processes, nm->current_process_index);
  h = hash_get (p->event_type_index_by_type_opaque, with_type_opaque);
  while (!h || !clib_bitmap_get (p->non_empty_event_type_bitmap, h[0]))
    {
      p->flags |= VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT;
      r =
	clib_setjmp (&p->resume_longjmp, VLIB_PROCESS_RESUME_LONGJMP_SUSPEND);
      if (r == VLIB_PROCESS_RESUME_LONGJMP_SUSPEND)
	clib_longjmp (&p->return_longjmp,
		      VLIB_PROCESS_RETURN_LONGJMP_SUSPEND);

      /* See if unknown event type has been signaled now. */
      if (!h)
	h = hash_get (p->event_type_index_by_type_opaque, with_type_opaque);
    }

  return vlib_process_get_events_helper (p, h[0], data_vector);
}

/** Suspend a cooperative multi-tasking thread
    Waits for an event, or for the indicated number of seconds to elapse
    @param vm - vlib_main_t pointer
    @param dt - timeout, in seconds.
    @returns the remaining time interval
*/

always_inline f64
vlib_process_wait_for_event_or_clock (vlib_main_t * vm, f64 dt)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_process_t *p;
  f64 wakeup_time;
  uword r;

  p = vec_elt (nm->processes, nm->current_process_index);

  if (vlib_process_suspend_time_is_zero (dt)
      || !clib_bitmap_is_zero (p->non_empty_event_type_bitmap))
    return dt;

  wakeup_time = vlib_time_now (vm) + dt;

  /* Suspend waiting for both clock and event to occur. */
  p->flags |= (VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT
	       | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK);

  r = clib_setjmp (&p->resume_longjmp, VLIB_PROCESS_RESUME_LONGJMP_SUSPEND);
  if (r == VLIB_PROCESS_RESUME_LONGJMP_SUSPEND)
    {
      p->resume_clock_interval = dt * 1e5;
      clib_longjmp (&p->return_longjmp, VLIB_PROCESS_RETURN_LONGJMP_SUSPEND);
    }

  /* Return amount of time still left to sleep.
     If <= 0 then we've been waken up by the clock (and not an event). */
  return wakeup_time - vlib_time_now (vm);
}

always_inline vlib_process_event_type_t *
vlib_process_new_event_type (vlib_process_t * p, uword with_type_opaque)
{
  vlib_process_event_type_t *et;
  pool_get (p->event_type_pool, et);
  et->opaque = with_type_opaque;
  return et;
}

always_inline uword
vlib_process_create_one_time_event (vlib_main_t * vm, uword node_index,
				    uword with_type_opaque)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_process_t *p = vec_elt (nm->processes, n->runtime_index);
  vlib_process_event_type_t *et;
  uword t;

  et = vlib_process_new_event_type (p, with_type_opaque);
  t = et - p->event_type_pool;
  p->one_time_event_type_bitmap =
    clib_bitmap_ori (p->one_time_event_type_bitmap, t);
  return t;
}

always_inline void
vlib_process_delete_one_time_event (vlib_main_t * vm, uword node_index,
				    uword t)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_process_t *p = vec_elt (nm->processes, n->runtime_index);

  ASSERT (clib_bitmap_get (p->one_time_event_type_bitmap, t));
  vlib_process_free_event_type (p, t, /* is_one_time_event */ 1);
}

always_inline void *
vlib_process_signal_event_helper (vlib_node_main_t * nm,
				  vlib_node_t * n,
				  vlib_process_t * p,
				  uword t,
				  uword n_data_elts, uword n_data_elt_bytes)
{
  uword p_flags, add_to_pending, delete_from_wheel;
  void *data_to_be_written_by_caller;

  ASSERT (n->type == VLIB_NODE_TYPE_PROCESS);

  ASSERT (!pool_is_free_index (p->event_type_pool, t));

  vec_validate (p->pending_event_data_by_type_index, t);

  /* Resize data vector and return caller's data to be written. */
  {
    void *data_vec = p->pending_event_data_by_type_index[t];
    uword l;

    if (!data_vec && vec_len (nm->recycled_event_data_vectors))
      {
	data_vec = vec_pop (nm->recycled_event_data_vectors);
	_vec_len (data_vec) = 0;
      }

    l = vec_len (data_vec);

    data_vec = _vec_resize (data_vec,
			    /* length_increment */ n_data_elts,
			    /* total size after increment */
			    (l + n_data_elts) * n_data_elt_bytes,
			    /* header_bytes */ 0, /* data_align */ 0);

    p->pending_event_data_by_type_index[t] = data_vec;
    data_to_be_written_by_caller = data_vec + l * n_data_elt_bytes;
  }

  p->non_empty_event_type_bitmap =
    clib_bitmap_ori (p->non_empty_event_type_bitmap, t);

  p_flags = p->flags;

  /* Event was already signalled? */
  add_to_pending = (p_flags & VLIB_PROCESS_RESUME_PENDING) == 0;

  /* Process will resume when suspend time elapses? */
  delete_from_wheel = 0;
  if (p_flags & VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK)
    {
      /* Waiting for both event and clock? */
      if (p_flags & VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT)
	{
	  if (!TW (tw_timer_handle_is_free)
	      ((TWT (tw_timer_wheel) *) nm->timing_wheel,
	       p->stop_timer_handle))
	    delete_from_wheel = 1;
	  else
	    /* timer just popped so process should already be on the list */
	    add_to_pending = 0;
	}
      else
	/* Waiting only for clock.  Event will be queue and may be
	   handled when timer expires. */
	add_to_pending = 0;
    }

  /* Never add current process to pending vector since current process is
     already running. */
  add_to_pending &= nm->current_process_index != n->runtime_index;

  if (add_to_pending)
    {
      u32 x = vlib_timing_wheel_data_set_suspended_process (n->runtime_index);
      p->flags = p_flags | VLIB_PROCESS_RESUME_PENDING;
      vec_add1 (nm->data_from_advancing_timing_wheel, x);
      if (delete_from_wheel)
	TW (tw_timer_stop) ((TWT (tw_timer_wheel) *) nm->timing_wheel,
			    p->stop_timer_handle);
    }

  return data_to_be_written_by_caller;
}

always_inline void *
vlib_process_signal_event_data (vlib_main_t * vm,
				uword node_index,
				uword type_opaque,
				uword n_data_elts, uword n_data_elt_bytes)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_process_t *p = vec_elt (nm->processes, n->runtime_index);
  uword *h, t;

  /* Must be in main thread */
  ASSERT (vlib_get_thread_index () == 0);

  h = hash_get (p->event_type_index_by_type_opaque, type_opaque);
  if (!h)
    {
      vlib_process_event_type_t *et =
	vlib_process_new_event_type (p, type_opaque);
      t = et - p->event_type_pool;
      hash_set (p->event_type_index_by_type_opaque, type_opaque, t);
    }
  else
    t = h[0];

  return vlib_process_signal_event_helper (nm, n, p, t, n_data_elts,
					   n_data_elt_bytes);
}

always_inline void *
vlib_process_signal_event_at_time (vlib_main_t * vm,
				   f64 dt,
				   uword node_index,
				   uword type_opaque,
				   uword n_data_elts, uword n_data_elt_bytes)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_process_t *p = vec_elt (nm->processes, n->runtime_index);
  uword *h, t;

  h = hash_get (p->event_type_index_by_type_opaque, type_opaque);
  if (!h)
    {
      vlib_process_event_type_t *et =
	vlib_process_new_event_type (p, type_opaque);
      t = et - p->event_type_pool;
      hash_set (p->event_type_index_by_type_opaque, type_opaque, t);
    }
  else
    t = h[0];

  if (vlib_process_suspend_time_is_zero (dt))
    return vlib_process_signal_event_helper (nm, n, p, t, n_data_elts,
					     n_data_elt_bytes);
  else
    {
      vlib_signal_timed_event_data_t *te;

      pool_get_aligned (nm->signal_timed_event_data_pool, te, sizeof (te[0]));

      te->n_data_elts = n_data_elts;
      te->n_data_elt_bytes = n_data_elt_bytes;
      te->n_data_bytes = n_data_elts * n_data_elt_bytes;

      /* Assert that structure fields are big enough. */
      ASSERT (te->n_data_elts == n_data_elts);
      ASSERT (te->n_data_elt_bytes == n_data_elt_bytes);
      ASSERT (te->n_data_bytes == n_data_elts * n_data_elt_bytes);

      te->process_node_index = n->runtime_index;
      te->event_type_index = t;

      p->stop_timer_handle =
	TW (tw_timer_start) ((TWT (tw_timer_wheel) *) nm->timing_wheel,
			     vlib_timing_wheel_data_set_timed_event
			     (te - nm->signal_timed_event_data_pool),
			     0 /* timer_id */ ,
			     (vlib_time_now (vm) + dt) * 1e5);

      /* Inline data big enough to hold event? */
      if (te->n_data_bytes < sizeof (te->inline_event_data))
	return te->inline_event_data;
      else
	{
	  te->event_data_as_vector = 0;
	  vec_resize (te->event_data_as_vector, te->n_data_bytes);
	  return te->event_data_as_vector;
	}
    }
}

always_inline void *
vlib_process_signal_one_time_event_data (vlib_main_t * vm,
					 uword node_index,
					 uword type_index,
					 uword n_data_elts,
					 uword n_data_elt_bytes)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_process_t *p = vec_elt (nm->processes, n->runtime_index);
  return vlib_process_signal_event_helper (nm, n, p, type_index, n_data_elts,
					   n_data_elt_bytes);
}

always_inline void
vlib_process_signal_event (vlib_main_t * vm,
			   uword node_index, uword type_opaque, uword data)
{
  uword *d = vlib_process_signal_event_data (vm, node_index, type_opaque,
					     1 /* elts */ , sizeof (uword));
  d[0] = data;
}

always_inline void
vlib_process_signal_event_pointer (vlib_main_t * vm,
				   uword node_index,
				   uword type_opaque, void *data)
{
  void **d = vlib_process_signal_event_data (vm, node_index, type_opaque,
					     1 /* elts */ , sizeof (data));
  d[0] = data;
}

/**
 * Signal event to process from any thread.
 *
 * When in doubt, use this.
 */
always_inline void
vlib_process_signal_event_mt (vlib_main_t * vm,
			      uword node_index, uword type_opaque, uword data)
{
  if (vlib_get_thread_index () != 0)
    {
      vlib_process_signal_event_mt_args_t args = {
	.node_index = node_index,
	.type_opaque = type_opaque,
	.data = data,
      };
      vlib_rpc_call_main_thread (vlib_process_signal_event_mt_helper,
				 (u8 *) & args, sizeof (args));
    }
  else
    vlib_process_signal_event (vm, node_index, type_opaque, data);
}

always_inline void
vlib_process_signal_one_time_event (vlib_main_t * vm,
				    uword node_index,
				    uword type_index, uword data)
{
  uword *d =
    vlib_process_signal_one_time_event_data (vm, node_index, type_index,
					     1 /* elts */ , sizeof (uword));
  d[0] = data;
}

always_inline void
vlib_signal_one_time_waiting_process (vlib_main_t * vm,
				      vlib_one_time_waiting_process_t * p)
{
  vlib_process_signal_one_time_event (vm, p->node_index, p->one_time_event,
				      /* data */ ~0);
  clib_memset (p, ~0, sizeof (p[0]));
}

always_inline void
vlib_signal_one_time_waiting_process_vector (vlib_main_t * vm,
					     vlib_one_time_waiting_process_t
					     ** wps)
{
  vlib_one_time_waiting_process_t *wp;
  vec_foreach (wp, *wps) vlib_signal_one_time_waiting_process (vm, wp);
  vec_free (*wps);
}

always_inline void
vlib_current_process_wait_for_one_time_event (vlib_main_t * vm,
					      vlib_one_time_waiting_process_t
					      * p)
{
  p->node_index = vlib_current_process (vm);
  p->one_time_event = vlib_process_create_one_time_event (vm, p->node_index,	/* type opaque */
							  ~0);
  vlib_process_wait_for_one_time_event (vm,
					/* don't care about data */ 0,
					p->one_time_event);
}

always_inline void
vlib_current_process_wait_for_one_time_event_vector (vlib_main_t * vm,
						     vlib_one_time_waiting_process_t
						     ** wps)
{
  vlib_one_time_waiting_process_t *wp;
  vec_add2 (*wps, wp, 1);
  vlib_current_process_wait_for_one_time_event (vm, wp);
}

always_inline u32
vlib_node_runtime_update_main_loop_vector_stats (vlib_main_t * vm,
						 vlib_node_runtime_t * node,
						 uword n_vectors)
{
  u32 i, d, vi0, vi1;
  u32 i0, i1;

  ASSERT (is_pow2 (ARRAY_LEN (node->main_loop_vector_stats)));
  i = ((vm->main_loop_count >> VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE)
       & (ARRAY_LEN (node->main_loop_vector_stats) - 1));
  i0 = i ^ 0;
  i1 = i ^ 1;
  d = ((vm->main_loop_count >> VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE)
       -
       (node->main_loop_count_last_dispatch >>
	VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE));
  vi0 = node->main_loop_vector_stats[i0];
  vi1 = node->main_loop_vector_stats[i1];
  vi0 = d == 0 ? vi0 : 0;
  vi1 = d <= 1 ? vi1 : 0;
  vi0 += n_vectors;
  node->main_loop_vector_stats[i0] = vi0;
  node->main_loop_vector_stats[i1] = vi1;
  node->main_loop_count_last_dispatch = vm->main_loop_count;
  /* Return previous counter. */
  return node->main_loop_vector_stats[i1];
}

always_inline f64
vlib_node_vectors_per_main_loop_as_float (vlib_main_t * vm, u32 node_index)
{
  vlib_node_runtime_t *rt = vlib_node_get_runtime (vm, node_index);
  u32 v;

  v = vlib_node_runtime_update_main_loop_vector_stats (vm, rt,	/* n_vectors */
						       0);
  return (f64) v / (1 << VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE);
}

always_inline u32
vlib_node_vectors_per_main_loop_as_integer (vlib_main_t * vm, u32 node_index)
{
  vlib_node_runtime_t *rt = vlib_node_get_runtime (vm, node_index);
  u32 v;

  v = vlib_node_runtime_update_main_loop_vector_stats (vm, rt,	/* n_vectors */
						       0);
  return v >> VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE;
}

void
vlib_frame_free (vlib_main_t * vm, vlib_node_runtime_t * r, vlib_frame_t * f);

/* Return the edge index if present, ~0 otherwise */
uword vlib_node_get_next (vlib_main_t * vm, uword node, uword next_node);

/* Add next node to given node in given slot. */
uword
vlib_node_add_next_with_slot (vlib_main_t * vm,
			      uword node, uword next_node, uword slot);

/* As above but adds to end of node's next vector. */
always_inline uword
vlib_node_add_next (vlib_main_t * vm, uword node, uword next_node)
{
  return vlib_node_add_next_with_slot (vm, node, next_node, ~0);
}

/* Add next node to given node in given slot. */
uword
vlib_node_add_named_next_with_slot (vlib_main_t * vm,
				    uword node, char *next_name, uword slot);

/* As above but adds to end of node's next vector. */
always_inline uword
vlib_node_add_named_next (vlib_main_t * vm, uword node, char *name)
{
  return vlib_node_add_named_next_with_slot (vm, node, name, ~0);
}

/**
 * Get list of nodes
 */
void
vlib_node_get_nodes (vlib_main_t * vm, u32 max_threads, int include_stats,
		     int barrier_sync, vlib_node_t **** node_dupsp,
		     vlib_main_t *** stat_vmsp);

/* Query node given name. */
vlib_node_t *vlib_get_node_by_name (vlib_main_t * vm, u8 * name);

/* Rename a node. */
void vlib_node_rename (vlib_main_t * vm, u32 node_index, char *fmt, ...);

/* Register new packet processing node.  Nodes can be registered
   dynamically via this call or statically via the VLIB_REGISTER_NODE
   macro. */
u32 vlib_register_node (vlib_main_t * vm, vlib_node_registration_t * r);

/* Register all node function variants */
void vlib_register_all_node_march_variants (vlib_main_t *vm);

/* Register all static nodes registered via VLIB_REGISTER_NODE. */
void vlib_register_all_static_nodes (vlib_main_t * vm);

/* Start a process. */
void vlib_start_process (vlib_main_t * vm, uword process_index);

/* Sync up runtime and main node stats. */
void vlib_node_sync_stats (vlib_main_t * vm, vlib_node_t * n);

/* Node graph initialization function. */
clib_error_t *vlib_node_main_init (vlib_main_t * vm);

format_function_t format_vlib_node_graph;
format_function_t format_vlib_node_name;
format_function_t format_vlib_next_node_name;
format_function_t format_vlib_node_and_next;
format_function_t format_vlib_cpu_time;
format_function_t format_vlib_time;
/* Parse node name -> node index. */
unformat_function_t unformat_vlib_node;

always_inline void
vlib_node_increment_counter (vlib_main_t * vm, u32 node_index,
			     u32 counter_index, u64 increment)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_error_main_t *em = &vm->error_main;
  u32 node_counter_base_index = n->error_heap_index;
  em->counters[node_counter_base_index + counter_index] += increment;
}

/** @brief Create a vlib process
 *  @param vm &vlib_global_main
 *  @param f the process node function
 *  @param log2_n_stack_bytes size of the process stack, defaults to 16K
 *  @return newly-create node index
 *  @warning call only on the main thread. Barrier sync required
 */
u32 vlib_process_create (vlib_main_t * vm, char *name,
			 vlib_node_function_t * f, u32 log2_n_stack_bytes);

<<<<<<< HEAD   (3e0daf misc: 19.08.3 Release Notes)
=======
always_inline int
vlib_node_set_dispatch_wrapper (vlib_main_t *vm, vlib_node_function_t *fn)
{
  if (fn && vm->dispatch_wrapper_fn)
    return 1;
  vm->dispatch_wrapper_fn = fn;
  return 0;
}

int vlib_node_set_march_variant (vlib_main_t *vm, u32 node_index,
				 clib_march_variant_type_t march_variant);

vlib_node_function_t *
vlib_node_get_preferred_node_fn_variant (vlib_main_t *vm,
					 vlib_node_fn_registration_t *regs);

>>>>>>> CHANGE (c9a244 vlib: refactor node function variants)
#endif /* included_vlib_node_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
