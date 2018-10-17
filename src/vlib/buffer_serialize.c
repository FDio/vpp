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
 * buffer.c: allocate/free network buffers.
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

#include <vlib/vlib.h>

static void
vlib_serialize_tx (serialize_main_header_t * m, serialize_stream_t * s)
{
  vlib_main_t *vm;
  vlib_serialize_buffer_main_t *sm;
  uword n, n_bytes_to_write;
  vlib_buffer_t *last;

  n_bytes_to_write = s->current_buffer_index;
  sm =
    uword_to_pointer (s->data_function_opaque,
		      vlib_serialize_buffer_main_t *);
  vm = sm->vlib_main;

  ASSERT (sm->tx.max_n_data_bytes_per_chain > 0);
  if (serialize_stream_is_end_of_stream (s)
      || sm->tx.n_total_data_bytes + n_bytes_to_write >
      sm->tx.max_n_data_bytes_per_chain)
    {
      vlib_process_t *p = vlib_get_current_process (vm);

      last = vlib_get_buffer (vm, sm->last_buffer);
      last->current_length = n_bytes_to_write;

      vlib_set_next_frame_buffer (vm, &p->node_runtime, sm->tx.next_index,
				  sm->first_buffer);

      sm->first_buffer = sm->last_buffer = ~0;
      sm->tx.n_total_data_bytes = 0;
    }

  else if (n_bytes_to_write == 0 && s->n_buffer_bytes == 0)
    {
      ASSERT (sm->first_buffer == ~0);
      ASSERT (sm->last_buffer == ~0);
      n =
	vlib_buffer_alloc_from_free_list (vm, &sm->first_buffer, 1,
					  sm->tx.free_list_index);
      if (n != 1)
	serialize_error (m,
			 clib_error_create
			 ("vlib_buffer_alloc_from_free_list fails"));
      sm->last_buffer = sm->first_buffer;
      s->n_buffer_bytes =
	vlib_buffer_free_list_buffer_size (vm, sm->tx.free_list_index);
    }

  if (n_bytes_to_write > 0)
    {
      vlib_buffer_t *prev = vlib_get_buffer (vm, sm->last_buffer);
      n =
	vlib_buffer_alloc_from_free_list (vm, &sm->last_buffer, 1,
					  sm->tx.free_list_index);
      if (n != 1)
	serialize_error (m,
			 clib_error_create
			 ("vlib_buffer_alloc_from_free_list fails"));
      sm->tx.n_total_data_bytes += n_bytes_to_write;
      prev->current_length = n_bytes_to_write;
      prev->next_buffer = sm->last_buffer;
      prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
    }

  if (sm->last_buffer != ~0)
    {
      last = vlib_get_buffer (vm, sm->last_buffer);
      s->buffer = vlib_buffer_get_current (last);
      s->current_buffer_index = 0;
      ASSERT (last->current_data == s->current_buffer_index);
    }
}

static void
vlib_serialize_rx (serialize_main_header_t * m, serialize_stream_t * s)
{
  vlib_main_t *vm;
  vlib_serialize_buffer_main_t *sm;
  vlib_buffer_t *last;

  sm =
    uword_to_pointer (s->data_function_opaque,
		      vlib_serialize_buffer_main_t *);
  vm = sm->vlib_main;

  if (serialize_stream_is_end_of_stream (s))
    return;

  if (sm->last_buffer != ~0)
    {
      last = vlib_get_buffer (vm, sm->last_buffer);

      if (last->flags & VLIB_BUFFER_NEXT_PRESENT)
	sm->last_buffer = last->next_buffer;
      else
	{
	  vlib_buffer_free (vm, &sm->first_buffer, /* count */ 1);
	  sm->first_buffer = sm->last_buffer = ~0;
	}
    }

  if (sm->last_buffer == ~0)
    {
      while (clib_fifo_elts (sm->rx.buffer_fifo) == 0)
	{
	  sm->rx.ready_one_time_event =
	    vlib_process_create_one_time_event (vm, vlib_current_process (vm),
						~0);
	  vlib_process_wait_for_one_time_event (vm, /* no event data */ 0,
						sm->rx.ready_one_time_event);
	}

      clib_fifo_sub1 (sm->rx.buffer_fifo, sm->first_buffer);
      sm->last_buffer = sm->first_buffer;
    }

  ASSERT (sm->last_buffer != ~0);

  last = vlib_get_buffer (vm, sm->last_buffer);
  s->current_buffer_index = 0;
  s->buffer = vlib_buffer_get_current (last);
  s->n_buffer_bytes = last->current_length;
}

static void
serialize_open_vlib_helper (serialize_main_t * m,
			    vlib_main_t * vm,
			    vlib_serialize_buffer_main_t * sm, uword is_read)
{
  /* Initialize serialize main but save overflow buffer for re-use between calls. */
  {
    u8 *save = m->stream.overflow_buffer;
    clib_memset (m, 0, sizeof (m[0]));
    m->stream.overflow_buffer = save;
    if (save)
      _vec_len (save) = 0;
  }

  sm->first_buffer = sm->last_buffer = ~0;
  if (is_read)
    clib_fifo_reset (sm->rx.buffer_fifo);
  else
    sm->tx.n_total_data_bytes = 0;
  sm->vlib_main = vm;
  m->header.data_function = is_read ? vlib_serialize_rx : vlib_serialize_tx;
  m->stream.data_function_opaque = pointer_to_uword (sm);
}

void
serialize_open_vlib_buffer (serialize_main_t * m, vlib_main_t * vm,
			    vlib_serialize_buffer_main_t * sm)
{
  serialize_open_vlib_helper (m, vm, sm, /* is_read */ 0);
}

void
unserialize_open_vlib_buffer (serialize_main_t * m, vlib_main_t * vm,
			      vlib_serialize_buffer_main_t * sm)
{
  serialize_open_vlib_helper (m, vm, sm, /* is_read */ 1);
}

u32
serialize_close_vlib_buffer (serialize_main_t * m)
{
  vlib_serialize_buffer_main_t *sm
    = uword_to_pointer (m->stream.data_function_opaque,
			vlib_serialize_buffer_main_t *);
  vlib_buffer_t *last;
  serialize_stream_t *s = &m->stream;

  last = vlib_get_buffer (sm->vlib_main, sm->last_buffer);
  last->current_length = s->current_buffer_index;

  if (vec_len (s->overflow_buffer) > 0)
    {
      sm->last_buffer
	= vlib_buffer_add_data (sm->vlib_main, sm->tx.free_list_index,
				sm->last_buffer,
				s->overflow_buffer,
				vec_len (s->overflow_buffer));
      _vec_len (s->overflow_buffer) = 0;
    }

  return sm->first_buffer;
}

void
unserialize_close_vlib_buffer (serialize_main_t * m)
{
  vlib_serialize_buffer_main_t *sm
    = uword_to_pointer (m->stream.data_function_opaque,
			vlib_serialize_buffer_main_t *);
  if (sm->first_buffer != ~0)
    vlib_buffer_free_one (sm->vlib_main, sm->first_buffer);
  clib_fifo_reset (sm->rx.buffer_fifo);
  if (m->stream.overflow_buffer)
    _vec_len (m->stream.overflow_buffer) = 0;
}

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
