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
/*
 * ioam_export_thread.c
 */
#include <vnet/api_errno.h>
#include <vppinfra/pool.h>
#include "ioam_export.h"

static vlib_node_registration_t ioam_export_process_node;
#define EXPORT_TIMEOUT (20.0)
#define THREAD_PERIOD (30.0)

static uword
ioam_export_process (vlib_main_t * vm,
		     vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  ioam_export_main_t *em = &ioam_export_main;
  f64 now;
  f64 timeout = 30.0;
  uword event_type;
  uword *event_data = 0;
  int i;
  ioam_export_buffer_t *eb = 0, *new_eb = 0;
  u32 *vec_buffer_indices = 0;
  u32 *vec_buffer_to_be_sent = 0;
  u32 *thread_index = 0;
  u32 new_pool_index = 0;

  em->export_process_node_index = ioam_export_process_node.index;
  /* Wait for Godot... */
  vlib_process_wait_for_event_or_clock (vm, 1e9);
  event_type = vlib_process_get_events (vm, &event_data);
  if (event_type != 1)
    clib_warning ("bogus kickoff event received, %d", event_type);
  vec_reset_length (event_data);

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case 2:		/* Stop and Wait for kickoff again */
	  timeout = 1e9;
	  break;
	case 1:		/* kickoff : Check for unsent buffers */
	  timeout = THREAD_PERIOD;
	  break;
	case ~0:		/* timeout */
	  break;
	}
      vec_reset_length (event_data);
      now = vlib_time_now (vm);
      /*
       * Create buffers for threads that are not active enough
       * to send out the export records
       */
      for (i = 0; i < vec_len (em->buffer_per_thread); i++)
	{
	  /* If the worker thread is processing export records ignore further checks */
	  if (*em->lockp[i] == 1)
	    continue;
	  eb = pool_elt_at_index (em->buffer_pool, em->buffer_per_thread[i]);
	  if (eb->records_in_this_buffer > 0 && now > (eb->touched_at + EXPORT_TIMEOUT))
	    {
	      pool_get_aligned (em->buffer_pool, new_eb,
				CLIB_CACHE_LINE_BYTES);
	      memset (new_eb, 0, sizeof (*new_eb));
	      if (ioam_export_init_buffer (vm, new_eb) == 1)
		{
		  new_pool_index = new_eb - em->buffer_pool;
		  vec_add (vec_buffer_indices, &new_pool_index, 1);
		  vec_add (vec_buffer_to_be_sent, &em->buffer_per_thread[i],
			   1);
		  vec_add (thread_index, &i, 1);
		}
	      else
		{
		  pool_put (em->buffer_pool, new_eb);
		  /*Give up */
		  goto CLEANUP;
		}
	    }
	}
      if (vec_len (thread_index) != 0)
	{
	  /*
	   * Now swap the buffers out
	   */
	  for (i = 0; i < vec_len (thread_index); i++)
	    {
	      while (__sync_lock_test_and_set (em->lockp[thread_index[i]], 1))
		;
	      em->buffer_per_thread[thread_index[i]] =
		vec_pop (vec_buffer_indices);
	      *em->lockp[thread_index[i]] = 0;
	    }

	  /* Send the buffers */
	  for (i = 0; i < vec_len (vec_buffer_to_be_sent); i++)
	    {
	      eb =
		pool_elt_at_index (em->buffer_pool, vec_buffer_to_be_sent[i]);
	      ioam_export_send_buffer (vm, eb);
	      pool_put (em->buffer_pool, eb);
	    }
	}

    CLEANUP:
      /* Free any leftover/unused buffers and everything that was allocated */
      for (i = 0; i < vec_len (vec_buffer_indices); i++)
	{
	  new_eb = pool_elt_at_index (em->buffer_pool, vec_buffer_indices[i]);
	  vlib_buffer_free (vm, &new_eb->buffer_index, 1);
	  pool_put (em->buffer_pool, new_eb);
	}
      vec_free (vec_buffer_indices);
      vec_free (vec_buffer_to_be_sent);
      vec_free (thread_index);
    }
  return 0;			/* not so much */
}

VLIB_REGISTER_NODE (ioam_export_process_node, static) =
{
 .function = ioam_export_process,
 .type = VLIB_NODE_TYPE_PROCESS,
 .name = "ioam-export-process",
};
