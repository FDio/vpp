/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/session/segment_manager.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>

/**
 * Counter used to build segment names
 */
u32 segment_name_counter = 0;

/**
 * Pool of segment managers
 */
segment_manager_t *segment_managers = 0;

/**
 * Process private segment index
 */
u32 *private_segment_indices;

/**
 * Default fifo and segment size. TODO config.
 */
u32 default_fifo_size = 1 << 16;
u32 default_segment_size = 1 << 20;

void
segment_manager_get_segment_info (u32 index, u8 ** name, u32 * size)
{
  svm_fifo_segment_private_t *s;
  s = svm_fifo_segment_get_segment (index);
  *name = s->h->segment_name;
  *size = s->ssvm.ssvm_size;
}

always_inline int
session_manager_add_segment_i (segment_manager_t * sm, u32 segment_size,
			       u8 * segment_name)
{
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  int rv;

  memset (ca, 0, sizeof (*ca));

  if (!sm->properties->use_private_segment)
    {
      ca->segment_name = (char *) segment_name;
      ca->segment_size = segment_size;
      ca->rx_fifo_size = sm->properties->rx_fifo_size;
      ca->tx_fifo_size = sm->properties->tx_fifo_size;
      ca->preallocated_fifo_pairs = sm->properties->preallocated_fifo_pairs;

      rv = svm_fifo_segment_create (ca);
      if (rv)
	{
	  clib_warning ("svm_fifo_segment_create ('%s', %d) failed",
			ca->segment_name, ca->segment_size);
	  return VNET_API_ERROR_SVM_SEGMENT_CREATE_FAIL;
	}
    }
  else
    {
      u32 rx_fifo_size, tx_fifo_size, rx_rounded_data_size,
	tx_rounded_data_size;
      u32 approx_segment_count;
      u64 approx_total_size;

      ca->segment_name = "process-private-segment";
      ca->segment_size = ~0;
      ca->rx_fifo_size = sm->properties->rx_fifo_size;
      ca->tx_fifo_size = sm->properties->tx_fifo_size;
      ca->preallocated_fifo_pairs = sm->properties->preallocated_fifo_pairs;
      ca->private_segment_count = sm->properties->private_segment_count;
      ca->private_segment_size = sm->properties->private_segment_size;

      /* Default to a small private segment */
      if (ca->private_segment_size == 0)
	ca->private_segment_size = 128 << 20;

      /* Calculate space requirements */
      rx_rounded_data_size = (1 << (max_log2 (ca->rx_fifo_size)));
      tx_rounded_data_size = (1 << (max_log2 (ca->tx_fifo_size)));

      rx_fifo_size = sizeof (svm_fifo_t) + rx_rounded_data_size;
      tx_fifo_size = sizeof (svm_fifo_t) + tx_rounded_data_size;

      approx_total_size = (u64) ca->preallocated_fifo_pairs
	* (rx_fifo_size + tx_fifo_size);
      approx_segment_count =
	(approx_total_size +
	 (ca->private_segment_size - 1)) / (u64) ca->private_segment_size;

      /* The user asked us to figure it out... */
      if (ca->private_segment_count == 0)
	{
	  ca->private_segment_count = approx_segment_count;
	}
      /* Follow directions, but issue a warning */
      else if (approx_segment_count != ca->private_segment_count)
	{
	  clib_warning
	    ("Honoring segment count %u, but calculated count was %u",
	     ca->private_segment_count, approx_segment_count);
	}

      if (svm_fifo_segment_create_process_private (ca))
	clib_warning ("Failed to create process private segment");

      ASSERT (vec_len (ca->new_segment_indices));
    }
  vec_append (sm->segment_indices, ca->new_segment_indices);
  vec_free (ca->new_segment_indices);
  return 0;
}

int
session_manager_add_segment (segment_manager_t * sm)
{
  u8 *segment_name;
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  u32 add_segment_size;
  int rv;

  memset (ca, 0, sizeof (*ca));
  segment_name = format (0, "%d-%d%c", getpid (), segment_name_counter++, 0);
  add_segment_size = sm->properties->add_segment_size ?
    sm->properties->add_segment_size : default_segment_size;

  rv = session_manager_add_segment_i (sm, add_segment_size, segment_name);
  vec_free (segment_name);
  return rv;
}

int
session_manager_add_first_segment (segment_manager_t * sm, u32 segment_size)
{
  u8 *segment_name;
  int rv;

  segment_name = format (0, "%d-%d%c", getpid (), segment_name_counter++, 0);
  rv = session_manager_add_segment_i (sm, segment_size, segment_name);
  vec_free (segment_name);
  return rv;
}

segment_manager_t *
segment_manager_new ()
{
  segment_manager_t *sm;
  pool_get (segment_managers, sm);
  memset (sm, 0, sizeof (*sm));
  return sm;
}

/**
 * Initializes segment manager based on options provided.
 * Returns error if svm segment allocation fails.
 */
int
segment_manager_init (segment_manager_t * sm,
		      segment_manager_properties_t * properties,
		      u32 first_seg_size)
{
  int rv;

  /* app allocates these */
  sm->properties = properties;

  first_seg_size = first_seg_size > 0 ? first_seg_size : default_segment_size;

  rv = session_manager_add_first_segment (sm, first_seg_size);
  if (rv)
    {
      clib_warning ("Failed to allocate segment");
      return rv;
    }

  clib_spinlock_init (&sm->lockp);
  return 0;
}

u8
segment_manager_has_fifos (segment_manager_t * sm)
{
  svm_fifo_segment_private_t *segment;
  int i;

  for (i = 0; i < vec_len (sm->segment_indices); i++)
    {
      segment = svm_fifo_segment_get_segment (sm->segment_indices[i]);
      if (CLIB_DEBUG && i && !svm_fifo_segment_has_fifos (segment)
	  && !(segment->h->flags & FIFO_SEGMENT_F_IS_PREALLOCATED))
	clib_warning ("segment %d has no fifos!", sm->segment_indices[i]);
      if (svm_fifo_segment_has_fifos (segment))
	return 1;
    }
  return 0;
}

static u8
segment_manager_app_detached (segment_manager_t * sm)
{
  return (sm->app_index == SEGMENT_MANAGER_INVALID_APP_INDEX);
}

static void
segment_manager_del_segment (segment_manager_t * sm, u32 segment_index)
{
  svm_fifo_segment_private_t *fifo_segment;
  u32 svm_segment_index;
  clib_spinlock_lock (&sm->lockp);
  svm_segment_index = sm->segment_indices[segment_index];
  fifo_segment = svm_fifo_segment_get_segment (svm_segment_index);
  if (!fifo_segment
      || ((fifo_segment->h->flags & FIFO_SEGMENT_F_IS_PREALLOCATED)
	  && !segment_manager_app_detached (sm)))
    {
      clib_spinlock_unlock (&sm->lockp);
      return;
    }
  svm_fifo_segment_delete (fifo_segment);
  vec_del1 (sm->segment_indices, segment_index);
  clib_spinlock_unlock (&sm->lockp);
}

/**
 * Initiate disconnects for all sessions 'owned' by a segment manager
 */
void
segment_manager_del_sessions (segment_manager_t * sm)
{
  int j;
  svm_fifo_segment_private_t *fifo_segment;
  svm_fifo_t *fifo;

  ASSERT (vec_len (sm->segment_indices));

  /* Across all fifo segments used by the server */
  for (j = 0; j < vec_len (sm->segment_indices); j++)
    {
      fifo_segment = svm_fifo_segment_get_segment (sm->segment_indices[j]);
      fifo = svm_fifo_segment_get_fifo_list (fifo_segment);

      /*
       * Remove any residual sessions from the session lookup table
       * Don't bother deleting the individual fifos, we're going to
       * throw away the fifo segment in a minute.
       */
      while (fifo)
	{
	  u32 session_index, thread_index;
	  stream_session_t *session;

	  session_index = fifo->master_session_index;
	  thread_index = fifo->master_thread_index;
	  session = stream_session_get (session_index, thread_index);

	  /* Instead of directly removing the session call disconnect */
	  if (session->session_state != SESSION_STATE_CLOSED)
	    {
	      session->session_state = SESSION_STATE_CLOSED;
	      session_send_session_evt_to_thread (stream_session_handle
						  (session),
						  FIFO_EVENT_DISCONNECT,
						  thread_index);
	    }
	  fifo = fifo->next;
	}

      /* Instead of removing the segment, test when cleaning up disconnected
       * sessions if the segment can be removed.
       */
    }
}

/**
 * Removes segment manager.
 *
 * Since the fifos allocated in the segment keep backpointers to the sessions
 * prior to removing the segment, we call session disconnect. This
 * subsequently propagates into transport.
 */
void
segment_manager_del (segment_manager_t * sm)
{
  int i;

  ASSERT (!segment_manager_has_fifos (sm)
	  && segment_manager_app_detached (sm));

  /* If we have empty preallocated segments that haven't been removed, remove
   * them now. Apart from that, the first segment in the first segment manager
   * is not removed when all fifos are removed. It can only be removed when
   * the manager is explicitly deleted/detached by the app. */
  for (i = vec_len (sm->segment_indices) - 1; i >= 0; i--)
    {
      if (CLIB_DEBUG)
	{
	  svm_fifo_segment_private_t *segment;
	  segment = svm_fifo_segment_get_segment (sm->segment_indices[i]);
	  ASSERT (!svm_fifo_segment_has_fifos (segment));
	}
      segment_manager_del_segment (sm, i);
    }
  clib_spinlock_free (&sm->lockp);
  if (CLIB_DEBUG)
    memset (sm, 0xfe, sizeof (*sm));
  pool_put (segment_managers, sm);
}

void
segment_manager_init_del (segment_manager_t * sm)
{
  if (segment_manager_has_fifos (sm))
    segment_manager_del_sessions (sm);
  else
    {
      ASSERT (!sm->first_is_protected || segment_manager_app_detached (sm));
      segment_manager_del (sm);
    }
}

int
segment_manager_alloc_session_fifos (segment_manager_t * sm,
				     svm_fifo_t ** server_rx_fifo,
				     svm_fifo_t ** server_tx_fifo,
				     u32 * fifo_segment_index)
{
  svm_fifo_segment_private_t *fifo_segment;
  u32 fifo_size, sm_index;
  u8 added_a_segment = 0;
  int i;

  ASSERT (vec_len (sm->segment_indices));

  /* Make sure we don't have multiple threads trying to allocate segments
   * at the same time. */
  clib_spinlock_lock (&sm->lockp);

  /* Allocate svm fifos */
again:
  for (i = 0; i < vec_len (sm->segment_indices); i++)
    {
      *fifo_segment_index = sm->segment_indices[i];
      fifo_segment = svm_fifo_segment_get_segment (*fifo_segment_index);

      fifo_size = sm->properties->rx_fifo_size;
      fifo_size = (fifo_size == 0) ? default_fifo_size : fifo_size;
      *server_rx_fifo =
	svm_fifo_segment_alloc_fifo (fifo_segment, fifo_size,
				     FIFO_SEGMENT_RX_FREELIST);

      fifo_size = sm->properties->tx_fifo_size;
      fifo_size = (fifo_size == 0) ? default_fifo_size : fifo_size;
      *server_tx_fifo =
	svm_fifo_segment_alloc_fifo (fifo_segment, fifo_size,
				     FIFO_SEGMENT_TX_FREELIST);

      if (*server_rx_fifo == 0)
	{
	  /* This would be very odd, but handle it... */
	  if (*server_tx_fifo != 0)
	    {
	      svm_fifo_segment_free_fifo (fifo_segment, *server_tx_fifo,
					  FIFO_SEGMENT_TX_FREELIST);
	      *server_tx_fifo = 0;
	    }
	  continue;
	}
      if (*server_tx_fifo == 0)
	{
	  if (*server_rx_fifo != 0)
	    {
	      svm_fifo_segment_free_fifo (fifo_segment, *server_rx_fifo,
					  FIFO_SEGMENT_RX_FREELIST);
	      *server_rx_fifo = 0;
	    }
	  continue;
	}
      break;
    }

  /* See if we're supposed to create another segment */
  if (*server_rx_fifo == 0)
    {
      if (sm->properties->add_segment && !sm->properties->use_private_segment)
	{
	  if (added_a_segment)
	    {
	      clib_warning ("added a segment, still can't allocate a fifo");
	      clib_spinlock_unlock (&sm->lockp);
	      return SESSION_ERROR_NEW_SEG_NO_SPACE;
	    }

	  if (session_manager_add_segment (sm))
	    {
	      clib_spinlock_unlock (&sm->lockp);
	      return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
	    }

	  added_a_segment = 1;
	  goto again;
	}
      else
	{
	  clib_warning ("No space to allocate fifos!");
	  clib_spinlock_unlock (&sm->lockp);
	  return SESSION_ERROR_NO_SPACE;
	}
    }

  /* Backpointers to segment manager */
  sm_index = segment_manager_index (sm);
  (*server_tx_fifo)->segment_manager = sm_index;
  (*server_rx_fifo)->segment_manager = sm_index;

  clib_spinlock_unlock (&sm->lockp);

  if (added_a_segment)
    return application_add_segment_notify (sm->app_index,
					   *fifo_segment_index);

  return 0;
}

void
segment_manager_dealloc_fifos (u32 svm_segment_index, svm_fifo_t * rx_fifo,
			       svm_fifo_t * tx_fifo)
{
  segment_manager_t *sm;
  svm_fifo_segment_private_t *fifo_segment;
  u32 i, segment_index = ~0;
  u8 is_first;

  sm = segment_manager_get_if_valid (rx_fifo->segment_manager);

  /* It's possible to have no segment manager if the session was removed
   * as result of a detach. */
  if (!sm)
    return;

  fifo_segment = svm_fifo_segment_get_segment (svm_segment_index);
  svm_fifo_segment_free_fifo (fifo_segment, rx_fifo,
			      FIFO_SEGMENT_RX_FREELIST);
  svm_fifo_segment_free_fifo (fifo_segment, tx_fifo,
			      FIFO_SEGMENT_TX_FREELIST);

  /*
   * Try to remove svm segment if it has no fifos. This can be done only if
   * the segment is not the first in the segment manager or if it is first
   * and it is not protected. Moreover, if the segment is first and the app
   * has detached from the segment manager, remove the segment manager.
   */
  if (!svm_fifo_segment_has_fifos (fifo_segment))
    {
      is_first = sm->segment_indices[0] == svm_segment_index;

      /* Remove segment if it holds no fifos or first but not protected */
      if (!is_first || !sm->first_is_protected)
	{
	  /* Find the segment manager segment index */
	  for (i = 0; i < vec_len (sm->segment_indices); i++)
	    if (sm->segment_indices[i] == svm_segment_index)
	      {
		segment_index = i;
		break;
	      }
	  ASSERT (segment_index != (u32) ~ 0);
	  segment_manager_del_segment (sm, segment_index);
	}

      /* Remove segment manager if no sessions and detached from app */
      if (segment_manager_app_detached (sm)
	  && !segment_manager_has_fifos (sm))
	segment_manager_del (sm);
    }
}

/**
 * Allocates shm queue in the first segment
 */
unix_shared_memory_queue_t *
segment_manager_alloc_queue (segment_manager_t * sm, u32 queue_size)
{
  ssvm_shared_header_t *sh;
  svm_fifo_segment_private_t *segment;
  unix_shared_memory_queue_t *q;
  void *oldheap;

  ASSERT (sm->segment_indices != 0);

  segment = svm_fifo_segment_get_segment (sm->segment_indices[0]);
  sh = segment->ssvm.sh;

  oldheap = ssvm_push_heap (sh);
  q = unix_shared_memory_queue_init (queue_size,
				     sizeof (session_fifo_event_t),
				     0 /* consumer pid */ ,
				     0 /* signal when queue non-empty */ );
  ssvm_pop_heap (oldheap);
  return q;
}

/**
 * Frees shm queue allocated in the first segment
 */
void
segment_manager_dealloc_queue (segment_manager_t * sm,
			       unix_shared_memory_queue_t * q)
{
  ssvm_shared_header_t *sh;
  svm_fifo_segment_private_t *segment;
  void *oldheap;

  ASSERT (sm->segment_indices != 0);

  segment = svm_fifo_segment_get_segment (sm->segment_indices[0]);
  sh = segment->ssvm.sh;

  oldheap = ssvm_push_heap (sh);
  unix_shared_memory_queue_free (q);
  ssvm_pop_heap (oldheap);
}

static clib_error_t *
segment_manager_show_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  svm_fifo_segment_private_t *segments, *seg;
  segment_manager_t *sm;
  u8 show_segments = 0, verbose = 0, *name;
  uword address;
  u64 size;
  u32 active_fifos;
  u32 free_fifos;

  mheap_t *heap_header;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "segments"))
	show_segments = 1;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  vlib_cli_output (vm, "%d segment managers allocated",
		   pool_elts (segment_managers));
  if (verbose && pool_elts (segment_managers))
    {
      vlib_cli_output (vm, "%-10s%=15s%=12s", "Index", "App Index",
		       "Segments");

      /* *INDENT-OFF* */
      pool_foreach (sm, segment_managers, ({
	vlib_cli_output (vm, "%-10d%=15d%=12d", segment_manager_index(sm),
			   sm->app_index, vec_len (sm->segment_indices));
      }));
      /* *INDENT-ON* */

    }
  if (show_segments)
    {
      segments = svm_fifo_segment_segments_pool ();
      vlib_cli_output (vm, "%d svm fifo segments allocated",
		       pool_elts (segments));
      vlib_cli_output (vm, "%-20s%=12s%=16s%=16s%=16s", "Name",
		       "HeapSize (M)", "ActiveFifos", "FreeFifos", "Address");

      /* *INDENT-OFF* */
      pool_foreach (seg, segments, ({
	if (seg->h->flags & FIFO_SEGMENT_F_IS_PRIVATE)
	  {
	    address = pointer_to_uword (seg->ssvm.sh->heap);
	    if (seg->h->flags & FIFO_SEGMENT_F_IS_MAIN_HEAP)
	      name = format (0, "main heap");
	    else
	      name = format (0, "private heap");
	    heap_header = mheap_header (seg->ssvm.sh->heap);
	    size = heap_header->max_size;
	  }
	else
	  {
	    address =  seg->ssvm.sh->ssvm_va;
	    size = seg->ssvm.ssvm_size;
	    name = seg->ssvm.sh->name;
	  }
	active_fifos = svm_fifo_segment_num_fifos (seg);
        free_fifos = svm_fifo_segment_num_free_fifos (seg, ~0 /* size */);
	vlib_cli_output (vm, "%-20v%=16llu%=16u%=16u%16llx",
                         name, size >> 20ULL, active_fifos, free_fifos,
			 address);
        if (verbose)
          vlib_cli_output (vm, "%U",
                           format_svm_fifo_segment, seg, verbose);
	if (seg->h->flags & FIFO_SEGMENT_F_IS_PRIVATE)
	  vec_free (name);
      }));
      /* *INDENT-ON* */

    }
  return 0;
}

		          /* *INDENT-OFF* */
VLIB_CLI_COMMAND (segment_manager_show_command, static) =
{
  .path = "show segment-manager",
  .short_help = "show segment-manager [segments][verbose]",
  .function = segment_manager_show_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
