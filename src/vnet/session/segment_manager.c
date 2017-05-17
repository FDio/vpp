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
u32 private_segment_index = ~0;

/**
 * Default fifo and segment size. TODO config.
 */
u32 default_fifo_size = 1 << 16;
u32 default_segment_size = 1 << 20;

void
segment_manager_get_segment_info (u32 index, u8 ** name, u32 * size)
{
  svm_fifo_segment_private_t *s;
  s = svm_fifo_get_segment (index);
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

  ca->segment_name = (char *) segment_name;
  ca->segment_size = segment_size;

  rv = svm_fifo_segment_create (ca);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_create ('%s', %d) failed",
		    ca->segment_name, ca->segment_size);
      vec_free (segment_name);
      return VNET_API_ERROR_SVM_SEGMENT_CREATE_FAIL;
    }

  vec_add1 (sm->segment_indices, ca->new_segment_index);

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

static void
segment_manager_alloc_process_private_segment ()
{
  svm_fifo_segment_create_args_t _a, *a = &_a;

  if (private_segment_index != ~0)
    return;

  memset (a, 0, sizeof (*a));
  a->segment_name = "process-private-segment";
  a->segment_size = ~0;
  a->new_segment_index = ~0;

  if (svm_fifo_segment_create_process_private (a))
    clib_warning ("Failed to create process private segment");

  private_segment_index = a->new_segment_index;
  ASSERT (private_segment_index != ~0);
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

  if (sm->properties->use_private_segment == 0)
    {
      rv = session_manager_add_first_segment (sm, first_seg_size);
      if (rv)
	{
	  clib_warning ("Failed to allocate segment");
	  return rv;
	}
    }
  else
    {
      if (private_segment_index == ~0)
	segment_manager_alloc_process_private_segment ();
      ASSERT (private_segment_index != ~0);
      vec_add1 (sm->segment_indices, private_segment_index);
    }

  clib_spinlock_init (&sm->lockp);
  return 0;
}

/**
 * Removes segment manager.
 *
 * Since the fifos allocated in the segment keep backpointers to the sessions
 * prior to removing the segment, we call session disconnect. This
 * subsequently propages into transport.
 */
void
segment_manager_del (segment_manager_t * sm)
{
  u32 *deleted_sessions = 0;
  u32 *deleted_thread_indices = 0;
  int i, j;

  /* Across all fifo segments used by the server */
  for (j = 0; j < vec_len (sm->segment_indices); j++)
    {
      svm_fifo_segment_private_t *fifo_segment;
      svm_fifo_t **fifos;
      /* Vector of fifos allocated in the segment */
      fifo_segment = svm_fifo_get_segment (sm->segment_indices[j]);
      fifos = svm_fifo_segment_get_fifos (fifo_segment);

      /*
       * Remove any residual sessions from the session lookup table
       * Don't bother deleting the individual fifos, we're going to
       * throw away the fifo segment in a minute.
       */
      for (i = 0; i < vec_len (fifos); i++)
	{
	  svm_fifo_t *fifo;
	  u32 session_index, thread_index;
	  stream_session_t *session;

	  fifo = fifos[i];
	  session_index = fifo->master_session_index;
	  thread_index = fifo->master_thread_index;

	  session = stream_session_get (session_index, thread_index);

	  /* Add to the deleted_sessions vector (once!) */
	  if (!session->is_deleted)
	    {
	      session->is_deleted = 1;
	      vec_add1 (deleted_sessions, session_index);
	      vec_add1 (deleted_thread_indices, thread_index);
	    }
	}

      for (i = 0; i < vec_len (deleted_sessions); i++)
	{
	  stream_session_t *session;
	  session = stream_session_get (deleted_sessions[i],
					deleted_thread_indices[i]);

	  /* Instead of directly removing the session call disconnect */
	  session_send_session_evt_to_thread (stream_session_handle (session),
					      FIFO_EVENT_DISCONNECT,
					      deleted_thread_indices[i]);

	  /*
	     stream_session_table_del (smm, session);
	     pool_put(smm->sessions[deleted_thread_indices[i]], session);
	   */
	}

      vec_reset_length (deleted_sessions);
      vec_reset_length (deleted_thread_indices);

      /* Instead of removing the segment, test when removing the session if
       * the segment can be removed
       */
      /* svm_fifo_segment_delete (fifo_segment); */
    }

  clib_spinlock_free (&sm->lockp);
  vec_free (deleted_sessions);
  vec_free (deleted_thread_indices);
  pool_put (segment_managers, sm);
}

static int
segment_manager_notify_app_seg_add (segment_manager_t * sm,
				    u32 fifo_segment_index)
{
  application_t *app = application_get (sm->app_index);
  u32 seg_size = 0;
  u8 *seg_name;

  /* Send an API message to the external app, to map new segment */
  ASSERT (app->cb_fns.add_segment_callback);

  segment_manager_get_segment_info (fifo_segment_index, &seg_name, &seg_size);
  return app->cb_fns.add_segment_callback (app->api_client_index, seg_name,
					   seg_size);
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
      fifo_segment = svm_fifo_get_segment (*fifo_segment_index);

      fifo_size = sm->properties->rx_fifo_size;
      fifo_size = (fifo_size == 0) ? default_fifo_size : fifo_size;
      *server_rx_fifo = svm_fifo_segment_alloc_fifo (fifo_segment, fifo_size);

      fifo_size = sm->properties->tx_fifo_size;
      fifo_size = (fifo_size == 0) ? default_fifo_size : fifo_size;
      *server_tx_fifo = svm_fifo_segment_alloc_fifo (fifo_segment, fifo_size);

      if (*server_rx_fifo == 0)
	{
	  /* This would be very odd, but handle it... */
	  if (*server_tx_fifo != 0)
	    {
	      svm_fifo_segment_free_fifo (fifo_segment, *server_tx_fifo);
	      *server_tx_fifo = 0;
	    }
	  continue;
	}
      if (*server_tx_fifo == 0)
	{
	  if (*server_rx_fifo != 0)
	    {
	      svm_fifo_segment_free_fifo (fifo_segment, *server_rx_fifo);
	      *server_rx_fifo = 0;
	    }
	  continue;
	}
      break;
    }

  /* See if we're supposed to create another segment */
  if (*server_rx_fifo == 0)
    {
      if (sm->properties->add_segment)
	{
	  if (added_a_segment)
	    {
	      clib_warning ("added a segment, still cant allocate a fifo");
	      return SESSION_ERROR_NEW_SEG_NO_SPACE;
	    }

	  if (session_manager_add_segment (sm))
	    {
	      return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
	    }

	  added_a_segment = 1;
	  goto again;
	}
      else
	{
	  clib_warning ("No space to allocate fifos!");
	  return SESSION_ERROR_NO_SPACE;
	}
    }

  /* Backpointers to segment manager */
  sm_index = segment_manager_index (sm);
  (*server_tx_fifo)->segment_manager = sm_index;
  (*server_rx_fifo)->segment_manager = sm_index;

  clib_spinlock_unlock (&sm->lockp);

  if (added_a_segment)
    return segment_manager_notify_app_seg_add (sm, *fifo_segment_index);

  return 0;
}

void
segment_manager_dealloc_fifos (u32 svm_segment_index, svm_fifo_t * rx_fifo,
			       svm_fifo_t * tx_fifo)
{
  segment_manager_t *sm;
  svm_fifo_segment_private_t *fifo_segment;

  sm = segment_manager_get_if_valid (rx_fifo->segment_manager);

  /* It's possible to have no segment manager if the session was removed
   * as result of a detach */
  if (!sm)
    return;

  fifo_segment = svm_fifo_get_segment (svm_segment_index);
  svm_fifo_segment_free_fifo (fifo_segment, rx_fifo);
  svm_fifo_segment_free_fifo (fifo_segment, tx_fifo);

  /* Remove segment only if it holds no fifos and not the first */
  if (sm->segment_indices[0] != svm_segment_index
      && !svm_fifo_segment_has_fifos (fifo_segment))
    {
      svm_fifo_segment_delete (fifo_segment);
      vec_del1 (sm->segment_indices, svm_segment_index);
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

  segment = svm_fifo_get_segment (sm->segment_indices[0]);
  sh = segment->ssvm.sh;

  oldheap = ssvm_push_heap (sh);
  q =
    unix_shared_memory_queue_init (queue_size, sizeof (session_fifo_event_t),
				   0 /* consumer pid */ , 0
				   /* signal when queue non-empty */ );
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

  segment = svm_fifo_get_segment (sm->segment_indices[0]);
  sh = segment->ssvm.sh;

  oldheap = ssvm_push_heap (sh);
  unix_shared_memory_queue_free (q);
  ssvm_pop_heap (oldheap);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
