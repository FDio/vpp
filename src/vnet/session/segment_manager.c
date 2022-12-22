/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

typedef struct segment_manager_main_
{
  segment_manager_t *segment_managers;	/**< Pool of segment managers */
  u32 seg_name_counter;			/**< Counter for segment names */

  /*
   * Configuration
   */
  u32 default_fifo_size;	/**< default rx/tx fifo size */
  u32 default_segment_size;	/**< default fifo segment size */
  u32 default_app_mq_size;	/**< default app msg q size */
  u32 default_max_fifo_size;	/**< default max fifo size */
  u8 default_high_watermark;	/**< default high watermark % */
  u8 default_low_watermark;	/**< default low watermark % */
} segment_manager_main_t;

static segment_manager_main_t sm_main;

#define segment_manager_foreach_segment_w_lock(VAR, SM, BODY)		\
do {									\
    clib_rwlock_reader_lock (&(SM)->segments_rwlock);			\
    pool_foreach((VAR), ((SM)->segments)) (BODY);			\
    clib_rwlock_reader_unlock (&(SM)->segments_rwlock);			\
} while (0)

static segment_manager_props_t *
segment_manager_properties_get (segment_manager_t * sm)
{
  app_worker_t *app_wrk = app_worker_get (sm->app_wrk_index);
  return application_get_segment_manager_properties (app_wrk->app_index);
}

segment_manager_props_t *
segment_manager_props_init (segment_manager_props_t * props)
{
  props->add_segment_size = sm_main.default_segment_size;
  props->rx_fifo_size = sm_main.default_fifo_size;
  props->tx_fifo_size = sm_main.default_fifo_size;
  props->evt_q_size = sm_main.default_app_mq_size;
  props->max_fifo_size = sm_main.default_max_fifo_size;
  props->high_watermark = sm_main.default_high_watermark;
  props->low_watermark = sm_main.default_low_watermark;
  props->n_slices = vlib_num_workers () + 1;
  return props;
}

u8
segment_manager_app_detached (segment_manager_t * sm)
{
  return (sm->flags & SEG_MANAGER_F_DETACHED);
}

void
segment_manager_app_detach (segment_manager_t * sm)
{
  sm->flags |= SEG_MANAGER_F_DETACHED;
}

always_inline u32
segment_manager_segment_index (segment_manager_t * sm, fifo_segment_t * seg)
{
  return (seg - sm->segments);
}

/**
 * Adds segment to segment manager's pool
 *
 * If needed a writer's lock is acquired before allocating a new segment
 * to avoid affecting any of the segments pool readers.
 */
static inline int
segment_manager_add_segment_inline (segment_manager_t *sm, uword segment_size,
				    u8 notify_app, u8 flags, u8 need_lock)
{
  segment_manager_main_t *smm = &sm_main;
  segment_manager_props_t *props;
  app_worker_t *app_wrk;
  fifo_segment_t *fs;
  u32 fs_index = ~0;
  u8 *seg_name;
  int rv;

  props = segment_manager_properties_get (sm);
  app_wrk = app_worker_get (sm->app_wrk_index);

  /* Not configured for addition of new segments and not first */
  if (!props->add_segment && !segment_size)
    {
      SESSION_DBG ("cannot allocate new segment");
      return SESSION_E_INVALID;
    }

  /*
   * Allocate fifo segment and grab lock if needed
   */
  if (need_lock)
    clib_rwlock_writer_lock (&sm->segments_rwlock);

  pool_get_zero (sm->segments, fs);

  /*
   * Allocate ssvm segment
   */
  segment_size = segment_size ? segment_size : props->add_segment_size;
  /* add overhead to ensure the result segment size is at least
   * of that requested */
  segment_size +=
    sizeof (fifo_segment_header_t) +
    vlib_thread_main.n_vlib_mains * sizeof (fifo_segment_slice_t) +
    FIFO_SEGMENT_ALLOC_OVERHEAD;

  if (props->huge_page)
    {
      uword hugepage_size = clib_mem_get_default_hugepage_size ();
      segment_size = round_pow2 (segment_size, hugepage_size);
      fs->ssvm.huge_page = 1;
    }
  else
    segment_size = round_pow2 (segment_size, clib_mem_get_page_size ());

  seg_name = format (0, "seg-%u-%u-%u%c", app_wrk->app_index,
		     app_wrk->wrk_index, smm->seg_name_counter++, 0);

  fs->ssvm.ssvm_size = segment_size;
  fs->ssvm.name = seg_name;
  fs->ssvm.requested_va = 0;

  if ((rv = ssvm_server_init (&fs->ssvm, props->segment_type)))
    {
      clib_warning ("svm_master_init ('%v', %u) failed", seg_name,
		    segment_size);
      pool_put (sm->segments, fs);
      goto done;
    }

  /*
   * Initialize fifo segment
   */
  fs->n_slices = props->n_slices;
  fifo_segment_init (fs);

  /*
   * Save segment index before dropping lock, if any held
   */
  fs_index = fs - sm->segments;
  fs->fs_index = fs_index;
  fs->sm_index = segment_manager_index (sm);

  /*
   * Set watermarks in segment
   */
  fs->high_watermark = sm->high_watermark;
  fs->low_watermark = sm->low_watermark;
  fs->flags = flags;
  fs->flags &= ~FIFO_SEGMENT_F_MEM_LIMIT;
  fs->h->pct_first_alloc = props->pct_first_alloc;

  if (notify_app)
    {
      app_worker_t *app_wrk;
      u64 fs_handle;
      fs_handle = segment_manager_segment_handle (sm, fs);
      app_wrk = app_worker_get (sm->app_wrk_index);
      rv = app_worker_add_segment_notify (app_wrk, fs_handle);
      if (rv)
	{
	  fs_index = rv;
	  goto done;
	}
    }
done:

  if (need_lock)
    clib_rwlock_writer_unlock (&sm->segments_rwlock);

  return fs_index;
}

int
segment_manager_add_segment (segment_manager_t *sm, uword segment_size,
			     u8 notify_app)
{
  return segment_manager_add_segment_inline (sm, segment_size, notify_app,
					     0 /* flags */, 0 /* need_lock */);
}

int
segment_manager_add_segment2 (segment_manager_t *sm, uword segment_size,
			      u8 flags)
{
  return segment_manager_add_segment_inline (sm, segment_size, 0, flags,
					     vlib_num_workers ());
}

/**
 * Remove segment without lock
 */
void
segment_manager_del_segment (segment_manager_t * sm, fifo_segment_t * fs)
{
  if (ssvm_type (&fs->ssvm) != SSVM_SEGMENT_PRIVATE)
    {
      if (!segment_manager_app_detached (sm))
	{
	  app_worker_t *app_wrk;
	  u64 segment_handle;
	  app_wrk = app_worker_get (sm->app_wrk_index);
	  segment_handle = segment_manager_segment_handle (sm, fs);
	  app_worker_del_segment_notify (app_wrk, segment_handle);
	}
    }

  fifo_segment_cleanup (fs);
  ssvm_delete (&fs->ssvm);

  if (CLIB_DEBUG)
    clib_memset (fs, 0xfb, sizeof (*fs));
  pool_put (sm->segments, fs);
}

static fifo_segment_t *
segment_manager_get_segment_if_valid (segment_manager_t * sm,
				      u32 segment_index)
{
  if (pool_is_free_index (sm->segments, segment_index))
    return 0;
  return pool_elt_at_index (sm->segments, segment_index);
}

/**
 * Removes segment after acquiring writer lock
 */
static inline void
sm_lock_and_del_segment_inline (segment_manager_t *sm, u32 fs_index,
				u8 check_if_empty)
{
  fifo_segment_t *fs;
  u8 is_prealloc;

  clib_rwlock_writer_lock (&sm->segments_rwlock);

  fs = segment_manager_get_segment_if_valid (sm, fs_index);
  if (!fs)
    goto done;

  if (check_if_empty && fifo_segment_has_fifos (fs))
    goto done;

  is_prealloc = fifo_segment_flags (fs) & FIFO_SEGMENT_F_IS_PREALLOCATED;
  if (is_prealloc && !segment_manager_app_detached (sm))
    goto done;

  segment_manager_del_segment (sm, fs);

done:
  clib_rwlock_writer_unlock (&sm->segments_rwlock);
}

void
segment_manager_lock_and_del_segment (segment_manager_t * sm, u32 fs_index)
{
  sm_lock_and_del_segment_inline (sm, fs_index, 0 /* check_if_empty */);
}

/**
 * Reads a segment from the segment manager's pool without lock
 */
fifo_segment_t *
segment_manager_get_segment (segment_manager_t * sm, u32 segment_index)
{
  return pool_elt_at_index (sm->segments, segment_index);
}

u64
segment_manager_segment_handle (segment_manager_t * sm,
				fifo_segment_t * segment)
{
  u32 segment_index = segment_manager_segment_index (sm, segment);
  return (((u64) segment_manager_index (sm) << 32) | segment_index);
}

u64
segment_manager_make_segment_handle (u32 segment_manager_index,
				     u32 segment_index)
{
  return (((u64) segment_manager_index << 32) | segment_index);
}

fifo_segment_t *
segment_manager_get_segment_w_handle (u64 segment_handle)
{
  u32 sm_index, segment_index;
  segment_manager_t *sm;

  segment_manager_parse_segment_handle (segment_handle, &sm_index,
					&segment_index);
  sm = segment_manager_get (sm_index);
  if (!sm || pool_is_free_index (sm->segments, segment_index))
    return 0;
  return pool_elt_at_index (sm->segments, segment_index);
}

/**
 * Reads a segment from the segment manager's pool and acquires reader lock
 *
 * Caller must drop the reader's lock by calling
 * @ref segment_manager_segment_reader_unlock once it finishes working with
 * the segment.
 */
fifo_segment_t *
segment_manager_get_segment_w_lock (segment_manager_t * sm, u32 segment_index)
{
  clib_rwlock_reader_lock (&sm->segments_rwlock);
  return pool_elt_at_index (sm->segments, segment_index);
}

void
segment_manager_segment_reader_lock (segment_manager_t * sm)
{
  clib_rwlock_reader_lock (&sm->segments_rwlock);
}

void
segment_manager_segment_reader_unlock (segment_manager_t * sm)
{
  clib_rwlock_reader_unlock (&sm->segments_rwlock);
}

segment_manager_t *
segment_manager_alloc (void)
{
  segment_manager_main_t *smm = &sm_main;
  segment_manager_t *sm;

  pool_get_zero (smm->segment_managers, sm);
  clib_rwlock_init (&sm->segments_rwlock);
  return sm;
}

int
segment_manager_init (segment_manager_t * sm)
{
  segment_manager_props_t *props;

  props = segment_manager_properties_get (sm);

  sm->max_fifo_size = props->max_fifo_size ?
    props->max_fifo_size : sm_main.default_max_fifo_size;
  sm->max_fifo_size = clib_max (sm->max_fifo_size, 4096);

  segment_manager_set_watermarks (sm,
				  props->high_watermark,
				  props->low_watermark);
  return 0;
}

/**
 * Initializes segment manager based on options provided.
 * Returns error if ssvm segment(s) allocation fails.
 */
int
segment_manager_init_first (segment_manager_t * sm)
{
  segment_manager_props_t *props;
  uword first_seg_size;
  fifo_segment_t *fs;
  int fs_index, i;

  segment_manager_init (sm);
  props = segment_manager_properties_get (sm);
  first_seg_size = clib_max (props->segment_size,
			     sm_main.default_segment_size);

  if (props->prealloc_fifos)
    {
      u64 approx_total_size, max_seg_size = ((u64) 1 << 32) - (128 << 10);
      u32 rx_rounded_data_size, tx_rounded_data_size;
      u32 prealloc_fifo_pairs = props->prealloc_fifos;
      u32 rx_fifo_size, tx_fifo_size, pair_size;
      u32 approx_segment_count;

      /* Figure out how many segments should be preallocated */
      rx_rounded_data_size = (1 << (max_log2 (props->rx_fifo_size)));
      tx_rounded_data_size = (1 << (max_log2 (props->tx_fifo_size)));

      rx_fifo_size = sizeof (svm_fifo_t) + rx_rounded_data_size;
      tx_fifo_size = sizeof (svm_fifo_t) + tx_rounded_data_size;
      pair_size = rx_fifo_size + tx_fifo_size;

      approx_total_size = (u64) prealloc_fifo_pairs *pair_size;
      if (first_seg_size > approx_total_size)
	max_seg_size = first_seg_size;
      approx_segment_count = (approx_total_size + (max_seg_size - 1))
	/ max_seg_size;

      /* Allocate the segments */
      for (i = 0; i < approx_segment_count + 1; i++)
	{
	  fs_index = segment_manager_add_segment (sm, max_seg_size, 0);
	  if (fs_index < 0)
	    {
	      SESSION_DBG ("Failed to preallocate segment %d", i);
	      return fs_index;
	    }

	  fs = segment_manager_get_segment (sm, fs_index);
	  if (i == 0)
	    sm->event_queue = segment_manager_alloc_queue (fs, props);

	  fifo_segment_preallocate_fifo_pairs (fs,
					       props->rx_fifo_size,
					       props->tx_fifo_size,
					       &prealloc_fifo_pairs);
	  fifo_segment_flags (fs) = FIFO_SEGMENT_F_IS_PREALLOCATED;
	  if (prealloc_fifo_pairs == 0)
	    break;
	}
      return 0;
    }

  fs_index = segment_manager_add_segment (sm, first_seg_size, 0);
  if (fs_index < 0)
    {
      SESSION_DBG ("Failed to allocate segment");
      return fs_index;
    }

  fs = segment_manager_get_segment (sm, fs_index);
  sm->event_queue = segment_manager_alloc_queue (fs, props);

  if (props->prealloc_fifo_hdrs)
    {
      u32 hdrs_per_slice;

      /* Do not preallocate on slice associated to main thread */
      i = (vlib_num_workers ()? 1 : 0);
      hdrs_per_slice = props->prealloc_fifo_hdrs / (fs->n_slices - i);

      for (; i < fs->n_slices; i++)
	{
	  if (fifo_segment_prealloc_fifo_hdrs (fs, i, hdrs_per_slice))
	    return SESSION_E_SEG_CREATE;
	}
    }

  return 0;
}

void
segment_manager_cleanup_detached_listener (segment_manager_t * sm)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (sm->app_wrk_index);
  if (!app_wrk)
    return;

  app_worker_del_detached_sm (app_wrk, segment_manager_index (sm));
}

/**
 * Cleanup segment manager.
 */
void
segment_manager_free (segment_manager_t * sm)
{
  segment_manager_main_t *smm = &sm_main;
  fifo_segment_t *fifo_segment;

  ASSERT (vlib_get_thread_index () == 0
	  && !segment_manager_has_fifos (sm)
	  && segment_manager_app_detached (sm));

  if (sm->flags & SEG_MANAGER_F_DETACHED_LISTENER)
    segment_manager_cleanup_detached_listener (sm);

  /* If we have empty preallocated segments that haven't been removed, remove
   * them now. Apart from that, the first segment in the first segment manager
   * is not removed when all fifos are removed. It can only be removed when
   * the manager is explicitly deleted/detached by the app. */
  clib_rwlock_writer_lock (&sm->segments_rwlock);

  /* *INDENT-OFF* */
  pool_foreach (fifo_segment, sm->segments)  {
    segment_manager_del_segment (sm, fifo_segment);
  }
  /* *INDENT-ON* */

  pool_free (sm->segments);
  clib_rwlock_writer_unlock (&sm->segments_rwlock);

  clib_rwlock_free (&sm->segments_rwlock);
  if (CLIB_DEBUG)
    clib_memset (sm, 0xfe, sizeof (*sm));
  pool_put (smm->segment_managers, sm);
}

static void
sm_free_w_index_helper (void *arg)
{
  u32 sm_index = *(u32 *) arg;
  segment_manager_t *sm;

  ASSERT (vlib_get_thread_index () == 0);

  if ((sm = segment_manager_get_if_valid (sm_index)))
    segment_manager_free (sm);
}

void
segment_manager_free_safe (segment_manager_t *sm)
{
  if (!vlib_thread_is_main_w_barrier ())
    {
      u32 sm_index = segment_manager_index (sm);
      vlib_rpc_call_main_thread (sm_free_w_index_helper, (u8 *) & sm_index,
				 sizeof (sm_index));
    }
  else
    {
      segment_manager_free (sm);
    }
}

void
segment_manager_init_free (segment_manager_t * sm)
{
  ASSERT (vlib_get_thread_index () == 0);

  segment_manager_app_detach (sm);
  if (segment_manager_has_fifos (sm))
    segment_manager_del_sessions (sm);
  else
    {
      ASSERT (!sm->first_is_protected || segment_manager_app_detached (sm));
      segment_manager_free (sm);
    }
}

segment_manager_t *
segment_manager_get (u32 index)
{
  return pool_elt_at_index (sm_main.segment_managers, index);
}

segment_manager_t *
segment_manager_get_if_valid (u32 index)
{
  if (pool_is_free_index (sm_main.segment_managers, index))
    return 0;
  return pool_elt_at_index (sm_main.segment_managers, index);
}

u32
segment_manager_index (segment_manager_t * sm)
{
  return sm - sm_main.segment_managers;
}

u8
segment_manager_has_fifos (segment_manager_t * sm)
{
  fifo_segment_t *seg;
  u8 first = 1;

  /* *INDENT-OFF* */
  segment_manager_foreach_segment_w_lock (seg, sm, ({
    if (CLIB_DEBUG && !first && !fifo_segment_has_fifos (seg)
	&& !(fifo_segment_flags (seg) & FIFO_SEGMENT_F_IS_PREALLOCATED))
      {
	clib_warning ("segment %d has no fifos!",
	              segment_manager_segment_index (sm, seg));
	first = 0;
      }
    if (fifo_segment_has_fifos (seg))
      {
	segment_manager_segment_reader_unlock (sm);
	return 1;
      }
  }));
  /* *INDENT-ON* */

  return 0;
}

/**
 * Initiate disconnects for all sessions 'owned' by a segment manager
 */
void
segment_manager_del_sessions (segment_manager_t * sm)
{
  session_handle_t *handles = 0, *handle;
  fifo_segment_t *fs;
  session_t *session;
  int slice_index;
  svm_fifo_t *f;

  ASSERT (pool_elts (sm->segments) != 0);

  /* Across all fifo segments used by the server */
  /* *INDENT-OFF* */
  segment_manager_foreach_segment_w_lock (fs, sm, ({
    for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
      {
        f = fifo_segment_get_slice_fifo_list (fs, slice_index);

        /*
         * Remove any residual sessions from the session lookup table
         * Don't bother deleting the individual fifos, we're going to
         * throw away the fifo segment in a minute.
         */
        while (f)
          {
	    session = session_get_if_valid (f->shr->master_session_index,
					    f->master_thread_index);
	    if (session)
	      vec_add1 (handles, session_handle (session));
	    f = f->next;
	  }
      }

    /* Instead of removing the segment, test when cleaning up disconnected
     * sessions if the segment can be removed.
     */
  }));
  /* *INDENT-ON* */

  vec_foreach (handle, handles)
  {
    session = session_get_from_handle (*handle);
    session_close (session);
    /* Avoid propagating notifications back to the app */
    session->app_wrk_index = APP_INVALID_INDEX;
  }
  vec_free (handles);
}

/**
 * Initiate disconnects for sessions in specified state 'owned' by a segment
 * manager
 */
void
segment_manager_del_sessions_filter (segment_manager_t *sm,
				     session_state_t *states)
{
  session_handle_t *handles = 0, *handle;
  fifo_segment_t *fs;
  session_t *session;
  int slice_index;
  svm_fifo_t *f;

  ASSERT (pool_elts (sm->segments) != 0);

  /* Across all fifo segments used by the server */
  segment_manager_foreach_segment_w_lock (
    fs, sm, ({
      for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
	{
	  f = fifo_segment_get_slice_fifo_list (fs, slice_index);
	  while (f)
	    {
	      session = session_get_if_valid (f->shr->master_session_index,
					      f->master_thread_index);
	      if (session)
		{
		  session_state_t *state;
		  vec_foreach (state, states)
		    {
		      if (session->session_state == *state)
			{
			  vec_add1 (handles, session_handle (session));
			  break;
			}
		    }
		}
	      f = f->next;
	    }
	}
    }));

  vec_foreach (handle, handles)
    {
      session = session_get_from_handle (*handle);
      session_close (session);
      /* Avoid propagating notifications back to the app */
      session->app_wrk_index = APP_INVALID_INDEX;
    }
  vec_free (handles);
}

int
segment_manager_try_alloc_fifos (fifo_segment_t *fs, u32 thread_index,
				 u32 rx_fifo_size, u32 tx_fifo_size,
				 svm_fifo_t **rx_fifo, svm_fifo_t **tx_fifo)
{
  rx_fifo_size = clib_max (rx_fifo_size, sm_main.default_fifo_size);
  *rx_fifo = fifo_segment_alloc_fifo_w_slice (fs, thread_index, rx_fifo_size,
					      FIFO_SEGMENT_RX_FIFO);

  tx_fifo_size = clib_max (tx_fifo_size, sm_main.default_fifo_size);
  *tx_fifo = fifo_segment_alloc_fifo_w_slice (fs, thread_index, tx_fifo_size,
					      FIFO_SEGMENT_TX_FIFO);

  if (*rx_fifo == 0)
    {
      /* This would be very odd, but handle it... */
      if (*tx_fifo != 0)
	{
	  fifo_segment_free_fifo (fs, *tx_fifo);
	  *tx_fifo = 0;
	}
      return SESSION_E_SEG_NO_SPACE;
    }
  if (*tx_fifo == 0)
    {
      if (*rx_fifo != 0)
	{
	  fifo_segment_free_fifo (fs, *rx_fifo);
	  *rx_fifo = 0;
	}
      return SESSION_E_SEG_NO_SPACE;
    }

  return 0;
}

static inline int
sm_lookup_segment_and_alloc_fifos (segment_manager_t *sm,
				   segment_manager_props_t *props,
				   u32 thread_index, svm_fifo_t **rx_fifo,
				   svm_fifo_t **tx_fifo)
{
  uword free_bytes, max_free_bytes;
  fifo_segment_t *cur, *fs = 0;

  max_free_bytes = props->rx_fifo_size + props->tx_fifo_size - 1;

  pool_foreach (cur, sm->segments)
    {
      if (fifo_segment_flags (cur) & FIFO_SEGMENT_F_CUSTOM_USE)
	continue;
      free_bytes = fifo_segment_available_bytes (cur);
      if (free_bytes > max_free_bytes)
	{
	  max_free_bytes = free_bytes;
	  fs = cur;
	}
    }

  if (PREDICT_FALSE (!fs))
    return SESSION_E_SEG_NO_SPACE;

  return segment_manager_try_alloc_fifos (
    fs, thread_index, props->rx_fifo_size, props->tx_fifo_size, rx_fifo,
    tx_fifo);
}

static int
sm_lock_and_alloc_segment_and_fifos (segment_manager_t *sm,
				     segment_manager_props_t *props,
				     u32 thread_index, svm_fifo_t **rx_fifo,
				     svm_fifo_t **tx_fifo)
{
  int new_fs_index, rv;
  fifo_segment_t *fs;

  if (!props->add_segment)
    return SESSION_E_SEG_NO_SPACE;

  clib_rwlock_writer_lock (&sm->segments_rwlock);

  /* Make sure there really is no free space. Another worker might've freed
   * some fifos or allocated a segment */
  rv = sm_lookup_segment_and_alloc_fifos (sm, props, thread_index, rx_fifo,
					  tx_fifo);
  if (!rv)
    goto done;

  new_fs_index =
    segment_manager_add_segment (sm, 0 /* segment_size*/, 1 /* notify_app */);
  if (new_fs_index < 0)
    {
      rv = SESSION_E_SEG_CREATE;
      goto done;
    }
  fs = segment_manager_get_segment (sm, new_fs_index);
  rv = segment_manager_try_alloc_fifos (fs, thread_index, props->rx_fifo_size,
					props->tx_fifo_size, rx_fifo, tx_fifo);
  if (rv)
    {
      SESSION_DBG ("Added a segment, still can't allocate a fifo");
      rv = SESSION_E_SEG_NO_SPACE2;
      goto done;
    }

done:

  clib_rwlock_writer_unlock (&sm->segments_rwlock);

  return rv;
}

int
segment_manager_alloc_session_fifos (segment_manager_t * sm,
				     u32 thread_index,
				     svm_fifo_t ** rx_fifo,
				     svm_fifo_t ** tx_fifo)
{
  segment_manager_props_t *props;
  int rv;

  props = segment_manager_properties_get (sm);

  /*
   * Fast path: find the first segment with enough free space and
   * try to allocate the fifos. Done with reader lock
   */

  segment_manager_segment_reader_lock (sm);

  rv = sm_lookup_segment_and_alloc_fifos (sm, props, thread_index, rx_fifo,
					  tx_fifo);

  segment_manager_segment_reader_unlock (sm);

  /*
   * Slow path: if no fifo segment or alloc fail grab writer lock and try
   * to allocate new segment
   */
  if (PREDICT_FALSE (rv < 0))
    return sm_lock_and_alloc_segment_and_fifos (sm, props, thread_index,
						rx_fifo, tx_fifo);

  return 0;
}

void
segment_manager_dealloc_fifos (svm_fifo_t * rx_fifo, svm_fifo_t * tx_fifo)
{
  segment_manager_t *sm;
  fifo_segment_t *fs;
  u32 segment_index;
  u8 try_delete = 0;

  if (!rx_fifo || !tx_fifo)
    return;

  /* Thread that allocated the fifos must be the one to clean them up */
  ASSERT (rx_fifo->master_thread_index == vlib_get_thread_index () ||
	  rx_fifo->refcnt > 1 || vlib_thread_is_main_w_barrier ());

  /* It's possible to have no segment manager if the session was removed
   * as result of a detach. */
  if (!(sm = segment_manager_get_if_valid (rx_fifo->segment_manager)))
    return;

  segment_index = rx_fifo->segment_index;
  fs = segment_manager_get_segment_w_lock (sm, segment_index);
  fifo_segment_free_fifo (fs, rx_fifo);
  fifo_segment_free_fifo (fs, tx_fifo);

  /*
   * Try to remove fifo segment if it has no fifos. This can be done only if
   * the segment is not the first in the segment manager or if it is first
   * and it is not protected. Moreover, if the segment is first and the app
   * has detached from the segment manager, remove the segment manager.
   */
  if (!fifo_segment_has_fifos (fs))
    {
      /* If first, remove only if not protected */
      try_delete = segment_index != 0 || !sm->first_is_protected;
    }

  segment_manager_segment_reader_unlock (sm);

  if (PREDICT_FALSE (try_delete))
    {
      /* Only remove if empty after writer lock acquired */
      sm_lock_and_del_segment_inline (sm, segment_index,
				      1 /* check_if_empty */);

      /* Remove segment manager if no sessions and detached from app */
      if (segment_manager_app_detached (sm)
	  && !segment_manager_has_fifos (sm))
	segment_manager_free_safe (sm);
    }
}

void
segment_manager_detach_fifo (segment_manager_t *sm, svm_fifo_t **f)
{
  fifo_segment_t *fs;

  fs = segment_manager_get_segment_w_lock (sm, (*f)->segment_index);
  fifo_segment_detach_fifo (fs, f);
  segment_manager_segment_reader_unlock (sm);
}

void
segment_manager_attach_fifo (segment_manager_t *sm, svm_fifo_t **f,
			     session_t *s)
{
  fifo_segment_t *fs;

  fs = segment_manager_get_segment_w_lock (sm, (*f)->segment_index);
  fifo_segment_attach_fifo (fs, f, s->thread_index);
  segment_manager_segment_reader_unlock (sm);

  (*f)->shr->master_session_index = s->session_index;
  (*f)->master_thread_index = s->thread_index;
}

u32
segment_manager_evt_q_expected_size (u32 q_len)
{
  u32 fifo_evt_size, notif_q_size, q_hdrs;
  u32 msg_q_sz, fifo_evt_ring_sz, session_ntf_ring_sz;

  fifo_evt_size = 1 << max_log2 (sizeof (session_event_t));
  notif_q_size = clib_max (16, q_len >> 4);

  msg_q_sz = q_len * sizeof (svm_msg_q_msg_t);
  fifo_evt_ring_sz = q_len * fifo_evt_size;
  session_ntf_ring_sz = notif_q_size * 256;
  q_hdrs = sizeof (svm_queue_t) + sizeof (svm_msg_q_t);

  return (msg_q_sz + fifo_evt_ring_sz + session_ntf_ring_sz + q_hdrs);
}

/**
 * Allocates shm queue in the first segment
 *
 * Must be called with lock held
 */
svm_msg_q_t *
segment_manager_alloc_queue (fifo_segment_t * segment,
			     segment_manager_props_t * props)
{
  u32 fifo_evt_size, session_evt_size = 256, notif_q_size;
  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  svm_msg_q_t *q;

  fifo_evt_size = sizeof (session_event_t);
  notif_q_size = clib_max (16, props->evt_q_size >> 4);
  /* *INDENT-OFF* */
  svm_msg_q_ring_cfg_t rc[SESSION_MQ_N_RINGS] = {
    {props->evt_q_size, fifo_evt_size, 0},
    {notif_q_size, session_evt_size, 0}
  };
  /* *INDENT-ON* */
  cfg->consumer_pid = 0;
  cfg->n_rings = 2;
  cfg->q_nitems = props->evt_q_size;
  cfg->ring_cfgs = rc;

  q = fifo_segment_msg_q_alloc (segment, 0, cfg);

  if (props->use_mq_eventfd)
    {
      if (svm_msg_q_alloc_eventfd (q))
	clib_warning ("failed to alloc eventfd");
    }
  return q;
}

svm_msg_q_t *
segment_manager_event_queue (segment_manager_t * sm)
{
  return sm->event_queue;
}

/**
 * Frees shm queue allocated in the first segment
 */
void
segment_manager_dealloc_queue (segment_manager_t * sm, svm_queue_t * q)
{
  fifo_segment_t *segment;
  ssvm_shared_header_t *sh;
  void *oldheap;

  ASSERT (!pool_is_free_index (sm->segments, 0));

  segment = segment_manager_get_segment_w_lock (sm, 0);
  sh = segment->ssvm.sh;

  oldheap = ssvm_push_heap (sh);
  svm_queue_free (q);
  ssvm_pop_heap (oldheap);
  segment_manager_segment_reader_unlock (sm);
}

/*
 * Init segment vm address allocator
 */
void
segment_manager_main_init (void)
{
  segment_manager_main_t *sm = &sm_main;

  sm->default_fifo_size = 1 << 12;
  sm->default_segment_size = 1 << 20;
  sm->default_app_mq_size = 128;
  sm->default_max_fifo_size = 4 << 20;
  sm->default_high_watermark = 80;
  sm->default_low_watermark = 50;
}

static u8 *
format_segment_manager (u8 *s, va_list *args)
{
  segment_manager_t *sm = va_arg (*args, segment_manager_t *);
  int verbose = va_arg (*args, int);
  app_worker_t *app_wrk;
  uword max_fifo_size;
  fifo_segment_t *seg;
  application_t *app;
  u8 custom_logic;

  app_wrk = app_worker_get_if_valid (sm->app_wrk_index);
  app = app_wrk ? application_get (app_wrk->app_index) : 0;
  custom_logic = (app && (app->cb_fns.fifo_tuning_callback)) ? 1 : 0;
  max_fifo_size = sm->max_fifo_size;

  s = format (s,
	      "[%u] %v app-wrk: %u segs: %u max-fifo-sz: %U "
	      "wmarks: %u %u %s flags: 0x%x",
	      segment_manager_index (sm), app ? app->name : 0,
	      sm->app_wrk_index, pool_elts (sm->segments), format_memory_size,
	      max_fifo_size, sm->high_watermark, sm->low_watermark,
	      custom_logic ? "custom-tuning" : "no-tuning", sm->flags);

  if (!verbose || !pool_elts (sm->segments))
    return s;

  s = format (s, "\n\n");

  segment_manager_foreach_segment_w_lock (
    seg, sm, ({ s = format (s, " *%U", format_fifo_segment, seg, verbose); }));

  return s;
}

static clib_error_t *
segment_manager_show_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  segment_manager_main_t *smm = &sm_main;
  u8 show_segments = 0, verbose = 0;
  segment_manager_t *sm;
  u32 sm_index = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      vlib_cli_output (vm, "%d segment managers allocated",
		       pool_elts (smm->segment_managers));
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "segments"))
	show_segments = 1;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else if (unformat (line_input, "index %u", &sm_index))
	;
      else
	{
	  vlib_cli_output (vm, "unknown input [%U]", format_unformat_error,
			   line_input);
	  goto done;
	}
    }

  if (!pool_elts (smm->segment_managers))
    goto done;

  if (sm_index != ~0)
    {
      sm = segment_manager_get_if_valid (sm_index);
      if (!sm)
	{
	  vlib_cli_output (vm, "segment manager %u not allocated", sm_index);
	  goto done;
	}
      vlib_cli_output (vm, "%U", format_segment_manager, sm, 1 /* verbose */);
      goto done;
    }

  if (verbose || show_segments)
    {
      pool_foreach (sm, smm->segment_managers)  {
	  vlib_cli_output (vm, "%U", format_segment_manager, sm,
			   show_segments);
      }

      vlib_cli_output (vm, "\n");
    }

done:

  unformat_free (line_input);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (segment_manager_show_command, static) = {
  .path = "show segment-manager",
  .short_help = "show segment-manager [segments][verbose][index <nn>]",
  .function = segment_manager_show_fn,
};
/* *INDENT-ON* */

void
segment_manager_format_sessions (segment_manager_t * sm, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  app_worker_t *app_wrk;
  fifo_segment_t *fs;
  const u8 *app_name;
  int slice_index;
  u8 *s = 0, *str;
  svm_fifo_t *f;

  if (!sm)
    {
      if (verbose)
	vlib_cli_output (vm, "%-" SESSION_CLI_ID_LEN "s%-20s%-15s%-10s",
			 "Connection", "App", "API Client", "SegManager");
      else
	vlib_cli_output (vm, "%-" SESSION_CLI_ID_LEN "s%-20s", "Connection",
			 "App");
      return;
    }

  app_wrk = app_worker_get (sm->app_wrk_index);
  app_name = application_name_from_index (app_wrk->app_index);

  clib_rwlock_reader_lock (&sm->segments_rwlock);

  /* *INDENT-OFF* */
  pool_foreach (fs, sm->segments)  {
    for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
      {
        f = fifo_segment_get_slice_fifo_list (fs, slice_index);
        while (f)
          {
            u32 session_index, thread_index;
            session_t *session;

	    session_index = f->shr->master_session_index;
	    thread_index = f->master_thread_index;

	    session = session_get (session_index, thread_index);
	    str = format (0, "%U", format_session, session, verbose);

	    if (verbose)
	      s = format (s, "%-" SESSION_CLI_ID_LEN "v%-20v%-15u%-10u", str,
			  app_name, app_wrk->api_client_index,
			  app_wrk->connects_seg_manager);
	    else
	      s = format (s, "%-" SESSION_CLI_ID_LEN "v%-20v", str, app_name);

	    vlib_cli_output (vm, "%v", s);
	    vec_reset_length (s);
	    vec_free (str);

	    f = f->next;
	  }
	vec_free (s);
      }
  }
  /* *INDENT-ON* */

  clib_rwlock_reader_unlock (&sm->segments_rwlock);
}

void
segment_manager_set_watermarks (segment_manager_t * sm,
				u8 high_watermark, u8 low_watermark)
{
  ASSERT (high_watermark <= 100 && low_watermark <= 100 &&
	  low_watermark <= high_watermark);

  sm->high_watermark = high_watermark;
  sm->low_watermark = low_watermark;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
