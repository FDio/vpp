/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#include <vnet/session/segment_manager.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <sys/mman.h>
#include <vnet/session/application_local.h>

VLIB_REGISTER_LOG_CLASS (segment_manager_log,
			 static) = { .class_name = "segment-manager",
				     .subclass_name = "error" };

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (segment_manager_log.class, "%s: " fmt, __func__, __VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (segment_manager_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_err (segment_manager_log.class, fmt, __VA_ARGS__)

typedef enum custom_segment_flags_
{
  CUSTOM_SEGMENT_F_CLIENT_DETACHED = 1 << 0,
  CUSTOM_SEGMENT_F_SERVER_DETACHED = 1 << 1,
} custom_segment_flags_t;

typedef struct custom_segment_
{
  u32 client_n_sessions;
  u32 server_n_sessions;
  u32 seg_ctx_index;
  u32 custom_seg_index;
  u32 segment_index;
  custom_segment_flags_t flags;
} custom_segment_t;

typedef struct custom_segments_
{
  u32 sm_index;
  u32 server_wrk;
  u32 client_wrk;
  u32 fifo_pair_bytes;
  custom_segment_t *segments;
} custom_segments_ctx_t;

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
  u8 no_dump_segments;		/**< don't dump segs in core files */

  /* custom segment stuff */
  clib_rwlock_t custom_segs_lock; /**< RW lock for seg contexts */
  uword *custom_segs_ctxs_table;  /**< Handle to segment pool map */
  custom_segments_ctx_t
    *custom_seg_ctxs; /**< Pool of custom segment contexts */
} segment_manager_main_t;

static segment_manager_main_t sm_main, *smm = &sm_main;

#define segment_manager_foreach_segment_w_lock(VAR, SM, BODY)		\
do {									\
    clib_rwlock_reader_lock (&(SM)->segments_rwlock);			\
    pool_foreach((VAR), ((SM)->segments)) (BODY);			\
    clib_rwlock_reader_unlock (&(SM)->segments_rwlock);			\
} while (0)

static void segment_manager_dealloc_fifos_ct (svm_fifo_t *rx_fifo,
					      svm_fifo_t *tx_fifo,
					      u32 is_client);

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

  if (props->max_segments && pool_elts (sm->segments) >= props->max_segments)
    {
      SESSION_DBG (
	"max number of segments allocated, can't allocate new segment");
      goto done;
    }

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

  if (props->use_huge_page)
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

  if (props->no_dump_segments || smm->no_dump_segments)
    {
      if (madvise (fs->ssvm.sh, fs->ssvm.ssvm_size, MADV_DONTDUMP) != 0)
	clib_warning ("madvise MADV_DONTDUMP failed for seg %s", seg_name);
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
static void
segment_manager_del_segment (segment_manager_t *sm, fifo_segment_t *fs)
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

static void
segment_manager_lock_and_del_segment (segment_manager_t *sm, u32 fs_index)
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

  pool_foreach (fifo_segment, sm->segments)  {
    segment_manager_del_segment (sm, fifo_segment);
  }

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
	    session = session_get_if_valid (f->vpp_session_index,
					    f->master_thread_index);
	    /* Remove sessions matching the app_wrk_index. We still need the
	     * non-matching app_wrk_index sessions so that it can clean up
	     * itself first. */
	    if (session && (session->app_wrk_index == sm->app_wrk_index))
	      vec_add1 (handles, session_handle (session));
	    f = f->next;
	  }
      }

    /* Instead of removing the segment, test when cleaning up disconnected
     * sessions if the segment can be removed.
     */
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
	      session = session_get_if_valid (f->vpp_session_index,
					      f->master_thread_index);
	      /* Remove sessions matching the app_wrk_index. We still need the
	       * non-matching app_wrk_index sessions so that it can clean up
	       * itself first. */
	      if (session && (session->app_wrk_index == sm->app_wrk_index))
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

static int
segment_manager_try_alloc_fifos (fifo_segment_t *fs,
				 clib_thread_index_t thread_index,
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
				   clib_thread_index_t thread_index,
				   svm_fifo_t **rx_fifo, svm_fifo_t **tx_fifo)
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
				     clib_thread_index_t thread_index,
				     svm_fifo_t **rx_fifo,
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
segment_manager_alloc_session_fifos (segment_manager_t *sm,
				     clib_thread_index_t thread_index,
				     svm_fifo_t **rx_fifo,
				     svm_fifo_t **tx_fifo)
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
segment_manager_dealloc_fifos (svm_fifo_t *rx_fifo, svm_fifo_t *tx_fifo)
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

  if (rx_fifo->flags & (SVM_FIFO_F_SERVER_CT | SVM_FIFO_F_CLIENT_CT))
    {
      if (rx_fifo->flags & SVM_FIFO_F_SERVER_CT)
	return segment_manager_dealloc_fifos_ct (rx_fifo, tx_fifo, 0);
      else
	segment_manager_dealloc_fifos_ct (rx_fifo->ct_fifo, tx_fifo->ct_fifo,
					  1);
    }

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

  (*f)->vpp_sh = s->handle;
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
  svm_msg_q_ring_cfg_t rc[SESSION_MQ_N_RINGS] = {
    {props->evt_q_size, fifo_evt_size, 0},
    {notif_q_size, session_evt_size, 0}
  };
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
segment_manager_main_init (u8 no_dump_segments)
{
  segment_manager_main_t *sm = &sm_main;

  sm->default_fifo_size = 1 << 12;
  sm->default_segment_size = 1 << 20;
  sm->default_app_mq_size = 128;
  sm->default_max_fifo_size = 4 << 20;
  sm->default_high_watermark = 80;
  sm->default_low_watermark = 50;
  sm->no_dump_segments = no_dump_segments;
  clib_rwlock_init (&sm->custom_segs_lock);
}

static u8 *
format_segment_manager_flags (u8 *s, va_list *args)
{
  int flags = va_arg (*args, int);
  typedef struct sm_flags_struct
  {
    u8 bit;
    char *str;
  } sm_flags_struct_t;
  sm_flags_struct_t *entry;
  static sm_flags_struct_t sm_flags_array[] = {
#define _(b, v, s)                                                            \
  {                                                                           \
    .bit = 1 << b,                                                            \
    .str = #s,                                                                \
  },
    foreach_seg_manager_flag
#undef _
    { .str = NULL }
  };

  entry = sm_flags_array;
  while (entry->str)
    {
      if (flags & entry->bit)
	s = format (s, "%s ", entry->str, entry->bit);
      entry++;
    }
  return s;
}

u8 *
format_segment_manager (u8 *s, va_list *args)
{
  segment_manager_t *sm = va_arg (*args, segment_manager_t *);
  int verbose = va_arg (*args, int);
  int indent = format_get_indent (s);
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
	      "wmarks: %u %u %s flags: %U",
	      segment_manager_index (sm), app ? app->name : 0,
	      sm->app_wrk_index, pool_elts (sm->segments), format_memory_size,
	      max_fifo_size, sm->high_watermark, sm->low_watermark,
	      custom_logic ? "custom-tuning" : "no-tuning",
	      format_segment_manager_flags, (int) sm->flags);

  if (!verbose || !pool_elts (sm->segments))
    return s;

  s = format (s, "\n\n");

  segment_manager_foreach_segment_w_lock (
    seg, sm, ({
      s = format (s, "%U *%U", format_white_space, indent, format_fifo_segment,
		  seg, verbose);
    }));

  return s;
}

static clib_error_t *
segment_manager_show_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
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

VLIB_CLI_COMMAND (segment_manager_show_command, static) = {
  .path = "show segment-manager",
  .short_help = "show segment-manager [segments][verbose][index <nn>]",
  .function = segment_manager_show_fn,
};

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

  pool_foreach (fs, sm->segments)
    {
      for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
	{
	  f = fifo_segment_get_slice_fifo_list (fs, slice_index);
	  while (f)
	    {
	      u32 session_index, thread_index;
	      session_t *session;

	      session_index = f->vpp_session_index;
	      thread_index = f->master_thread_index;

	      session = session_get (session_index, thread_index);
	      str = format (0, "%U", format_session, session, verbose);

	      if (verbose)
		s = format (s, "%-" SESSION_CLI_ID_LEN "v%-20v%-15u%-10u", str,
			    app_name, app_wrk->api_client_index,
			    app_wrk->connects_seg_manager);
	      else
		s =
		  format (s, "%-" SESSION_CLI_ID_LEN "v%-20v", str, app_name);

	      vlib_cli_output (vm, "%v", s);
	      vec_reset_length (s);
	      vec_free (str);

	      f = f->next;
	    }
	  vec_free (s);
	}
    }

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

/* custom segment stuff */

static inline u64
ct_client_seg_handle (u64 server_sh, u32 client_wrk_index)
{
  return (((u64) client_wrk_index << 56) | server_sh);
}

static void
segment_manager_dealloc_fifos_ct (svm_fifo_t *rx_fifo, svm_fifo_t *tx_fifo,
				  u32 is_client)
{
  custom_segments_ctx_t *seg_ctx;
  segment_manager_t *sm;
  app_worker_t *app_wrk;
  custom_segment_t *ct_seg;
  fifo_segment_t *fs;
  u32 seg_index;
  int cnt;
  u32 seg_ctx_index = rx_fifo->seg_ctx_index;
  u32 ct_seg_index = rx_fifo->ct_seg_index;

  /*
   * Cleanup fifos
   */

  if (!(sm = segment_manager_get_if_valid (rx_fifo->segment_manager)))
    return;
  seg_index = rx_fifo->segment_index;

  fs = segment_manager_get_segment_w_lock (sm, seg_index);
  ASSERT ((fifo_segment_flags (fs) & FIFO_SEGMENT_F_CUSTOM_USE) ==
	  FIFO_SEGMENT_F_CUSTOM_USE);
  fifo_segment_free_fifo (fs, rx_fifo);
  fifo_segment_free_fifo (fs, tx_fifo);
  segment_manager_segment_reader_unlock (sm);

  /*
   * Atomically update segment context with readers lock
   */

  clib_rwlock_reader_lock (&smm->custom_segs_lock);

  seg_ctx = pool_elt_at_index (smm->custom_seg_ctxs, seg_ctx_index);
  ct_seg = pool_elt_at_index (seg_ctx->segments, ct_seg_index);

  if (is_client)
    {
      cnt =
	__atomic_sub_fetch (&ct_seg->client_n_sessions, 1, __ATOMIC_RELAXED);
    }
  else
    {
      cnt =
	__atomic_sub_fetch (&ct_seg->server_n_sessions, 1, __ATOMIC_RELAXED);
    }

  clib_rwlock_reader_unlock (&smm->custom_segs_lock);

  /*
   * No need to do any app updates, return
   */
  ASSERT (cnt >= 0);
  if (cnt)
    return;

  /*
   * Grab exclusive lock and update flags unless some other thread
   * added more sessions
   */
  clib_rwlock_writer_lock (&smm->custom_segs_lock);

  if (is_client)
    {
      cnt = ct_seg->client_n_sessions;
      if (cnt)
	goto done;
      ct_seg->flags |= CUSTOM_SEGMENT_F_CLIENT_DETACHED;
    }
  else
    {
      cnt = ct_seg->server_n_sessions;
      if (cnt)
	goto done;
      ct_seg->flags |= CUSTOM_SEGMENT_F_SERVER_DETACHED;
    }

  if (!(ct_seg->flags & CUSTOM_SEGMENT_F_CLIENT_DETACHED) ||
      !(ct_seg->flags & CUSTOM_SEGMENT_F_SERVER_DETACHED))
    goto done;

  /*
   * Remove segment context because both client and server detached.
   * Save client_wrk before potentially freeing seg_ctx.
   */
  u32 client_wrk = seg_ctx->client_wrk;

  pool_put_index (seg_ctx->segments, ct_seg_index);

  /*
   * No more segment indices left, remove the segments context
   */
  if (!pool_elts (seg_ctx->segments))
    {
      u64 table_handle = client_wrk << 16 | seg_ctx->server_wrk;
      table_handle = (u64) seg_ctx->sm_index << 32 | table_handle;
      hash_unset (smm->custom_segs_ctxs_table, table_handle);
      pool_free (seg_ctx->segments);
      pool_put_index (smm->custom_seg_ctxs, seg_ctx_index);
    }

  /*
   * Segment to be removed so notify both apps
   */

  app_wrk = app_worker_get_if_valid (client_wrk);
  /* Determine if client app still needs notification, i.e., if it is
   * still attached. If client detached and this is the last ct session
   * on this segment, then its connects segment manager should also be
   * detached, so do not send notification */
  if (app_wrk)
    {
      segment_manager_t *csm;
      u64 segment_handle = segment_manager_segment_handle (sm, fs);
      csm = app_worker_get_connect_segment_manager (app_wrk);
      if (!segment_manager_app_detached (csm))
	app_worker_del_segment_notify (app_wrk, ct_client_seg_handle (segment_handle, client_wrk));
    }

  /* Notify server app and free segment */
  segment_manager_lock_and_del_segment (sm, seg_index);

  /* Cleanup segment manager if needed. If server detaches there's a chance
   * the client's sessions will hold up segment removal */
  if (segment_manager_app_detached (sm) && !segment_manager_has_fifos (sm))
    segment_manager_free_safe (sm);

done:

  clib_rwlock_writer_unlock (&smm->custom_segs_lock);
}

static inline custom_segment_t *
sm_lookup_free_custom_segment (segment_manager_t *sm, u32 seg_ctx_index)
{
  uword free_bytes, max_free_bytes;
  custom_segment_t *ct_seg, *res = 0;
  custom_segments_ctx_t *seg_ctx;
  fifo_segment_t *fs;
  u32 max_fifos;

  seg_ctx = pool_elt_at_index (smm->custom_seg_ctxs, seg_ctx_index);
  max_free_bytes = seg_ctx->fifo_pair_bytes;

  pool_foreach (ct_seg, seg_ctx->segments)
    {
      /* Client or server has detached so segment cannot be used */
      fs = segment_manager_get_segment (sm, ct_seg->segment_index);
      free_bytes = fifo_segment_available_bytes (fs);
      max_fifos = fifo_segment_size (fs) / seg_ctx->fifo_pair_bytes;
      if (free_bytes > max_free_bytes &&
	  fifo_segment_num_fifos (fs) / 2 < max_fifos)
	{
	  max_free_bytes = free_bytes;
	  res = ct_seg;
	}
    }

  return res;
}

static custom_segment_t *
sm_custom_alloc_segment (app_worker_t *server_wrk, u64 table_handle,
			 segment_manager_t *sm, u32 client_wrk_index)
{
  u32 seg_ctx_index = ~0, sm_index, pair_bytes;
  u64 seg_size, seg_handle, client_seg_handle;
  segment_manager_props_t *props;
  const u32 margin = 16 << 10;
  custom_segments_ctx_t *seg_ctx;
  application_t *server;
  app_worker_t *client_wrk;
  custom_segment_t *ct_seg;
  uword *spp;
  int fs_index;

  server = application_get (server_wrk->app_index);
  props = application_segment_manager_properties (server);
  sm_index = segment_manager_index (sm);
  pair_bytes = props->rx_fifo_size + props->tx_fifo_size + margin;

  /*
   * Make sure another thread did not alloc a segment while acquiring the lock
   */

  spp = hash_get (smm->custom_segs_ctxs_table, table_handle);
  if (spp)
    {
      seg_ctx_index = *spp;
      ct_seg = sm_lookup_free_custom_segment (sm, seg_ctx_index);
      if (ct_seg)
	return ct_seg;
    }

  /*
   * No segment, try to alloc one and notify the server and the client.
   * Make sure the segment is not used for other fifos
   */
  seg_size = clib_max (props->segment_size, 128 << 20);
  fs_index =
    segment_manager_add_segment2 (sm, seg_size, FIFO_SEGMENT_F_CUSTOM_USE);
  if (fs_index < 0)
    return 0;

  if (seg_ctx_index == ~0)
    {
      pool_get_zero (smm->custom_seg_ctxs, seg_ctx);
      seg_ctx_index = seg_ctx - smm->custom_seg_ctxs;
      hash_set (smm->custom_segs_ctxs_table, table_handle, seg_ctx_index);
      seg_ctx->server_wrk = server_wrk->wrk_index;
      seg_ctx->client_wrk = client_wrk_index;
      seg_ctx->sm_index = sm_index;
      seg_ctx->fifo_pair_bytes = pair_bytes;
    }
  else
    {
      seg_ctx = pool_elt_at_index (smm->custom_seg_ctxs, seg_ctx_index);
    }

  pool_get_zero (seg_ctx->segments, ct_seg);
  ct_seg->segment_index = fs_index;
  ct_seg->server_n_sessions = 0;
  ct_seg->client_n_sessions = 0;
  ct_seg->custom_seg_index = ct_seg - seg_ctx->segments;
  ct_seg->seg_ctx_index = seg_ctx_index;

  /* New segment, notify the server and client */
  seg_handle = segment_manager_make_segment_handle (sm_index, fs_index);
  if (app_worker_add_segment_notify (server_wrk, seg_handle))
    goto error;

  client_wrk = app_worker_get (client_wrk_index);
  /* Make sure client workers do not have overlapping segment handles.
   * Ideally, we should attach fs to client worker segment manager and
   * create a new handle but that's not currently possible. */
  client_seg_handle = ct_client_seg_handle (seg_handle, client_wrk_index);
  if (app_worker_add_segment_notify (client_wrk, client_seg_handle))
    {
      app_worker_del_segment_notify (server_wrk, seg_handle);
      goto error;
    }

  return ct_seg;

error:

  segment_manager_lock_and_del_segment (sm, fs_index);
  pool_put_index (seg_ctx->segments, ct_seg->seg_ctx_index);
  return 0;
}

int
segment_manager_alloc_session_fifos_ct (session_t *s, segment_manager_t *sm,
					clib_thread_index_t thread_index,
					svm_fifo_t **rx_fifo,
					svm_fifo_t **tx_fifo)
{
  segment_manager_props_t *props;
  u64 table_handle, seg_handle;
  u32 sm_index, fs_index = ~0;
  custom_segments_ctx_t *seg_ctx;
  application_t *server;
  custom_segment_t *ct_seg;
  fifo_segment_t *fs;
  uword *spp;
  int rv;
  app_worker_t *server_wrk = app_worker_get (s->app_wrk_index);
  ct_connection_t *sct, *cct;

  sct = ct_connection_get (s->connection_index, thread_index);
  ASSERT (sct != 0);
  if (sct == 0)
    {
      log_err ("Cannot find server cut-through connection: connection index "
	       "%d, thread index %d",
	       s->connection_index, thread_index);
      return -1;
    }
  cct = ct_connection_get (sct->peer_index, thread_index);
  ASSERT (cct != 0);
  if (cct == 0)
    {
      log_err ("Cannot find client cut-through connection: peer index %d, "
	       "thread index %d",
	       sct->peer_index, thread_index);
      return -1;
    }

  sm_index = segment_manager_index (sm);
  server = application_get (server_wrk->app_index);
  props = application_segment_manager_properties (server);

  table_handle = sct->client_wrk << 16 | server_wrk->wrk_index;
  table_handle = (u64) sm_index << 32 | table_handle;

  /*
   * Check if we already have a segment that can hold the fifos
   */

  clib_rwlock_reader_lock (&smm->custom_segs_lock);

  spp = hash_get (smm->custom_segs_ctxs_table, table_handle);
  if (spp)
    {
      ct_seg = sm_lookup_free_custom_segment (sm, *spp);
      if (ct_seg)
	{
	  sct->seg_ctx_index = ct_seg->seg_ctx_index;
	  sct->ct_seg_index = ct_seg->custom_seg_index;
	  fs_index = ct_seg->segment_index;
	  ct_seg->flags &= ~(CUSTOM_SEGMENT_F_SERVER_DETACHED |
			     CUSTOM_SEGMENT_F_CLIENT_DETACHED);
	  __atomic_add_fetch (&ct_seg->server_n_sessions, 1, __ATOMIC_RELAXED);
	  __atomic_add_fetch (&ct_seg->client_n_sessions, 1, __ATOMIC_RELAXED);
	}
    }

  clib_rwlock_reader_unlock (&smm->custom_segs_lock);

  /*
   * If not, grab exclusive lock and allocate segment
   */
  if (fs_index == ~0)
    {
      clib_rwlock_writer_lock (&smm->custom_segs_lock);

      ct_seg = sm_custom_alloc_segment (server_wrk, table_handle, sm,
					sct->client_wrk);
      if (!ct_seg)
	{
	  clib_rwlock_writer_unlock (&smm->custom_segs_lock);
	  return -1;
	}

      sct->seg_ctx_index = ct_seg->seg_ctx_index;
      sct->ct_seg_index = ct_seg->custom_seg_index;
      ct_seg->server_n_sessions += 1;
      ct_seg->client_n_sessions += 1;
      fs_index = ct_seg->segment_index;

      clib_rwlock_writer_unlock (&smm->custom_segs_lock);
    }

  /*
   * Allocate and initialize the fifos
   */
  fs = segment_manager_get_segment_w_lock (sm, fs_index);
  rv = segment_manager_try_alloc_fifos (fs, thread_index, props->rx_fifo_size,
					props->tx_fifo_size, rx_fifo, tx_fifo);
  if (rv)
    {
      segment_manager_segment_reader_unlock (sm);

      clib_rwlock_reader_lock (&smm->custom_segs_lock);

      seg_ctx = pool_elt_at_index (smm->custom_seg_ctxs, sct->seg_ctx_index);
      ct_seg = pool_elt_at_index (seg_ctx->segments, sct->ct_seg_index);
      __atomic_sub_fetch (&ct_seg->server_n_sessions, 1, __ATOMIC_RELAXED);
      __atomic_sub_fetch (&ct_seg->client_n_sessions, 1, __ATOMIC_RELAXED);

      clib_rwlock_reader_unlock (&smm->custom_segs_lock);

      return rv;
    }

  seg_handle = segment_manager_segment_handle (sm, fs);
  segment_manager_segment_reader_unlock (sm);

  sct->segment_handle = seg_handle;
  sct->server_wrk = s->app_wrk_index;

  cct->server_wrk = sct->server_wrk;
  cct->seg_ctx_index = sct->seg_ctx_index;
  cct->ct_seg_index = sct->ct_seg_index;
  (*rx_fifo)->seg_ctx_index = (*tx_fifo)->seg_ctx_index = cct->seg_ctx_index;
  (*rx_fifo)->ct_seg_index = (*tx_fifo)->ct_seg_index = cct->ct_seg_index;
  (*tx_fifo)->flags |= SVM_FIFO_F_SERVER_CT;
  (*rx_fifo)->flags |= SVM_FIFO_F_SERVER_CT;
  cct->client_rx_fifo = *tx_fifo;
  cct->client_tx_fifo = *rx_fifo;
  cct->client_rx_fifo->refcnt++;
  cct->client_tx_fifo->refcnt++;
  cct->segment_handle =
    ct_client_seg_handle (sct->segment_handle, cct->client_wrk);

  return 0;
}
