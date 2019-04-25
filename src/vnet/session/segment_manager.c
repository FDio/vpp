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
  clib_valloc_main_t va_allocator;	/**< Virtual address allocator */
  u32 seg_name_counter;			/**< Counter for segment names */

  /*
   * Configuration
   */
  u32 default_fifo_size;		/**< default rx/tx fifo size */
  u32 default_segment_size;		/**< default fifo segment size */
  u32 default_app_mq_size;		/**< default app msg q size */
} segment_manager_main_t;

static segment_manager_main_t sm_main;

#define segment_manager_foreach_segment_w_lock(VAR, SM, BODY)		\
do {									\
    clib_rwlock_reader_lock (&(SM)->segments_rwlock);			\
    pool_foreach((VAR), ((SM)->segments), (BODY));			\
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
  return props;
}

static u8
segment_manager_app_detached (segment_manager_t * sm)
{
  return (sm->app_wrk_index == SEGMENT_MANAGER_INVALID_APP_INDEX);
}

void
segment_manager_app_detach (segment_manager_t * sm)
{
  sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
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
int
segment_manager_add_segment (segment_manager_t * sm, u32 segment_size)
{
  segment_manager_main_t *smm = &sm_main;
  u32 rnd_margin = 128 << 10, fs_index = ~0, page_size;
  uword baseva = (uword) ~ 0ULL, alloc_size;
  segment_manager_props_t *props;
  fifo_segment_t *fs;
  u8 *seg_name;
  int rv;

  props = segment_manager_properties_get (sm);

  /* Not configured for addition of new segments and not first */
  if (!props->add_segment && !segment_size)
    {
      clib_warning ("cannot allocate new segment");
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /*
   * Allocate fifo segment and lock if needed
   */
  if (vlib_num_workers ())
    clib_rwlock_writer_lock (&sm->segments_rwlock);

  pool_get_zero (sm->segments, fs);

  /*
   * Initialize ssvm segment and svm fifo private header
   */
  segment_size = segment_size ? segment_size : props->add_segment_size;
  page_size = clib_mem_get_page_size ();
  segment_size = (segment_size + page_size - 1) & ~(page_size - 1);
  if (props->segment_type != SSVM_SEGMENT_PRIVATE)
    {
      seg_name = format (0, "%d-%d%c", getpid (), smm->seg_name_counter++, 0);
      alloc_size = (uword) segment_size + rnd_margin;
      baseva = clib_valloc_alloc (&smm->va_allocator, alloc_size, 0);
      if (!baseva)
	{
	  clib_warning ("out of space for segments");
	  pool_put (sm->segments, fs);
	  goto done;
	}
    }
  else
    seg_name = format (0, "%s%c", "process-private-segment", 0);

  fs->ssvm.ssvm_size = segment_size;
  fs->ssvm.name = seg_name;
  fs->ssvm.requested_va = baseva;

  if ((rv = ssvm_master_init (&fs->ssvm, props->segment_type)))
    {
      clib_warning ("svm_master_init ('%v', %u) failed", seg_name,
		    segment_size);

      if (props->segment_type != SSVM_SEGMENT_PRIVATE)
	clib_valloc_free (&smm->va_allocator, baseva);
      pool_put (sm->segments, fs);
      goto done;
    }

  fifo_segment_init (fs);

  /*
   * Save segment index before dropping lock, if any held
   */
  fs_index = fs - sm->segments;

done:

  if (vlib_num_workers ())
    clib_rwlock_writer_unlock (&sm->segments_rwlock);

  return fs_index;
}

/**
 * Remove segment without lock
 */
void
segment_manager_del_segment (segment_manager_t * sm, fifo_segment_t * fs)
{
  segment_manager_main_t *smm = &sm_main;

  if (ssvm_type (&fs->ssvm) != SSVM_SEGMENT_PRIVATE)
    {
      clib_valloc_free (&smm->va_allocator, fs->ssvm.requested_va);

      if (sm->app_wrk_index != SEGMENT_MANAGER_INVALID_APP_INDEX)
	{
	  app_worker_t *app_wrk;
	  u64 segment_handle;
	  app_wrk = app_worker_get (sm->app_wrk_index);
	  segment_handle = segment_manager_segment_handle (sm, fs);
	  app_worker_del_segment_notify (app_wrk, segment_handle);
	}
    }

  ssvm_delete (&fs->ssvm);

  if (CLIB_DEBUG)
    clib_memset (fs, 0xfb, sizeof (*fs));
  pool_put (sm->segments, fs);
}

/**
 * Removes segment after acquiring writer lock
 */
static inline void
segment_manager_lock_and_del_segment (segment_manager_t * sm, u32 fs_index)
{
  fifo_segment_t *fs;
  u8 is_prealloc;

  clib_rwlock_writer_lock (&sm->segments_rwlock);
  fs = segment_manager_get_segment (sm, fs_index);
  is_prealloc = fifo_segment_flags (fs) & FIFO_SEGMENT_F_IS_PREALLOCATED;
  if (is_prealloc && !segment_manager_app_detached (sm))
    {
      clib_rwlock_writer_unlock (&sm->segments_rwlock);
      return;
    }

  segment_manager_del_segment (sm, fs);
  clib_rwlock_writer_unlock (&sm->segments_rwlock);
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

static void
segment_manager_parse_segment_handle (u64 segment_handle, u32 * sm_index,
				      u32 * segment_index)
{
  *sm_index = segment_handle >> 32;
  *segment_index = segment_handle & 0xFFFFFFFF;
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
segment_manager_segment_reader_unlock (segment_manager_t * sm)
{
  ASSERT (sm->segments_rwlock->n_readers > 0);
  clib_rwlock_reader_unlock (&sm->segments_rwlock);
}

void
segment_manager_segment_writer_unlock (segment_manager_t * sm)
{
  clib_rwlock_writer_unlock (&sm->segments_rwlock);
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

/**
 * Initializes segment manager based on options provided.
 * Returns error if ssvm segment(s) allocation fails.
 */
int
segment_manager_init (segment_manager_t * sm, u32 first_seg_size,
		      u32 prealloc_fifo_pairs)
{
  u32 rx_fifo_size, tx_fifo_size, pair_size;
  u32 rx_rounded_data_size, tx_rounded_data_size;
  u64 approx_total_size, max_seg_size = ((u64) 1 << 32) - (128 << 10);
  segment_manager_props_t *props;
  fifo_segment_t *segment;
  u32 approx_segment_count;
  int seg_index, i;

  props = segment_manager_properties_get (sm);
  first_seg_size = clib_max (first_seg_size, sm_main.default_segment_size);

  if (prealloc_fifo_pairs)
    {
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
	  seg_index = segment_manager_add_segment (sm, max_seg_size);
	  if (seg_index < 0)
	    {
	      clib_warning ("Failed to preallocate segment %d", i);
	      return seg_index;
	    }

	  segment = segment_manager_get_segment (sm, seg_index);
	  if (i == 0)
	    sm->event_queue = segment_manager_alloc_queue (segment, props);

	  fifo_segment_preallocate_fifo_pairs (segment,
					       props->rx_fifo_size,
					       props->tx_fifo_size,
					       &prealloc_fifo_pairs);
	  fifo_segment_flags (segment) = FIFO_SEGMENT_F_IS_PREALLOCATED;
	  if (prealloc_fifo_pairs == 0)
	    break;
	}
    }
  else
    {
      seg_index = segment_manager_add_segment (sm, first_seg_size);
      if (seg_index < 0)
	{
	  clib_warning ("Failed to allocate segment");
	  return seg_index;
	}
      segment = segment_manager_get_segment (sm, seg_index);
      sm->event_queue = segment_manager_alloc_queue (segment, props);
    }

  return 0;
}

/**
 * Cleanup segment manager.
 */
void
segment_manager_free (segment_manager_t * sm)
{
  segment_manager_main_t *smm = &sm_main;
  fifo_segment_t *fifo_segment;

  ASSERT (!segment_manager_has_fifos (sm)
	  && segment_manager_app_detached (sm));

  /* If we have empty preallocated segments that haven't been removed, remove
   * them now. Apart from that, the first segment in the first segment manager
   * is not removed when all fifos are removed. It can only be removed when
   * the manager is explicitly deleted/detached by the app. */
  clib_rwlock_writer_lock (&sm->segments_rwlock);

  /* *INDENT-OFF* */
  pool_foreach (fifo_segment, sm->segments, ({
    segment_manager_del_segment (sm, fifo_segment);
  }));
  /* *INDENT-ON* */

  clib_rwlock_writer_unlock (&sm->segments_rwlock);

  clib_rwlock_free (&sm->segments_rwlock);
  if (CLIB_DEBUG)
    clib_memset (sm, 0xfe, sizeof (*sm));
  pool_put (smm->segment_managers, sm);
}

void
segment_manager_init_free (segment_manager_t * sm)
{
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
  fifo_segment_t *fifo_segment;
  session_handle_t *handles = 0, *handle;
  session_t *session;
  svm_fifo_t *fifo;

  ASSERT (pool_elts (sm->segments) != 0);

  /* Across all fifo segments used by the server */
  /* *INDENT-OFF* */
  segment_manager_foreach_segment_w_lock (fifo_segment, sm, ({
    fifo = fifo_segment_get_fifo_list (fifo_segment);

    /*
     * Remove any residual sessions from the session lookup table
     * Don't bother deleting the individual fifos, we're going to
     * throw away the fifo segment in a minute.
     */
    while (fifo)
      {
	session = session_get_if_valid (fifo->master_session_index,
	                                fifo->master_thread_index);
	if (session)
	  vec_add1 (handles, session_handle (session));
	fifo = fifo->next;
      }

    /* Instead of removing the segment, test when cleaning up disconnected
     * sessions if the segment can be removed.
     */
  }));
  /* *INDENT-ON* */

  vec_foreach (handle, handles)
    session_close (session_get_from_handle (*handle));
}

int
segment_manager_try_alloc_fifos (fifo_segment_t * fifo_segment,
				 u32 rx_fifo_size, u32 tx_fifo_size,
				 svm_fifo_t ** rx_fifo, svm_fifo_t ** tx_fifo)
{
  rx_fifo_size = clib_max (rx_fifo_size, sm_main.default_fifo_size);
  *rx_fifo = fifo_segment_alloc_fifo (fifo_segment, rx_fifo_size,
				      FIFO_SEGMENT_RX_FIFO);

  tx_fifo_size = clib_max (tx_fifo_size, sm_main.default_fifo_size);
  *tx_fifo = fifo_segment_alloc_fifo (fifo_segment, tx_fifo_size,
				      FIFO_SEGMENT_TX_FIFO);

  if (*rx_fifo == 0)
    {
      /* This would be very odd, but handle it... */
      if (*tx_fifo != 0)
	{
	  fifo_segment_free_fifo (fifo_segment, *tx_fifo);
	  *tx_fifo = 0;
	}
      return -1;
    }
  if (*tx_fifo == 0)
    {
      if (*rx_fifo != 0)
	{
	  fifo_segment_free_fifo (fifo_segment, *rx_fifo);
	  *rx_fifo = 0;
	}
      return -1;
    }

  return 0;
}

int
segment_manager_alloc_session_fifos (segment_manager_t * sm,
				     svm_fifo_t ** rx_fifo,
				     svm_fifo_t ** tx_fifo)
{
  int alloc_fail = 1, rv = 0, new_fs_index;
  segment_manager_props_t *props;
  fifo_segment_t *fs = 0;
  u32 sm_index, fs_index;
  u8 added_a_segment = 0;
  u64 fs_handle;

  props = segment_manager_properties_get (sm);

  /*
   * Find the first free segment to allocate the fifos in
   */

  /* *INDENT-OFF* */
  segment_manager_foreach_segment_w_lock (fs, sm, ({
    alloc_fail = segment_manager_try_alloc_fifos (fs,
                                                  props->rx_fifo_size,
                                                  props->tx_fifo_size,
                                                  rx_fifo, tx_fifo);
    /* Exit with lock held, drop it after notifying app */
    if (!alloc_fail)
      goto alloc_success;
  }));
  /* *INDENT-ON* */

alloc_check:

  if (!alloc_fail)
    {

    alloc_success:

      ASSERT (rx_fifo && tx_fifo);
      sm_index = segment_manager_index (sm);
      fs_index = segment_manager_segment_index (sm, fs);
      (*tx_fifo)->segment_manager = sm_index;
      (*rx_fifo)->segment_manager = sm_index;
      (*tx_fifo)->segment_index = fs_index;
      (*rx_fifo)->segment_index = fs_index;

      if (added_a_segment)
	{
	  app_worker_t *app_wrk;
	  fs_handle = segment_manager_segment_handle (sm, fs);
	  app_wrk = app_worker_get (sm->app_wrk_index);
	  rv = app_worker_add_segment_notify (app_wrk, fs_handle);
	}
      /* Drop the lock after app is notified */
      segment_manager_segment_reader_unlock (sm);
      return rv;
    }

  /*
   * Allocation failed, see if we can add a new segment
   */
  if (props->add_segment)
    {
      if (added_a_segment)
	{
	  clib_warning ("Added a segment, still can't allocate a fifo");
	  segment_manager_segment_reader_unlock (sm);
	  return SESSION_ERROR_NEW_SEG_NO_SPACE;
	}
      if ((new_fs_index = segment_manager_add_segment (sm, 0)) < 0)
	{
	  clib_warning ("Failed to add new segment");
	  return SESSION_ERROR_SEG_CREATE;
	}
      fs = segment_manager_get_segment_w_lock (sm, new_fs_index);
      alloc_fail = segment_manager_try_alloc_fifos (fs, props->rx_fifo_size,
						    props->tx_fifo_size,
						    rx_fifo, tx_fifo);
      added_a_segment = 1;
      goto alloc_check;
    }
  else
    {
      clib_warning ("Can't add new seg and no space to allocate fifos!");
      return SESSION_ERROR_NO_SPACE;
    }
}

void
segment_manager_dealloc_fifos (svm_fifo_t * rx_fifo, svm_fifo_t * tx_fifo)
{
  segment_manager_t *sm;
  fifo_segment_t *fs;
  u32 segment_index;

  if (!rx_fifo || !tx_fifo)
    return;

  /* It's possible to have no segment manager if the session was removed
   * as result of a detach. */
  if (!(sm = segment_manager_get_if_valid (rx_fifo->segment_manager)))
    return;

  segment_index = rx_fifo->segment_index;
  fs = segment_manager_get_segment_w_lock (sm, segment_index);
  fifo_segment_free_fifo (fs, rx_fifo);
  fifo_segment_free_fifo (fs, tx_fifo);

  /*
   * Try to remove svm segment if it has no fifos. This can be done only if
   * the segment is not the first in the segment manager or if it is first
   * and it is not protected. Moreover, if the segment is first and the app
   * has detached from the segment manager, remove the segment manager.
   */
  if (!fifo_segment_has_fifos (fs))
    {
      segment_manager_segment_reader_unlock (sm);

      /* Remove segment if it holds no fifos or first but not protected */
      if (segment_index != 0 || !sm->first_is_protected)
	segment_manager_lock_and_del_segment (sm, segment_index);

      /* Remove segment manager if no sessions and detached from app */
      if (segment_manager_app_detached (sm)
	  && !segment_manager_has_fifos (sm))
	{
	  segment_manager_free (sm);
	}
    }
  else
    segment_manager_segment_reader_unlock (sm);
}

int
segment_manager_grow_fifo (segment_manager_t * sm, svm_fifo_t * f, u32 size)
{
  fifo_segment_t *fs;
  int rv;

  fs = segment_manager_get_segment_w_lock (sm, f->segment_index);
  rv = fifo_segment_grow_fifo (fs, f, size);
  segment_manager_segment_reader_unlock (sm);

  return rv;
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
  void *oldheap;

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

  oldheap = ssvm_push_heap (segment->ssvm.sh);
  q = svm_msg_q_alloc (cfg);
  ssvm_pop_heap (oldheap);

  if (props->use_mq_eventfd)
    {
      if (svm_msg_q_alloc_producer_eventfd (q))
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
segment_manager_main_init (segment_manager_main_init_args_t * a)
{
  segment_manager_main_t *sm = &sm_main;
  clib_valloc_chunk_t _ip, *ip = &_ip;

  ip->baseva = a->baseva;
  ip->size = a->size;

  clib_valloc_init (&sm->va_allocator, ip, 1 /* lock */ );

  sm->default_fifo_size = 1 << 12;
  sm->default_segment_size = 1 << 20;
  sm->default_app_mq_size = 128;
}

static clib_error_t *
segment_manager_show_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  segment_manager_main_t *smm = &sm_main;
  fifo_segment_t *seg;
  segment_manager_t *sm;
  u8 show_segments = 0, verbose = 0;
  char *address;
  size_t size;
  u32 active_fifos;
  u32 free_fifos;

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
		   pool_elts (smm->segment_managers));
  if (verbose && pool_elts (smm->segment_managers))
    {
      vlib_cli_output (vm, "%-10s%=15s%=12s", "Index", "App Index",
		       "Segments");

      /* *INDENT-OFF* */
      pool_foreach (sm, smm->segment_managers, ({
	vlib_cli_output (vm, "%-10d%=15d%=12d", segment_manager_index (sm),
			   sm->app_wrk_index, pool_elts (sm->segments));
      }));
      /* *INDENT-ON* */

    }
  if (show_segments)
    {
      vlib_cli_output (vm, "%-15s%15s%15s%15s%15s%15s", "Name", "Type",
		       "HeapSize (M)", "ActiveFifos", "FreeFifos", "Address");

      /* *INDENT-OFF* */
      pool_foreach (sm, smm->segment_managers, ({
	  segment_manager_foreach_segment_w_lock (seg, sm, ({
	    fifo_segment_info (seg, &address, &size);
	    active_fifos = fifo_segment_num_fifos (seg);
	    free_fifos = fifo_segment_num_free_fifos (seg, ~0 /* size */);
	    vlib_cli_output (vm, "%-15v%15U%15llu%15u%15u%15llx",
			     ssvm_name (&seg->ssvm), format_fifo_segment_type,
			     seg, size >> 20ULL, active_fifos, free_fifos,
			     address);
	    if (verbose)
	      vlib_cli_output (vm, "%U", format_fifo_segment, seg, verbose);
	  }));
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

void
segment_manager_format_sessions (segment_manager_t * sm, int verbose)
{
  fifo_segment_t *fifo_segment;
  vlib_main_t *vm = vlib_get_main ();
  app_worker_t *app_wrk;
  const u8 *app_name;
  u8 *s = 0;

  if (!sm)
    {
      if (verbose)
	vlib_cli_output (vm, "%-40s%-20s%-15s%-10s", "Connection", "App",
			 "API Client", "SegManager");
      else
	vlib_cli_output (vm, "%-40s%-20s", "Connection", "App");
      return;
    }

  app_wrk = app_worker_get (sm->app_wrk_index);
  app_name = application_name_from_index (app_wrk->app_index);

  clib_rwlock_reader_lock (&sm->segments_rwlock);

  /* *INDENT-OFF* */
  pool_foreach (fifo_segment, sm->segments, ({
    svm_fifo_t *fifo;
    u8 *str;

    fifo = fifo_segment_get_fifo_list (fifo_segment);
    while (fifo)
      {
        u32 session_index, thread_index;
        session_t *session;

        session_index = fifo->master_session_index;
        thread_index = fifo->master_thread_index;

        session = session_get (session_index, thread_index);
        str = format (0, "%U", format_session, session, verbose);

        if (verbose)
          s = format (s, "%-40s%-20s%-15u%-10u", str, app_name,
                      app_wrk->api_client_index, app_wrk->connects_seg_manager);
        else
          s = format (s, "%-40s%-20s", str, app_name);

        vlib_cli_output (vm, "%v", s);
        vec_reset_length (s);
        vec_free (str);

        fifo = fifo->next;
      }
    vec_free (s);
  }));
  /* *INDENT-ON* */

  clib_rwlock_reader_unlock (&sm->segments_rwlock);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
