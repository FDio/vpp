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
  props->max_fifo_size = sm_main.default_max_fifo_size;
  props->high_watermark = sm_main.default_high_watermark;
  props->low_watermark = sm_main.default_low_watermark;
  props->n_slices = vlib_num_workers () + 1;
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

static inline segm_numa_pool_t *
segm_numa_pool (segment_manager_t * sm, u8 numa)
{
  if (numa > CLIB_MAX_NUMAS)
    return 0;
  return &sm->numas[numa];
}

static fifo_segment_t *
segm_numa_alloc_segment (segm_numa_pool_t * snp)
{
  fifo_segment_t *fs;
  pool_get_zero (snp->segments, fs);
  return fs;
}

static void
segm_numa_free_segment (segm_numa_pool_t * snp, fifo_segment_t * fs)
{
  if (CLIB_DEBUG)
    clib_memset (fs, 0xfb, sizeof (*fs));
  pool_put (snp->segments, fs);
}

static inline fifo_segment_t *
segm_numa_segment (segm_numa_pool_t * snp, u32 seg_index)
{
  return pool_elt_at_index (snp->segments, seg_index);
}

static inline fifo_segment_t *
segm_numa_segment_safe (segm_numa_pool_t * snp, u32 seg_index)
{
  if (pool_is_free_index (snp->segments, seg_index))
    return 0;
  return pool_elt_at_index (snp->segments, seg_index);
}

static inline u32
segm_numa_segment_index (segm_numa_pool_t * snp, fifo_segment_t * fs)
{
  return (fs - snp->segments);
}

static inline u32
segment_manager_segment_index (segment_manager_t * sm, fifo_segment_t * fs)
{
  segm_numa_pool_t *snp = segm_numa_pool (sm, fifo_segment_numa (fs));
  return segm_numa_segment_index (snp, fs);
}

static inline u8
segm_segment_id_numa (u32 segment_id)
{
  return segment_id >> 29;
}

static inline u8
segm_segment_id_index (u32 segment_id)
{
  return segment_id & 0x1fffffff;
}

static inline u32
segm_numa_segment_id (segm_numa_pool_t * snp, fifo_segment_t * fs)
{
  return (snp->numa << 29 | segm_numa_segment_index (snp, fs));
}

static inline u32
segment_manager_segment_id (segment_manager_t * sm, fifo_segment_t * fs)
{
  segm_numa_pool_t *snp;
  u8 numa;

  numa = fifo_segment_numa (fs);
  snp = segm_numa_pool (sm, numa);

  return (numa << 29 | segm_numa_segment_index (snp, fs));
}

/**
 * Adds segment to segment manager's pool
 *
 * If needed a writer's lock is acquired before allocating a new segment
 * to avoid affecting any of the segments pool readers.
 */
segm_segment_id_t
segment_manager_add_segment (segment_manager_t * sm, uword segment_size)
{
  uword baseva = (uword) ~ 0ULL, alloc_size, page_size;
  segment_manager_main_t *smm = &sm_main;
  segment_manager_props_t *props;
  u32 rnd_margin = 128 << 10;
  segm_segment_id_t fs_id;
  segm_numa_pool_t *snp;
  fifo_segment_t *fs;
  u8 *seg_name, numa;
  int rv;

  props = segment_manager_properties_get (sm);

  /* Not configured for addition of new segments and not first */
  if (!props->add_segment && !segment_size)
    {
      clib_warning ("cannot allocate new segment");
      return SEGMENT_MANAGER_INVALID_ID;
    }

  /*
   * Allocate fifo segment and grab lock if needed
   */
  if (vlib_num_workers ())
    clib_rwlock_writer_lock (&sm->segments_rwlock);

  numa = os_get_numa_index ();
  snp = segm_numa_pool (sm, numa);
  fs = segm_numa_alloc_segment (snp);
//  pool_get_zero (sm->segments, fs);

  /*
   * Allocate ssvm segment
   */
  segment_size = segment_size ? segment_size : props->add_segment_size;
  page_size = clib_mem_get_page_size ();
  /* Protect against segment size u32 wrap */
  segment_size = clib_max (segment_size + page_size - 1, segment_size);
  segment_size = segment_size & ~(page_size - 1);

  if (props->segment_type != SSVM_SEGMENT_PRIVATE)
    {
      seg_name = format (0, "%d-%d%c", getpid (), smm->seg_name_counter++, 0);
      alloc_size = (uword) segment_size + rnd_margin;
      baseva = clib_valloc_alloc (&smm->va_allocator, alloc_size, 0);
      if (!baseva)
	{
	  clib_warning ("out of space for segments");
	  segm_numa_free_segment (snp, fs);
//        pool_put (sm->segments, fs);
	  goto done;
	}
    }
  else
    seg_name = format (0, "%s%c", "process-private", 0);

  fs->ssvm.ssvm_size = segment_size;
  fs->ssvm.name = seg_name;
  fs->ssvm.requested_va = baseva;
  fs->ssvm.numa = numa;

  if ((rv = ssvm_master_init (&fs->ssvm, props->segment_type)))
    {
      clib_warning ("svm_master_init ('%v', %u) failed", seg_name,
		    segment_size);

      if (props->segment_type != SSVM_SEGMENT_PRIVATE)
	clib_valloc_free (&smm->va_allocator, baseva);
      segm_numa_free_segment (snp, fs);
//      pool_put (sm->segments, fs);
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
//  fs_index = fs - sm->segments;
  fs_id = segm_numa_segment_id (snp, fs);

  /*
   * Set watermarks in segment
   */
  fs->h->high_watermark = sm->high_watermark;
  fs->h->low_watermark = sm->low_watermark;
  fs->h->pct_first_alloc = props->pct_first_alloc;
  fs->h->flags &= ~FIFO_SEGMENT_F_MEM_LIMIT;

done:

  if (vlib_num_workers ())
    clib_rwlock_writer_unlock (&sm->segments_rwlock);

  return fs_id;
}

/**
 * Remove segment without lock
 */
void
segment_manager_del_segment (segment_manager_t * sm, fifo_segment_t * fs)
{
  segment_manager_main_t *smm = &sm_main;
  segm_numa_pool_t *snp;

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

  snp = segm_numa_pool (sm, fifo_segment_numa (fs));
  segm_numa_free_segment (snp, fs);
}

/**
 * Removes segment after acquiring writer lock
 */
static inline void
segment_manager_lock_and_del_segment (segment_manager_t * sm,
				      segm_segment_id_t fs_id)
{
  fifo_segment_t *fs;
  u8 is_prealloc;

  clib_rwlock_writer_lock (&sm->segments_rwlock);
  fs = segment_manager_get_segment_w_id (sm, fs_id);
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
  u32 segment_index = segment_manager_segment_id (sm, segment);
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
segment_manager_get_segment_w_id (segment_manager_t * sm,
				  segm_segment_id_t segment_id)
{
  u8 numa = segm_segment_id_numa (segment_id);
  segm_numa_pool_t *snp;

  if (!(snp = segm_numa_pool (sm, numa)))
    return 0;

  return segm_numa_segment_safe (snp, segm_segment_id_index (segment_id));
}

fifo_segment_t *
segment_manager_get_segment_w_handle (u64 segment_handle)
{
  u32 sm_index, segment_id;
  segment_manager_t *sm;

  segment_manager_parse_segment_handle (segment_handle, &sm_index,
					&segment_id);
  if (!(sm = segment_manager_get (sm_index)))
    return 0;

  return segment_manager_get_segment_w_id (sm, segment_id);
}

/**
 * Reads a segment from the segment manager's pool and acquires reader lock
 *
 * Caller must drop the reader's lock by calling
 * @ref segment_manager_segment_reader_unlock once it finishes working with
 * the segment.
 */
fifo_segment_t *
segment_manager_get_segment_w_lock (segment_manager_t * sm,
				    segm_segment_id_t seg_id)
{
  clib_rwlock_reader_lock (&sm->segments_rwlock);
  return segment_manager_get_segment_w_id (sm, seg_id);
//  return pool_elt_at_index (sm->segments, segment_index);
}

void
segment_manager_segment_reader_unlock (segment_manager_t * sm)
{
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
  int i;

  pool_get_zero (smm->segment_managers, sm);
  clib_rwlock_init (&sm->segments_rwlock);

  vec_validate (sm->numas, CLIB_MAX_NUMAS - 1);
  for (i = 0; i < vec_len (sm->numas); i++)
    segm_numa_pool (sm, i)->numa = i;

  return sm;
}

/**
 * Initializes segment manager based on options provided.
 * Returns error if ssvm segment(s) allocation fails.
 */
int
segment_manager_init (segment_manager_t * sm)
{
  u32 rx_fifo_size, tx_fifo_size, pair_size;
  u32 rx_rounded_data_size, tx_rounded_data_size;
  uword first_seg_size;
  u32 prealloc_fifo_pairs;
  u64 approx_total_size, max_seg_size = ((u64) 1 << 32) - (128 << 10);
  segment_manager_props_t *props;
  fifo_segment_t *fs;
  segm_segment_id_t seg_id;
  u32 approx_segment_count;
  u32 i;

  props = segment_manager_properties_get (sm);
  first_seg_size = clib_max (props->segment_size,
			     sm_main.default_segment_size);
  prealloc_fifo_pairs = props->prealloc_fifos;

  sm->max_fifo_size = props->max_fifo_size ?
    props->max_fifo_size : sm_main.default_max_fifo_size;
  sm->max_fifo_size = clib_max (sm->max_fifo_size, 4096);

  segment_manager_set_watermarks (sm,
				  props->high_watermark,
				  props->low_watermark);

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
	  seg_id = segment_manager_add_segment (sm, max_seg_size);
	  if (seg_id == SEGMENT_MANAGER_INVALID_ID)
	    {
	      clib_warning ("Failed to preallocate segment %d", i);
	      return SESSION_ERROR_SEG_CREATE;
	    }

	  fs = segment_manager_get_segment_w_id (sm, seg_id);
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
    }
  else
    {
      seg_id = segment_manager_add_segment (sm, first_seg_size);
      if (seg_id == SEGMENT_MANAGER_INVALID_ID)
	{
	  clib_warning ("Failed to allocate segment");
	  return SESSION_ERROR_SEG_CREATE;
	}
      fs = segment_manager_get_segment_w_id (sm, seg_id);
      sm->event_queue = segment_manager_alloc_queue (fs, props);
    }

  sm->first_seg_id = seg_id;

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

static fifo_segment_t *
find_max_free_segment (segment_manager_t * sm, u32 thread_index)
{
  fifo_segment_t *cur, *fs = 0;
  uword free_bytes, max_free_bytes = 0;

  clib_rwlock_reader_lock (&sm->segments_rwlock);
  /* *INDENT-OFF* */
  pool_foreach (cur, sm->segments, ({
    if ((free_bytes = fifo_segment_free_bytes (cur)) > max_free_bytes)
      {
        max_free_bytes = free_bytes;
        fs = cur;
      }
  }));
  /* *INDENT-ON* */
  clib_rwlock_reader_unlock (&sm->segments_rwlock);

  return fs;
}

u32
segment_manager_index (segment_manager_t * sm)
{
  return sm - sm_main.segment_managers;
}

u8
segm_numa_pool_has_fifos (segm_numa_pool_t * snp)
{
  fifo_segment_t *fs;

  /* *INDENT-OFF* */
  pool_foreach (fs, snp->segments, {
    if (fifo_segment_has_fifos (fs))
      return 1;
  });
  /* *INDENT-ON* */

  return 0;
}

u8
segment_manager_has_fifos (segment_manager_t * sm)
{
  segm_numa_pool_t *snp;
  u8 has_fifos = 0;

  clib_rwlock_reader_lock (&sm->segments_rwlock);

  vec_foreach (snp, sm->numas) if (segm_numa_pool_has_fifos (snp))
    {
      has_fifos = 1;
      break;
    }

  clib_rwlock_reader_unlock (&sm->segments_rwlock);

  return has_fifos;
}

void
segm_numa_close_sessions (segm_numa_pool_t * snp)
{
  session_handle_t *handles = 0, *handle;
  fifo_segment_t *fs;
  session_t *session;
  int slice_index;
  svm_fifo_t *f;

  /* *INDENT-OFF* */
  pool_foreach (fs, snp->segments, {
    for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
      {
        f = fifo_segment_get_slice_fifo_list (fs, slice_index);

        /*
	 * Grab handles of all active fifos that should be closed
         */
        while (f)
          {
            session = session_get_if_valid (f->master_session_index,
                                            f->master_thread_index);
            if (session)
              vec_add1 (handles, session_handle (session));
            f = f->next;
          }
      }
  });
  /* *INDENT-ON* */

  vec_foreach (handle, handles)
    session_close (session_get_from_handle (*handle));
}

/**
 * Initiate disconnects for all sessions 'owned' by a segment manager
 */
void
segment_manager_del_sessions (segment_manager_t * sm)
{
  segm_numa_pool_t *snp;

  clib_rwlock_reader_lock (&sm->segments_rwlock);

  vec_foreach (snp, sm->numas) segm_numa_close_sessions (snp);

  clib_rwlock_reader_unlock (&sm->segments_rwlock);
}

int
segment_manager_try_alloc_fifos (fifo_segment_t * fifo_segment,
				 u32 thread_index,
				 u32 rx_fifo_size, u32 tx_fifo_size,
				 svm_fifo_t ** rx_fifo, svm_fifo_t ** tx_fifo)
{
  rx_fifo_size = clib_max (rx_fifo_size, sm_main.default_fifo_size);
  *rx_fifo = fifo_segment_alloc_fifo_w_slice (fifo_segment, thread_index,
					      rx_fifo_size,
					      FIFO_SEGMENT_RX_FIFO);

  tx_fifo_size = clib_max (tx_fifo_size, sm_main.default_fifo_size);
  *tx_fifo = fifo_segment_alloc_fifo_w_slice (fifo_segment, thread_index,
					      tx_fifo_size,
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
				     u32 thread_index,
				     svm_fifo_t ** rx_fifo,
				     svm_fifo_t ** tx_fifo)
{
  segm_segment_id_t fs_id, new_fs_id;
  segment_manager_props_t *props;
  int alloc_fail = 1, rv = 0;
  fifo_segment_t *fs = 0;
  u8 added_a_segment = 0;
  u64 fs_handle;
  u32 sm_index;

  props = segment_manager_properties_get (sm);

  /*
   * Find the first free segment to allocate the fifos in
   */
  fs = find_max_free_segment (sm, thread_index);

  if (fs)
    {
      clib_rwlock_reader_lock (&sm->segments_rwlock);
      alloc_fail = segment_manager_try_alloc_fifos (fs, thread_index,
						    props->rx_fifo_size,
						    props->tx_fifo_size,
						    rx_fifo, tx_fifo);
      /* On success, keep lock until fifos are initialized */
      if (!alloc_fail)
	goto alloc_success;

      segment_manager_segment_reader_unlock (sm);
    }
  else
    {
      alloc_fail = 1;
    }

alloc_check:

  if (!alloc_fail)
    {

    alloc_success:

      ASSERT (rx_fifo && tx_fifo);
      sm_index = segment_manager_index (sm);
      fs_id = segment_manager_segment_id (sm, fs);
      (*tx_fifo)->segment_manager = sm_index;
      (*rx_fifo)->segment_manager = sm_index;
      (*tx_fifo)->segment_index = fs_id;
      (*rx_fifo)->segment_index = fs_id;

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
      new_fs_id = segment_manager_add_segment (sm, 0);
      if (new_fs_id == SEGMENT_MANAGER_INVALID_ID)
	{
	  clib_warning ("Failed to add new segment");
	  return SESSION_ERROR_SEG_CREATE;
	}
      fs = segment_manager_get_segment_w_lock (sm, new_fs_id);
      alloc_fail = segment_manager_try_alloc_fifos (fs, thread_index,
						    props->rx_fifo_size,
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
  segm_segment_id_t seg_id;

  if (!rx_fifo || !tx_fifo)
    return;

  /* It's possible to have no segment manager if the session was removed
   * as result of a detach. */
  if (!(sm = segment_manager_get_if_valid (rx_fifo->segment_manager)))
    return;

  seg_id = rx_fifo->segment_index;
  fs = segment_manager_get_segment_w_lock (sm, seg_id);
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
      if (seg_id != sm->first_seg_id || !sm->first_is_protected)
	segment_manager_lock_and_del_segment (sm, seg_id);

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
  fifo_segment_update_free_bytes (segment);
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
  sm->default_max_fifo_size = 4 << 20;
  sm->default_high_watermark = 80;
  sm->default_low_watermark = 50;
}

static clib_error_t *
segment_manager_show_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  segment_manager_main_t *smm = &sm_main;
  u8 show_segments = 0, verbose = 0;
  segment_manager_t *sm;
  segm_numa_pool_t *snp;
  fifo_segment_t *seg;
  app_worker_t *app_wrk;
  application_t *app;
  u8 custom_logic;

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
      vlib_cli_output (vm, "%-6s%=10s%=10s%=13s%=11s%=11s%=12s",
		       "Index", "AppIndex", "Segments", "MaxFifoSize",
		       "HighWater", "LowWater", "FifoTuning");

      /* *INDENT-OFF* */
      pool_foreach (sm, smm->segment_managers, ({
        app_wrk = app_worker_get_if_valid (sm->app_wrk_index);
        app = app_wrk ? application_get (app_wrk->app_index) : 0;
        custom_logic = (app && (app->cb_fns.fifo_tuning_callback)) ? 1 : 0;

	vlib_cli_output (vm, "%-6d%=10d%=10d%=13U%=11d%=11d%=12s",
                         segment_manager_index (sm),
			 sm->app_wrk_index, pool_elts (sm->segments),
                         format_memory_size, sm->max_fifo_size,
                         sm->high_watermark, sm->low_watermark,
                         custom_logic ? "custom" : "none");
      }));
      /* *INDENT-ON* */

    }
  if (show_segments)
    {
      vlib_cli_output (vm, "%U", format_fifo_segment, 0, verbose);

      /* *INDENT-OFF* */
      pool_foreach (sm, smm->segment_managers, ({
        clib_rwlock_reader_lock (&sm->segments_rwlock);

        vec_foreach (snp, sm->numas)
          {
            pool_foreach (seg, snp->segments, ({
              vlib_cli_output (vm, "%U", format_fifo_segment, seg, verbose);
            }));
          }

        clib_rwlock_reader_unlock (&sm->segments_rwlock);
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
  pool_foreach (fs, sm->segments, ({
    for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
      {
        f = fifo_segment_get_slice_fifo_list (fs, slice_index);
        while (f)
          {
            u32 session_index, thread_index;
            session_t *session;

            session_index = f->master_session_index;
            thread_index = f->master_thread_index;

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

            f = f->next;
          }
        vec_free (s);
      }
  }));
  /* *INDENT-ON* */

  clib_rwlock_reader_unlock (&sm->segments_rwlock);
}

void
segment_manager_set_watermarks (segment_manager_t * sm,
				u8 high_watermark, u8 low_watermark)
{
  ASSERT (high_watermark >= 0 && high_watermark <= 100 &&
	  low_watermark >= 0 && low_watermark <= 100 &&
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
