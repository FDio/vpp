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
#ifndef SRC_VNET_SESSION_SEGMENT_MANAGER_H_
#define SRC_VNET_SESSION_SEGMENT_MANAGER_H_

#include <svm/message_queue.h>
#include <vppinfra/lock.h>
#include <vppinfra/valloc.h>
#include <svm/fifo_segment.h>
#include <vnet/session/session_types.h>

typedef struct _segment_manager_props
{
  u32 rx_fifo_size;			/**< receive fifo size */
  u32 tx_fifo_size;			/**< transmit fifo size */
  u32 evt_q_size;			/**< event queue length */
  u32 prealloc_fifos;			/**< preallocated fifo pairs */
  u32 prealloc_fifo_hdrs;		/**< preallocated fifo hdrs */
  uword segment_size;			/**< first segment size */
  uword add_segment_size;		/**< additional segment size */
  u8 add_segment:1;			/**< can add new segments flag */
  u8 use_mq_eventfd:1;			/**< use eventfds for mqs flag */
  u8 reserved:6;			/**< reserved flags */
  u8 n_slices;				/**< number of fs slices/threads */
  ssvm_segment_type_t segment_type;	/**< seg type: if set to SSVM_N_TYPES,
					     private segments are used */
  u32 max_fifo_size;			/**< max fifo size */
  u8 high_watermark;			/**< memory usage high watermark % */
  u8 low_watermark;			/**< memory usage low watermark % */
  u8 pct_first_alloc;			/**< pct of fifo size to alloc */
  u8 huge_page;				/**< use hugepage */
} segment_manager_props_t;

typedef enum seg_manager_flag_
{
  SEG_MANAGER_F_DETACHED = 1 << 0,
  SEG_MANAGER_F_DETACHED_LISTENER = 1 << 1,
} seg_manager_flag_t;

typedef struct _segment_manager
{
  /** Pool of segments allocated by this manager */
  fifo_segment_t *segments;

  /** rwlock that protects the segments pool */
  clib_rwlock_t segments_rwlock;

  /** Owner app worker index */
  u32 app_wrk_index;

  /**
   * First segment should not be deleted unless segment manger is deleted.
   * This also indicates that the segment manager is the first to have been
   * allocated for the app.
   */
  u8 first_is_protected;

  /**
   * App event queue allocated in first segment
   */
  svm_msg_q_t *event_queue;

  u8 flags;

  u32 max_fifo_size;
  u8 high_watermark;
  u8 low_watermark;
} segment_manager_t;

#define SEGMENT_MANAGER_INVALID_APP_INDEX ((u32) ~0)
#define SEGMENT_INVALID_HANDLE ((u64) ~0)

segment_manager_t *segment_manager_alloc (void);
int segment_manager_init (segment_manager_t * sm);
int segment_manager_init_first (segment_manager_t * sm);

/**
 * Cleanup segment manager
 *
 * @param sm	segment manager to be freed
 */
void segment_manager_free (segment_manager_t * sm);
void segment_manager_free_safe (segment_manager_t *sm);

/**
 * Initiate segment manager cleanup
 *
 * @param sm	segment manager to be freed
 */
void segment_manager_init_free (segment_manager_t * sm);
segment_manager_t *segment_manager_get (u32 index);
segment_manager_t *segment_manager_get_if_valid (u32 index);
u32 segment_manager_index (segment_manager_t * sm);

/**
 * Add segment without lock
 *
 * @param sm		Segment manager
 * @param segment_size	Size of segment to be added
 * @param notify_app	Flag set if app notification requested
 */
int segment_manager_add_segment (segment_manager_t *sm, uword segment_size,
				 u8 notify_app);

/**
 * Add segment with lock
 *
 * @param sm		Segment manager
 * @param segment_size	Size of segment to be added
 * @param flags		Flags to be set on segment
 */
int segment_manager_add_segment2 (segment_manager_t *sm, uword segment_size,
				  u8 flags);
void segment_manager_del_segment (segment_manager_t * sm,
				  fifo_segment_t * fs);
void segment_manager_lock_and_del_segment (segment_manager_t * sm,
					   u32 fs_index);
fifo_segment_t *segment_manager_get_segment (segment_manager_t * sm,
					     u32 segment_index);
fifo_segment_t *segment_manager_get_segment_w_handle (u64 sh);
fifo_segment_t *segment_manager_get_segment_w_lock (segment_manager_t * sm,
						    u32 segment_index);
int segment_manager_add_first_segment (segment_manager_t * sm,
				       u32 segment_size);
u64 segment_manager_make_segment_handle (u32 segment_manager_index,
					 u32 segment_index);
u64 segment_manager_segment_handle (segment_manager_t * sm,
				    fifo_segment_t * segment);
void segment_manager_segment_reader_unlock (segment_manager_t * sm);

int segment_manager_alloc_session_fifos (segment_manager_t * sm,
					 u32 thread_index,
					 svm_fifo_t ** rx_fifo,
					 svm_fifo_t ** tx_fifo);
int segment_manager_try_alloc_fifos (fifo_segment_t * fs,
				     u32 thread_index,
				     u32 rx_fifo_size, u32 tx_fifo_size,
				     svm_fifo_t ** rx_fifo,
				     svm_fifo_t ** tx_fifo);
void segment_manager_dealloc_fifos (svm_fifo_t * rx_fifo,
				    svm_fifo_t * tx_fifo);
void segment_manager_detach_fifo (segment_manager_t *sm, svm_fifo_t **f);
void segment_manager_attach_fifo (segment_manager_t *sm, svm_fifo_t **f,
				  session_t *s);

void segment_manager_set_watermarks (segment_manager_t * sm,
				     u8 high_watermark, u8 low_watermark);

u8 segment_manager_has_fifos (segment_manager_t * sm);

svm_msg_q_t *segment_manager_alloc_queue (fifo_segment_t * fs,
					  segment_manager_props_t * props);
void segment_manager_dealloc_queue (segment_manager_t * sm, svm_queue_t * q);
svm_msg_q_t *segment_manager_event_queue (segment_manager_t * sm);
u32 segment_manager_evt_q_expected_size (u32 q_size);

u8 segment_manager_app_detached (segment_manager_t * sm);
void segment_manager_app_detach (segment_manager_t * sm);

/**
 * Cleanup segment manager sessions
 *
 * Initiates disconnects for all sessions 'owned' by a segment manager by
 * leveraging the backpointers that fifos keep.
 *
 * @param sm	segment manager whose sessions are to be disconnected
 */
void segment_manager_del_sessions (segment_manager_t * sm);
void segment_manager_del_sessions_filter (segment_manager_t *sm,
					  session_state_t *states);
void segment_manager_format_sessions (segment_manager_t * sm, int verbose);

void segment_manager_main_init (void);

segment_manager_props_t *segment_manager_props_init (segment_manager_props_t *
						     sm);

static inline void
segment_manager_parse_segment_handle (u64 segment_handle, u32 * sm_index,
				      u32 * segment_index)
{
  *sm_index = segment_handle >> 32;
  *segment_index = segment_handle & 0xFFFFFFFF;
}

#endif /* SRC_VNET_SESSION_SEGMENT_MANAGER_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
