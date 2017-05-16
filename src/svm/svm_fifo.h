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
#ifndef __included_ssvm_fifo_h__
#define __included_ssvm_fifo_h__

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <pthread.h>

/** Out-of-order segment */
typedef struct
{
  u32 next;	/**< Next linked-list element pool index */
  u32 prev;	/**< Previous linked-list element pool index */

  u32 start;	/**< Start of segment, normalized*/
  u32 length;	/**< Length of segment */
} ooo_segment_t;

format_function_t format_ooo_segment;
format_function_t format_ooo_list;

#define OOO_SEGMENT_INVALID_INDEX ((u32)~0)

typedef struct
{
  volatile u32 cursize;		/**< current fifo size */
  u32 nitems;
    CLIB_CACHE_LINE_ALIGN_MARK (end_cursize);

  volatile u32 has_event;	/**< non-zero if deq event exists */

  /* Backpointers */
  u32 master_session_index;
  u32 client_session_index;
  u8 master_thread_index;
  u8 client_thread_index;
  u32 segment_manager;
    CLIB_CACHE_LINE_ALIGN_MARK (end_shared);
  u32 head;
    CLIB_CACHE_LINE_ALIGN_MARK (end_consumer);

  /* producer */
  u32 tail;

  ooo_segment_t *ooo_segments;	/**< Pool of ooo segments */
  u32 ooos_list_head;		/**< Head of out-of-order linked-list */
  u32 ooos_newest;		/**< Last segment to have been updated */

    CLIB_CACHE_LINE_ALIGN_MARK (data);
} svm_fifo_t;

static inline u32
svm_fifo_max_dequeue (svm_fifo_t * f)
{
  return f->cursize;
}

static inline u32
svm_fifo_max_enqueue (svm_fifo_t * f)
{
  return f->nitems - svm_fifo_max_dequeue (f);
}

static inline u8
svm_fifo_has_ooo_data (svm_fifo_t * f)
{
  return f->ooos_list_head != OOO_SEGMENT_INVALID_INDEX;
}

/**
 * Sets fifo event flag.
 *
 * @return 1 if flag was not set.
 */
always_inline u8
svm_fifo_set_event (svm_fifo_t * f)
{
  /* Probably doesn't need to be atomic. Still, better avoid surprises */
  return __sync_lock_test_and_set (&f->has_event, 1) == 0;
}

/**
 * Unsets fifo event flag.
 */
always_inline void
svm_fifo_unset_event (svm_fifo_t * f)
{
  /* Probably doesn't need to be atomic. Still, better avoid surprises */
  __sync_lock_release (&f->has_event);
}

svm_fifo_t *svm_fifo_create (u32 data_size_in_bytes);
void svm_fifo_free (svm_fifo_t * f);

int svm_fifo_enqueue_nowait (svm_fifo_t * f, u32 max_bytes,
			     u8 * copy_from_here);
int svm_fifo_enqueue_with_offset (svm_fifo_t * f, u32 offset,
				  u32 required_bytes, u8 * copy_from_here);
int svm_fifo_dequeue_nowait (svm_fifo_t * f, u32 max_bytes, u8 * copy_here);

int svm_fifo_peek (svm_fifo_t * f, u32 offset, u32 max_bytes, u8 * copy_here);
int svm_fifo_dequeue_drop (svm_fifo_t * f, u32 max_bytes);
u32 svm_fifo_number_ooo_segments (svm_fifo_t * f);
ooo_segment_t *svm_fifo_first_ooo_segment (svm_fifo_t * f);
void svm_fifo_init_pointers (svm_fifo_t * f, u32 pointer);

format_function_t format_svm_fifo;

always_inline ooo_segment_t *
svm_fifo_newest_ooo_segment (svm_fifo_t * f)
{
  return f->ooo_segments + f->ooos_newest;
}

always_inline u32
ooo_segment_offset (svm_fifo_t * f, ooo_segment_t * s)
{
//  return ((f->nitems + s->fifo_position - f->tail) % f->nitems);
  return s->start;
}

always_inline u32
ooo_segment_end_offset (svm_fifo_t * f, ooo_segment_t * s)
{
//  return ((f->nitems + s->fifo_position + s->length - f->tail) % f->nitems);
  return s->start + s->length;
}

always_inline ooo_segment_t *
ooo_segment_get_prev (svm_fifo_t * f, ooo_segment_t * s)
{
  if (s->prev == OOO_SEGMENT_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (f->ooo_segments, s->prev);
}

#endif /* __included_ssvm_fifo_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
