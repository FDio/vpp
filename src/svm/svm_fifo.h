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

typedef enum
{
  SVM_FIFO_TAG_NOT_HELD = 0,
  SVM_FIFO_TAG_DEQUEUE,
  SVM_FIFO_TAG_ENQUEUE,
} svm_lock_tag_t;

/** Out-of-order segment */
typedef struct
{
  u32 next;	/**< Next linked-list element pool index */
  u32 prev;	/**< Previous linked-list element pool index */

  u32 fifo_position;	/**< Start of segment, normalized*/
  u32 length;		/**< Length of segment */
} ooo_segment_t;

#define OOO_SEGMENT_INVALID_INDEX ((u32)~0)

typedef struct
{
  pthread_mutex_t mutex;	/* 8 bytes */
  pthread_cond_t condvar;	/* 8 bytes */
  u32 owner_pid;
  svm_lock_tag_t tag;
  volatile u32 cursize;
  u32 nitems;

  /* Backpointers */
  u32 server_session_index;
  u32 client_session_index;
  u8 server_thread_index;
  u8 client_thread_index;
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

static inline int
svm_fifo_lock (svm_fifo_t * f, u32 pid, u32 tag, int nowait)
{
  if (PREDICT_TRUE (nowait == 0))
    pthread_mutex_lock (&f->mutex);
  else
    {
      if (pthread_mutex_trylock (&f->mutex))
	return -1;
    }
  f->owner_pid = pid;
  f->tag = tag;
  return 0;
}

static inline void
svm_fifo_unlock (svm_fifo_t * f)
{
  f->owner_pid = 0;
  f->tag = 0;
  CLIB_MEMORY_BARRIER ();
  pthread_mutex_unlock (&f->mutex);
}

static inline u32
svm_fifo_max_dequeue (svm_fifo_t * f)
{
  return f->cursize;
}

static inline u32
svm_fifo_max_enqueue (svm_fifo_t * f)
{
  return f->nitems - f->cursize;
}

static inline u8
svm_fifo_has_ooo_data (svm_fifo_t * f)
{
  return f->ooos_list_head != OOO_SEGMENT_INVALID_INDEX;
}

svm_fifo_t *svm_fifo_create (u32 data_size_in_bytes);

int svm_fifo_enqueue_nowait (svm_fifo_t * f, int pid, u32 max_bytes,
			     u8 * copy_from_here);

int svm_fifo_enqueue_with_offset (svm_fifo_t * f, int pid,
				  u32 offset, u32 required_bytes,
				  u8 * copy_from_here);

int svm_fifo_dequeue_nowait (svm_fifo_t * f, int pid, u32 max_bytes,
			     u8 * copy_here);

int svm_fifo_peek (svm_fifo_t * f, int pid, u32 offset, u32 max_bytes,
		   u8 * copy_here);
int svm_fifo_dequeue_drop (svm_fifo_t * f, int pid, u32 max_bytes);

always_inline ooo_segment_t *
svm_fifo_newest_ooo_segment (svm_fifo_t * f)
{
  return f->ooo_segments + f->ooos_newest;
}

always_inline u32
ooo_segment_offset (svm_fifo_t * f, ooo_segment_t * s)
{
  return ((f->nitems + s->fifo_position - f->tail) % f->nitems);
}

always_inline u32
ooo_segment_end_offset (svm_fifo_t * f, ooo_segment_t * s)
{
  return ((f->nitems + s->fifo_position + s->length - f->tail) % f->nitems);
}

#endif /* __included_ssvm_fifo_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
