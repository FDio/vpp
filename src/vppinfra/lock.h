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

#ifndef included_clib_lock_h
#define included_clib_lock_h

#include <vppinfra/clib.h>

#if __x86_64__
#define CLIB_PAUSE() __builtin_ia32_pause ()
#else
#define CLIB_PAUSE()
#endif

#if CLIB_DEBUG > 1
#define CLIB_LOCK_DBG(_p)				\
do {							\
    (*_p)->frame_address = __builtin_frame_address (0);	\
    (*_p)->pid = getpid ();				\
    (*_p)->thread_index = os_get_thread_index ();	\
} while (0)
#define CLIB_LOCK_DBG_CLEAR(_p)				\
do {							\
    (*_p)->frame_address = 0;				\
    (*_p)->pid = 0;					\
    (*_p)->thread_index = 0;				\
} while (0)
#else
#define CLIB_LOCK_DBG(_p)
#define CLIB_LOCK_DBG_CLEAR(_p)
#endif

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 lock;
#if CLIB_DEBUG > 0
  pid_t pid;
  uword thread_index;
  void *frame_address;
#endif
} *clib_spinlock_t;

static inline void
clib_spinlock_init (clib_spinlock_t * p)
{
  *p = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES);
  memset ((void *) *p, 0, CLIB_CACHE_LINE_BYTES);
}

static inline void
clib_spinlock_free (clib_spinlock_t * p)
{
  if (*p)
    {
      clib_mem_free ((void *) *p);
      *p = 0;
    }
}

static_always_inline void
clib_spinlock_lock (clib_spinlock_t * p)
{
  while (clib_atomic_test_and_set (&(*p)->lock))
    CLIB_PAUSE ();
  CLIB_LOCK_DBG (p);
}

static_always_inline void
clib_spinlock_lock_if_init (clib_spinlock_t * p)
{
  if (PREDICT_FALSE (*p != 0))
    clib_spinlock_lock (p);
}

static_always_inline void
clib_spinlock_unlock (clib_spinlock_t * p)
{
  CLIB_LOCK_DBG_CLEAR (p);
  /* Make sure all writes are complete before releasing the lock */
  CLIB_MEMORY_BARRIER ();
  (*p)->lock = 0;
}

static_always_inline void
clib_spinlock_unlock_if_init (clib_spinlock_t * p)
{
  if (PREDICT_FALSE (*p != 0))
    clib_spinlock_unlock (p);
}

/*
 * Readers-Writer Lock
 */

typedef struct clib_rw_lock_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 n_readers;
  volatile u32 n_readers_lock;
  volatile u32 writer_lock;
#if CLIB_DEBUG > 0
  pid_t pid;
  uword thread_index;
  void *frame_address;
#endif
} *clib_rwlock_t;

always_inline void
clib_rwlock_init (clib_rwlock_t * p)
{
  *p = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES);
  memset ((void *) *p, 0, CLIB_CACHE_LINE_BYTES);
}

always_inline void
clib_rwlock_free (clib_rwlock_t * p)
{
  if (*p)
    {
      clib_mem_free ((void *) *p);
      *p = 0;
    }
}

always_inline void
clib_rwlock_reader_lock (clib_rwlock_t * p)
{
  while (clib_atomic_test_and_set (&(*p)->n_readers_lock))
    CLIB_PAUSE ();

  (*p)->n_readers += 1;
  if ((*p)->n_readers == 1)
    {
      while (clib_atomic_test_and_set (&(*p)->writer_lock))
	CLIB_PAUSE ();
    }
  CLIB_MEMORY_BARRIER ();
  (*p)->n_readers_lock = 0;

  CLIB_LOCK_DBG (p);
}

always_inline void
clib_rwlock_reader_unlock (clib_rwlock_t * p)
{
  ASSERT ((*p)->n_readers > 0);
  CLIB_LOCK_DBG_CLEAR (p);

  while (clib_atomic_test_and_set (&(*p)->n_readers_lock))
    CLIB_PAUSE ();

  (*p)->n_readers -= 1;
  if ((*p)->n_readers == 0)
    {
      CLIB_MEMORY_BARRIER ();
      (*p)->writer_lock = 0;
    }

  CLIB_MEMORY_BARRIER ();
  (*p)->n_readers_lock = 0;
}

always_inline void
clib_rwlock_writer_lock (clib_rwlock_t * p)
{
  while (clib_atomic_test_and_set (&(*p)->writer_lock))
    CLIB_PAUSE ();
  CLIB_LOCK_DBG (p);
}

always_inline void
clib_rwlock_writer_unlock (clib_rwlock_t * p)
{
  CLIB_LOCK_DBG_CLEAR (p);
  CLIB_MEMORY_BARRIER ();
  (*p)->writer_lock = 0;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
