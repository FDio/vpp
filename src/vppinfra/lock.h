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
#include <vppinfra/atomics.h>

#if __x86_64__
#define CLIB_PAUSE() __builtin_ia32_pause ()
#elif defined (__aarch64__) || defined (__arm__)
#define CLIB_PAUSE() __asm__ ("yield")
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

#define CLIB_SPINLOCK_IS_LOCKED(_p) (*(_p))->lock
#define CLIB_SPINLOCK_ASSERT_LOCKED(_p) ASSERT(CLIB_SPINLOCK_IS_LOCKED((_p)))

struct clib_spinlock_s
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 lock;
#if CLIB_DEBUG > 0
  pid_t pid;
  uword thread_index;
  void *frame_address;
#endif
};

typedef struct clib_spinlock_s *clib_spinlock_t;

static inline void
clib_spinlock_init (clib_spinlock_t * p)
{
  *p = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES);
  clib_memset ((void *) *p, 0, CLIB_CACHE_LINE_BYTES);
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

#define CLIB_SPINLOCK_LOCK(x)                                                 \
  {                                                                           \
    typeof (x) __free = 0;                                                    \
    while (!__atomic_compare_exchange_n (&(x), &__free, 1, 0,                 \
					 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) \
      {                                                                       \
	while (__atomic_load_n (&(x), __ATOMIC_RELAXED))                      \
	  CLIB_PAUSE ();                                                      \
	__free = 0;                                                           \
      }                                                                       \
  }

#define CLIB_SPINLOCK_TRYLOCK(x)                                              \
  ({                                                                          \
    typeof (x) __free = 0;                                                    \
    __atomic_compare_exchange_n (&(x), &__free, 1, 0, __ATOMIC_ACQUIRE,       \
				 __ATOMIC_RELAXED);                           \
  })

#define CLIB_SPINLOCK_UNLOCK(x) __atomic_store_n (&(x), 0, __ATOMIC_RELEASE)

static_always_inline void
clib_spinlock_lock (clib_spinlock_t * p)
{
  CLIB_SPINLOCK_LOCK ((*p)->lock);
  CLIB_LOCK_DBG (p);
}

static_always_inline int
clib_spinlock_trylock (clib_spinlock_t * p)
{
  int rv = CLIB_SPINLOCK_TRYLOCK ((*p)->lock);
  if (rv)
    CLIB_LOCK_DBG (p);
  return rv;
}

static_always_inline void
clib_spinlock_lock_if_init (clib_spinlock_t * p)
{
  if (PREDICT_FALSE (*p != 0))
    clib_spinlock_lock (p);
}

static_always_inline int
clib_spinlock_trylock_if_init (clib_spinlock_t * p)
{
  if (PREDICT_FALSE (*p != 0))
    return clib_spinlock_trylock (p);
  return 1;
}

static_always_inline void
clib_spinlock_unlock (clib_spinlock_t * p)
{
  CLIB_LOCK_DBG_CLEAR (p);
  /* Make sure all reads/writes are complete before releasing the lock */
  CLIB_SPINLOCK_UNLOCK ((*p)->lock);
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
  /* -1 when W lock held, > 0 when R lock held */
  volatile i32 rw_cnt;
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
  clib_memset ((void *) *p, 0, CLIB_CACHE_LINE_BYTES);
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
  i32 cnt;
  do
    {
      /* rwlock held by a writer */
      while ((cnt = clib_atomic_load_relax_n (&(*p)->rw_cnt)) < 0)
	CLIB_PAUSE ();
    }
  while (!clib_atomic_cmp_and_swap_acq_relax_n
	 (&(*p)->rw_cnt, &cnt, cnt + 1, 1));
  CLIB_LOCK_DBG (p);
}

always_inline void
clib_rwlock_reader_unlock (clib_rwlock_t * p)
{
  ASSERT ((*p)->rw_cnt > 0);
  CLIB_LOCK_DBG_CLEAR (p);
  clib_atomic_fetch_sub_rel (&(*p)->rw_cnt, 1);
}

always_inline void
clib_rwlock_writer_lock (clib_rwlock_t * p)
{
  i32 cnt = 0;
  do
    {
      /* rwlock held by writer or reader(s) */
      while ((cnt = clib_atomic_load_relax_n (&(*p)->rw_cnt)) != 0)
	CLIB_PAUSE ();
    }
  while (!clib_atomic_cmp_and_swap_acq_relax_n (&(*p)->rw_cnt, &cnt, -1, 1));
  CLIB_LOCK_DBG (p);
}

always_inline void
clib_rwlock_writer_unlock (clib_rwlock_t * p)
{
  CLIB_LOCK_DBG_CLEAR (p);
  clib_atomic_release (&(*p)->rw_cnt);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
