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
  while (__sync_lock_test_and_set (&(*p)->lock, 1))
#if __x86_64__
    __builtin_ia32_pause ()
#endif
      ;
#if CLIB_DEBUG > 0
  (*p)->frame_address = __builtin_frame_address (0);
  (*p)->pid = getpid ();
  (*p)->thread_index = os_get_thread_index ();
#endif
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
  (*p)->lock = 0;
#if CLIB_DEBUG > 0
  (*p)->frame_address = 0;
  (*p)->pid = 0;
  (*p)->thread_index = 0;
#endif
}

static_always_inline void
clib_spinlock_unlock_if_init (clib_spinlock_t * p)
{
  if (PREDICT_FALSE (*p != 0))
    clib_spinlock_unlock (p);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
