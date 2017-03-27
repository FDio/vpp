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

typedef volatile u32 *clib_spinlock_t;

static_always_inline void
clib_spinlock_init (clib_spinlock_t * lock)
{

  *lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
				  CLIB_CACHE_LINE_BYTES);
  memset ((void *) *lock, 0, CLIB_CACHE_LINE_BYTES);
}

static_always_inline void
clib_spinlock_free (clib_spinlock_t * lock)
{
  if (*lock)
    {
      clib_mem_free ((void *) *lock);
      *lock = 0;
    }
}

static_always_inline void
clib_spinlock_lock (clib_spinlock_t * lock)
{
  while (__sync_lock_test_and_set (*lock, 1))
#if __x86_64__
    __builtin_ia32_pause ()
#endif
      ;
}

static_always_inline void
clib_spinlock_lock_if_init (clib_spinlock_t * lock)
{
  if (PREDICT_FALSE (*lock != 0))
    clib_spinlock_lock (lock);
}

static_always_inline void
clib_spinlock_unlock (clib_spinlock_t * lock)
{
  if (PREDICT_FALSE (*lock != 0))
    **lock = 0;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
