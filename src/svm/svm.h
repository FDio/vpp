/*
 *------------------------------------------------------------------
 * svm.h - shared VM allocation, mmap(...MAP_FIXED...)
 * brain police
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef __included_svm_h__
#define __included_svm_h__

#include <pthread.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <svm/svm_common.h>

#define MMAP_PAGESIZE (clib_mem_get_page_size())

static inline void *
svm_mem_alloc (svm_region_t * rp, uword size)
{
  u8 *oldheap;
  ASSERT (rp->flags & SVM_FLAGS_MHEAP);
  u8 *rv;

  pthread_mutex_lock (&rp->mutex);
  oldheap = clib_mem_set_heap (rp->data_heap);
  rv = clib_mem_alloc (size);
  clib_mem_set_heap (oldheap);
  pthread_mutex_unlock (&rp->mutex);
  return (rv);
}

static inline void *
svm_mem_alloc_aligned_at_offset (svm_region_t * rp,
				 uword size, uword align, uword offset)
{
  u8 *oldheap;
  ASSERT (rp->flags & SVM_FLAGS_MHEAP);
  u8 *rv;

  pthread_mutex_lock (&rp->mutex);
  oldheap = clib_mem_set_heap (rp->data_heap);
  rv = clib_mem_alloc_aligned_at_offset (size, align, offset,
					 1 /* yes, call os_out_of_memory */ );
  clib_mem_set_heap (oldheap);
  pthread_mutex_unlock (&rp->mutex);
  return (rv);
}

static inline void
svm_mem_free (svm_region_t * rp, void *ptr)
{
  u8 *oldheap;
  ASSERT (rp->flags & SVM_FLAGS_MHEAP);

  pthread_mutex_lock (&rp->mutex);
  oldheap = clib_mem_set_heap (rp->data_heap);
  clib_mem_free (ptr);
  clib_mem_set_heap (oldheap);
  pthread_mutex_unlock (&rp->mutex);

}

static inline void *
svm_push_pvt_heap (svm_region_t * rp)
{
  u8 *oldheap;
  oldheap = clib_mem_set_heap (rp->region_heap);
  return ((void *) oldheap);
}

static inline void *
svm_push_data_heap (svm_region_t * rp)
{
  u8 *oldheap;
  oldheap = clib_mem_set_heap (rp->data_heap);
  return ((void *) oldheap);
}

static inline void
svm_pop_heap (void *oldheap)
{
  clib_mem_set_heap (oldheap);
}

#endif /* __included_svm_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
