/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009 Cisco and/or its affiliates.
 */

/*
 * svm.h - shared VM allocation, mmap(...MAP_FIXED...)
 * brain police
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
  clib_mem_heap_t *oldheap;
  ASSERT (rp->flags & SVM_FLAGS_MHEAP);
  u8 *rv;

  pthread_mutex_lock (&rp->mutex);
  oldheap = clib_mem_set_heap (rp->data_heap);
  rv = clib_mem_alloc (size);
  clib_mem_set_heap (oldheap);
  pthread_mutex_unlock (&rp->mutex);
  return (rv);
}

static inline void
svm_mem_free (svm_region_t * rp, void *ptr)
{
  clib_mem_heap_t *oldheap;
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
  clib_mem_heap_t *oldheap;
  oldheap = clib_mem_set_heap (rp->region_heap);
  return ((void *) oldheap);
}

static inline void *
svm_push_data_heap (svm_region_t * rp)
{
  clib_mem_heap_t *oldheap;
  oldheap = clib_mem_set_heap (rp->data_heap);
  return ((void *) oldheap);
}

static inline void
svm_pop_heap (void *oldheap)
{
  clib_mem_set_heap (oldheap);
}

#endif /* __included_svm_h__ */
