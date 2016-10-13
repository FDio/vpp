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

#define MMAP_PAGESIZE (clib_mem_get_page_size())

#define SVM_VERSION ((1<<16) | 1)	/* set to declare region ready. */

#define SVM_FLAGS_MHEAP (1<<0)	/* region contains an mheap */
#define SVM_FLAGS_FILE  (1<<1)	/* region backed by one or more files */
#define SVM_FLAGS_NODATA (1<<2)	/* region will be further subdivided */
#define SVM_FLAGS_NEED_DATA_INIT (1<<3)

#define SVM_PVT_MHEAP_SIZE (128<<10)	/* region's private mheap (128k) */

typedef struct svm_region_
{
  volatile uword version;
  pthread_mutex_t mutex;
  pthread_cond_t condvar;
  int mutex_owner_pid;		/* in case of trouble */
  int mutex_owner_tag;
  uword flags;
  uword virtual_base;		/* base of the region object */
  uword virtual_size;
  void *region_heap;
  void *data_base;		/* data portion base address */
  void *data_heap;		/* data heap, if any */
  volatile void *user_ctx;	/* user context pointer */
  /* stuff allocated in the region's heap */
  uword bitmap_size;		/* nbits in virtual alloc bitmap */
  uword *bitmap;		/* the bitmap */
  char *region_name;
  char *backing_file;
  char **filenames;
  uword *client_pids;
  /* pad */

  /* next page:
   * (64K) clib heap for the region itself
   *
   * data_base -> whatever is in this region
   */

} svm_region_t;

typedef struct svm_map_region_args_
{
  char *root_path;		/* NULL means use the truly global arena */
  char *name;
  u64 baseva;
  u64 size;
  u64 pvt_heap_size;
  uword flags;
  char *backing_file;
  uword backing_mmap_size;
  /* uid, gid to own the svm region(s) */
  int uid;
  int gid;
} svm_map_region_args_t;


/*
 * Memory shared across all router instances. Packet buffers, etc
 * Base should be "out of the way," and size should be big enough to
 * cover everything we plan to put here.
 */
#define SVM_GLOBAL_REGION_BASEVA  0x30000000
#define SVM_GLOBAL_REGION_SIZE    (64<<20)
#define SVM_GLOBAL_REGION_NAME "/global_vm"

/*
 * Memory shared across individual router instances.
 */
#define SVM_OVERLAY_REGION_BASEVA \
               (SVM_GLOBAL_REGION_BASEVA + SVM_GLOBAL_REGION_SIZE)
#define SVM_OVERLAY_REGION_SIZE   (1<<20)
#define SVM_OVERLAY_REGION_BASENAME "/overlay_vm"

typedef struct
{
  u8 *subregion_name;
} svm_subregion_t;

typedef struct
{
  svm_subregion_t *subregions;	/* subregion pool */
  uword *name_hash;
  u8 *root_path;
} svm_main_region_t;


void *svm_region_find_or_create (svm_map_region_args_t * a);
void svm_region_init (void);
void svm_region_init_chroot (char *root_path);
void svm_region_init_chroot_uid_gid (char *root_path, int uid, int gid);
void svm_region_init_args (svm_map_region_args_t * a);
void svm_region_exit (void);
void svm_region_unmap (void *rp_arg);
void svm_client_scan (char *root_path);
void svm_client_scan_this_region_nolock (svm_region_t * rp);
u8 *shm_name_from_svm_map_region_args (svm_map_region_args_t * a);

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

u8 *format_svm_region (u8 * s, va_list * args);

svm_region_t *svm_get_root_rp (void);

#endif /* __included_svm_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
