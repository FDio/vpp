/*
 *------------------------------------------------------------------
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

#ifndef __included_svm_common_h__
#define __included_svm_common_h__

#include <stdarg.h>
#include <pthread.h>
#include <vppinfra/types.h>

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
  const char *root_path;	/* NULL means use the truly global arena */
  const char *name;
  uword baseva;
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
 * Memory mapped to high addresses for session/vppcom/vcl/etc...
 */
#if __WORDSIZE == 64
#define HIGH_SEGMENT_BASEVA (8ULL   << 30)	/* 8GB */
#elif __WORDSIZE == 32
#define HIGH_SEGMENT_BASEVA (3584UL << 20)	/* 3.5GB */
#else
#error "unknown __WORDSIZE"
#endif

/*
 * Memory shared across all router instances. Packet buffers, etc
 * Base should be "out of the way," and size should be big enough to
 * cover everything we plan to put here.
 */
#define SVM_GLOBAL_REGION_SIZE    (64<<20)
#define SVM_GLOBAL_REGION_NAME "/global_vm"
u64 svm_get_global_region_base_va ();

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
  int uid;
  int gid;
} svm_main_region_t;


void *svm_region_find_or_create (svm_map_region_args_t * a);
void svm_region_init (void);
void svm_region_init_mapped_region (svm_map_region_args_t * a,
				    svm_region_t * rp);
int svm_region_init_chroot (const char *root_path);
void svm_region_init_chroot_uid_gid (const char *root_path, int uid, int gid);
void svm_region_init_args (svm_map_region_args_t * a);
void svm_region_exit (void);
void svm_region_exit_client (void);
void svm_region_unmap (void *rp_arg);
void svm_region_unmap_client (void *rp_arg);
void svm_client_scan (const char *root_path);
void svm_client_scan_this_region_nolock (svm_region_t * rp);
u8 *shm_name_from_svm_map_region_args (svm_map_region_args_t * a);
u8 *format_svm_region (u8 * s, va_list * args);

svm_region_t *svm_get_root_rp (void);

#endif /* __included_svm_common_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
