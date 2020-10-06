/*
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
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
#ifndef __included_ssvm_h__
#define __included_ssvm_h__

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/lock.h>

#ifndef MMAP_PAGESIZE
#define MMAP_PAGESIZE (clib_mem_get_page_size())
#endif

#define SSVM_N_OPAQUE 7

typedef enum ssvm_segment_type_
{
  SSVM_SEGMENT_SHM = 0,
  SSVM_SEGMENT_MEMFD,
  SSVM_SEGMENT_PRIVATE,
  SSVM_N_SEGMENT_TYPES		/**< Private segments */
} ssvm_segment_type_t;

typedef struct
{
  /* Spin-lock */
  volatile u32 lock;
  volatile u32 owner_pid;
  int recursion_count;
  u32 tag;			/* for debugging */

  /* The allocation arena */
  void *heap;

  /* Segment must be mapped at this address, or no supper */
  uword ssvm_va;
  /* The actual mmap size */
  uword ssvm_size;
  u32 server_pid;
  u32 client_pid;
  u8 *name;
  void *opaque[SSVM_N_OPAQUE];

  /* Set when server init done */
  volatile u32 ready;

  ssvm_segment_type_t type;
} ssvm_shared_header_t;

typedef struct
{
  ssvm_shared_header_t *sh;
  uword ssvm_size;
  uword requested_va;
  u32 my_pid;
  u8 *name;
  u8 numa;			/**< UNUSED: numa requested at alloc time */
  int is_server;

  union
  {
    int fd;			/**< memfd segments */
    int attach_timeout;		/**< shm segments attach timeout (sec) */
  };
} ssvm_private_t;

always_inline void
ssvm_lock (ssvm_shared_header_t * h, u32 my_pid, u32 tag)
{
  if (h->owner_pid == my_pid)
    {
      h->recursion_count++;
      return;
    }

  while (clib_atomic_test_and_set (&h->lock))
    CLIB_PAUSE ();

  h->owner_pid = my_pid;
  h->recursion_count = 1;
  h->tag = tag;
}

always_inline void
ssvm_lock_non_recursive (ssvm_shared_header_t * h, u32 tag)
{
  while (clib_atomic_test_and_set (&h->lock))
    CLIB_PAUSE ();

  h->tag = tag;
}

always_inline void
ssvm_unlock (ssvm_shared_header_t * h)
{
  if (--h->recursion_count == 0)
    {
      h->owner_pid = 0;
      h->tag = 0;
      clib_atomic_release (&h->lock);
    }
}

always_inline void
ssvm_unlock_non_recursive (ssvm_shared_header_t * h)
{
  h->tag = 0;
  clib_atomic_release (&h->lock);
}

static inline void *
ssvm_push_heap (ssvm_shared_header_t * sh)
{
  clib_mem_heap_t *oldheap;
  oldheap = clib_mem_set_heap (sh->heap);
  return ((void *) oldheap);
}

static inline void
ssvm_pop_heap (void *oldheap)
{
  clib_mem_set_heap (oldheap);
}

static inline void *
ssvm_mem_alloc (ssvm_private_t * ssvm, uword size)
{
  clib_mem_heap_t *oldheap;
  void *rv;

  oldheap = clib_mem_set_heap (ssvm->sh->heap);
  rv = clib_mem_alloc (size);
  clib_mem_set_heap (oldheap);
  return (rv);
}

#define foreach_ssvm_api_error                  \
_(NO_NAME, "No shared segment name", -100)      \
_(NO_SIZE, "Size not set (server)", -101)       \
_(CREATE_FAILURE, "Create failed", -102)        \
_(SET_SIZE, "Set size failed", -103)		\
_(MMAP, "mmap failed", -104)			\
_(CLIENT_TIMEOUT, "Client map timeout", -105)

typedef enum
{
#define _(n,s,c) SSVM_API_ERROR_##n = c,
  foreach_ssvm_api_error
#undef _
} ssvm_api_error_enum_t;

#define SSVM_API_ERROR_NO_NAME	(-10)

int ssvm_server_init (ssvm_private_t * ssvm, ssvm_segment_type_t type);
int ssvm_client_init (ssvm_private_t * ssvm, ssvm_segment_type_t type);
void ssvm_delete (ssvm_private_t * ssvm);

int ssvm_server_init_shm (ssvm_private_t * ssvm);
int ssvm_client_init_shm (ssvm_private_t * ssvm);
void ssvm_delete_shm (ssvm_private_t * ssvm);

int ssvm_server_init_memfd (ssvm_private_t * memfd);
int ssvm_client_init_memfd (ssvm_private_t * memfd);
void ssvm_delete_memfd (ssvm_private_t * memfd);

int ssvm_server_init_private (ssvm_private_t * ssvm);
int ssvm_client_init_private (ssvm_private_t * ssvm);
void ssvm_delete_private (ssvm_private_t * ssvm);

ssvm_segment_type_t ssvm_type (const ssvm_private_t * ssvm);
u8 *ssvm_name (const ssvm_private_t * ssvm);

#endif /* __included_ssvm_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
