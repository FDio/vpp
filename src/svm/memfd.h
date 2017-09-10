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
#ifndef __included_memfd_h__
#define __included_memfd_h__

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
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
/* DGMS, memfd syscall not in glibc... */
#include <vppinfra/linux/syscall.h>

#ifndef MMAP_PAGESIZE
#define MMAP_PAGESIZE (clib_mem_get_page_size())
#endif

#define MEMFD_N_OPAQUE 7

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
  u64 memfd_va;
  /* The actual mmap size */
  u64 memfd_size;
  u32 master_pid;
  u32 slave_pid;
  u8 *name;
  void *opaque[MEMFD_N_OPAQUE];

  /* Set when the master application thinks it's time to make the donuts */
  volatile u32 ready;

  /* Needed to make unique MAC addresses, etc. */
  u32 master_index;
} memfd_shared_header_t;

typedef struct
{
  memfd_shared_header_t *sh;
  int fd;
  u64 memfd_size;
  u32 my_pid;
  u32 vlib_hw_if_index;
  uword requested_va;
  int i_am_master;
  u32 per_interface_next_index;
  u32 *rx_queue;
  u8 *name;
} memfd_private_t;

always_inline void
memfd_lock (memfd_shared_header_t * h, u32 my_pid, u32 tag)
{
  if (h->owner_pid == my_pid)
    {
      h->recursion_count++;
      return;
    }

  while (__sync_lock_test_and_set (&h->lock, 1))
    ;

  h->owner_pid = my_pid;
  h->recursion_count = 1;
  h->tag = tag;
}

always_inline void
memfd_lock_non_recursive (memfd_shared_header_t * h, u32 tag)
{
  while (__sync_lock_test_and_set (&h->lock, 1))
    ;

  h->tag = tag;
}

always_inline void
memfd_unlock (memfd_shared_header_t * h)
{
  if (--h->recursion_count == 0)
    {
      h->owner_pid = 0;
      h->tag = 0;
      CLIB_MEMORY_BARRIER ();
      h->lock = 0;
    }
}

always_inline void
memfd_unlock_non_recursive (memfd_shared_header_t * h)
{
  h->tag = 0;
  CLIB_MEMORY_BARRIER ();
  h->lock = 0;
}

static inline void *
memfd_push_heap (memfd_shared_header_t * sh)
{
  u8 *oldheap;
  oldheap = clib_mem_set_heap (sh->heap);
  return ((void *) oldheap);
}

static inline void
memfd_pop_heap (void *oldheap)
{
  clib_mem_set_heap (oldheap);
}

#define foreach_memfd_api_error                  \
_(NO_NAME, "No shared segment name", -100)      \
_(NO_SIZE, "Size not set (master)", -101)       \
_(CREATE_FAILURE, "Create failed", -102)        \
_(SET_SIZE, "Set size failed", -103)		\
_(MMAP, "mmap failed", -104)			\
_(SLAVE_TIMEOUT, "Slave map timeout", -105)

typedef enum
{
#define _(n,s,c) MEMFD_API_ERROR_##n = c,
  foreach_memfd_api_error
#undef _
} memfd_api_error_enum_t;

#define MEMFD_API_ERROR_NO_NAME	(-10)

int memfd_master_init (memfd_private_t * memfd, u32 master_index);
int memfd_slave_init (memfd_private_t * memfd);
void memfd_delete (memfd_private_t * memfd);

/* These do not belong here, but the original keeps running around... */
/* $$$$ work w/ Damjan to fix properly */

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif
#define MFD_ALLOW_SEALING       0x0002U
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW     0x0004	/* prevent file from growing */
#define F_SEAL_WRITE    0x0008	/* prevent writes */

#endif /* __included_memfd_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
