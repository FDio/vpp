/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_physmem_h__
#define __included_physmem_h__

/* Manage I/O physical memory. */
#define _GNU_SOURCE
#include <sched.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vppinfra/mheap.h>
#include <vppinfra/os.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <sys/fcntl.h>		/* for open */
#include <sys/file.h>		/* for flock */
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>

typedef struct
{
  /* Virtual memory via mmaped. */
  void *mem;

  /* Size in bytes. */
  uword mem_size;

  /* Heap allocated out of virtual memory. */
  void *heap;

  /* huge TLB segment id */
  int shmid;

  /* should we try to use htlb ? */
  int no_hugepages;

} physmem_main_t;

#endif /* __included_physmem_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
