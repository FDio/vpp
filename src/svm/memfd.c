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
#include "memfd.h"

int
memfd_master_init (memfd_private_t * memfd, u32 master_index)
{
  int flags;
  memfd_shared_header_t *sh;
  u64 ticks = clib_cpu_time_now ();
  u64 randomize_baseva;
  void *oldheap;

  if (memfd->memfd_size == 0)
    return MEMFD_API_ERROR_NO_SIZE;

  ASSERT (vec_c_string_is_terminated (memfd->name));
  memfd->name = format (0, "memfd svm region %d", master_index);

  memfd->fd = memfd_create ((char *) memfd->name, MFD_ALLOW_SEALING);
  if (memfd->fd < 0)
    {
      clib_unix_warning ("create segment '%s'", memfd->name);
      return MEMFD_API_ERROR_CREATE_FAILURE;
    }

  if ((ftruncate (memfd->fd, memfd->memfd_size)) == -1)
    {
      clib_unix_warning ("set memfd size");
      return MEMFD_API_ERROR_SET_SIZE;
    }

  if ((fcntl (memfd->fd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
    clib_unix_warning ("fcntl (F_ADD_SEALS, F_SEAL_SHRINK)");

  flags = MAP_SHARED;
  if (memfd->requested_va)
    flags |= MAP_FIXED;

  randomize_baseva = (ticks & 15) * MMAP_PAGESIZE;

  if (memfd->requested_va)
    memfd->requested_va += randomize_baseva;

  sh = memfd->sh =
    (memfd_shared_header_t *) mmap ((void *) memfd->requested_va,
				    memfd->memfd_size, PROT_READ | PROT_WRITE,
				    flags, memfd->fd, 0);

  if (memfd->sh == MAP_FAILED)
    {
      clib_unix_warning ("mmap");
      close (memfd->fd);
      return MEMFD_API_ERROR_MMAP;
    }

  memfd->my_pid = getpid ();
  sh->master_pid = memfd->my_pid;
  sh->memfd_size = memfd->memfd_size;
  sh->heap = mheap_alloc_with_flags
    (((u8 *) sh) + MMAP_PAGESIZE, memfd->memfd_size - MMAP_PAGESIZE,
     MHEAP_FLAG_DISABLE_VM | MHEAP_FLAG_THREAD_SAFE);

  sh->memfd_va = pointer_to_uword (sh);
  sh->master_index = master_index;

  oldheap = memfd_push_heap (sh);
  sh->name = format (0, "%s%c", memfd->name, 0);
  memfd_pop_heap (oldheap);

  memfd->i_am_master = 1;

  /* The application has to set set sh->ready... */
  return 0;
}

/*
 * Subtly different than svm_slave_init. The caller
 * needs to acquire a usable file descriptor for the memfd segment
 * e.g. via vppinfra/socket.c:default_socket_recvmsg
 */

int
memfd_slave_init (memfd_private_t * memfd)
{
  memfd_shared_header_t *sh;

  ASSERT (vec_c_string_is_terminated (memfd->name));
  memfd->i_am_master = 0;

  /* Map the segment once, to look at the shared header */
  sh = (void *) mmap (0, MMAP_PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
		      memfd->fd, 0);
  if (sh == MAP_FAILED)
    {
      clib_unix_warning ("slave research mmap");
      close (memfd->fd);
      return MEMFD_API_ERROR_MMAP;
    }

  memfd->requested_va = (u64) sh->memfd_va;
  memfd->memfd_size = sh->memfd_size;
  munmap (sh, MMAP_PAGESIZE);

  sh = memfd->sh =
    (void *) mmap ((void *) memfd->requested_va, memfd->memfd_size,
		   PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_FIXED, memfd->fd, 0);

  if (sh == MAP_FAILED)
    {
      clib_unix_warning ("slave final mmap");
      close (memfd->fd);
      return MEMFD_API_ERROR_MMAP;
    }
  sh->slave_pid = getpid ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
