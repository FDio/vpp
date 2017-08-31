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
#include "ssvm.h"
#include "svm_common.h"

int
ssvm_master_init (ssvm_private_t * ssvm, u32 master_index)
{
  svm_main_region_t *smr = svm_get_root_rp ()->data_base;
  int ssvm_fd;
  u8 *ssvm_filename;
  u8 junk = 0;
  int flags;
  ssvm_shared_header_t *sh;
  u64 ticks = clib_cpu_time_now ();
  u64 randomize_baseva;
  void *oldheap;

  if (ssvm->ssvm_size == 0)
    return SSVM_API_ERROR_NO_SIZE;

  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] creating segment '%s'", getpid (), ssvm->name);

  ASSERT (vec_c_string_is_terminated (ssvm->name));
  ssvm_filename = format (0, "/dev/shm/%s%c", ssvm->name, 0);

  unlink ((char *) ssvm_filename);

  vec_free (ssvm_filename);

  ssvm_fd = shm_open ((char *) ssvm->name, O_RDWR | O_CREAT | O_EXCL, 0777);

  if (ssvm_fd < 0)
    {
      clib_unix_warning ("create segment '%s'", ssvm->name);
      return SSVM_API_ERROR_CREATE_FAILURE;
    }

  if (fchmod (ssvm_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0)
    clib_unix_warning ("ssvm segment chmod");
  if (fchown (ssvm_fd, smr->uid, smr->gid) < 0)
    clib_unix_warning ("ssvm segment chown");

  if (lseek (ssvm_fd, ssvm->ssvm_size, SEEK_SET) < 0)
    {
      clib_unix_warning ("lseek");
      close (ssvm_fd);
      return SSVM_API_ERROR_SET_SIZE;
    }

  if (write (ssvm_fd, &junk, 1) != 1)
    {
      clib_unix_warning ("set ssvm size");
      close (ssvm_fd);
      return SSVM_API_ERROR_SET_SIZE;
    }

  flags = MAP_SHARED;
  if (ssvm->requested_va)
    flags |= MAP_FIXED;

  randomize_baseva = (ticks & 15) * MMAP_PAGESIZE;

  if (ssvm->requested_va)
    ssvm->requested_va += randomize_baseva;

  sh = ssvm->sh =
    (ssvm_shared_header_t *) mmap ((void *) ssvm->requested_va,
				   ssvm->ssvm_size, PROT_READ | PROT_WRITE,
				   flags, ssvm_fd, 0);

  if (ssvm->sh == MAP_FAILED)
    {
      clib_unix_warning ("mmap");
      close (ssvm_fd);
      return SSVM_API_ERROR_MMAP;
    }

  close (ssvm_fd);

  ssvm->my_pid = getpid ();
  sh->master_pid = ssvm->my_pid;
  sh->ssvm_size = ssvm->ssvm_size;
  sh->heap = mheap_alloc_with_flags
    (((u8 *) sh) + MMAP_PAGESIZE, ssvm->ssvm_size - MMAP_PAGESIZE,
     MHEAP_FLAG_DISABLE_VM | MHEAP_FLAG_THREAD_SAFE);

  sh->ssvm_va = pointer_to_uword (sh);
  sh->master_index = master_index;

  oldheap = ssvm_push_heap (sh);
  sh->name = format (0, "%s%c", ssvm->name, 0);
  ssvm_pop_heap (oldheap);

  ssvm->i_am_master = 1;

  /* The application has to set set sh->ready... */
  return 0;
}

int
ssvm_slave_init (ssvm_private_t * ssvm, int timeout_in_seconds)
{
  struct stat stat;
  int ssvm_fd = -1;
  ssvm_shared_header_t *sh;

  ASSERT (vec_c_string_is_terminated (ssvm->name));
  ssvm->i_am_master = 0;

  while (timeout_in_seconds-- > 0)
    {
      if (ssvm_fd < 0)
	ssvm_fd = shm_open ((char *) ssvm->name, O_RDWR, 0777);
      if (ssvm_fd < 0)
	{
	  sleep (1);
	  continue;
	}
      if (fstat (ssvm_fd, &stat) < 0)
	{
	  sleep (1);
	  continue;
	}

      if (stat.st_size > 0)
	goto map_it;
    }
  clib_warning ("slave timeout");
  return SSVM_API_ERROR_SLAVE_TIMEOUT;

map_it:
  sh = (void *) mmap (0, MMAP_PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
		      ssvm_fd, 0);
  if (sh == MAP_FAILED)
    {
      clib_unix_warning ("slave research mmap");
      close (ssvm_fd);
      return SSVM_API_ERROR_MMAP;
    }

  while (timeout_in_seconds-- > 0)
    {
      if (sh->ready)
	goto re_map_it;
    }
  close (ssvm_fd);
  munmap (sh, MMAP_PAGESIZE);
  clib_warning ("slave timeout 2");
  return SSVM_API_ERROR_SLAVE_TIMEOUT;

re_map_it:
  ssvm->requested_va = (u64) sh->ssvm_va;
  ssvm->ssvm_size = sh->ssvm_size;
  munmap (sh, MMAP_PAGESIZE);

  sh = ssvm->sh = (void *) mmap ((void *) ssvm->requested_va, ssvm->ssvm_size,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_FIXED, ssvm_fd, 0);

  if (sh == MAP_FAILED)
    {
      clib_unix_warning ("slave final mmap");
      close (ssvm_fd);
      return SSVM_API_ERROR_MMAP;
    }
  sh->slave_pid = getpid ();
  return 0;
}

void
ssvm_delete (ssvm_private_t * ssvm)
{
  u8 *fn;

  fn = format (0, "/dev/shm/%s%c", ssvm->name, 0);

  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] unlinking ssvm (%s) backing file '%s'", getpid (),
		  ssvm->name, fn);

  /* Throw away the backing file */
  if (unlink ((char *) fn) < 0)
    clib_unix_warning ("unlink segment '%s'", ssvm->name);

  vec_free (fn);
  vec_free (ssvm->name);

  munmap ((void *) ssvm->requested_va, ssvm->ssvm_size);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
