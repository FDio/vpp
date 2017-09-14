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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/format.h>
#include <vppinfra/clib_error.h>
#include <vppinfra/linux/syscall.h>
#include <vppinfra/linux/sysfs.h>

int
clib_mem_vm_get_log2_page_size (int fd)
{
  struct stat st = { 0 };
  if (fstat (fd, &st))
    return 0;
  return min_log2 (st.st_blksize);
}

clib_error_t *
clib_mem_vm_ext_alloc (clib_mem_vm_alloc_t * a)
{
  int fd = -1;
  clib_error_t *err = 0;
  void *addr = 0;
  u8 *filename = 0;
  int mmap_flags = MAP_SHARED;
  int log2_page_size;
  int n_pages;
  int old_mpol = -1;
  u64 old_mask[16] = { 0 };

  /* save old numa mem policy if needed */
  if (a->flags & (CLIB_MEM_VM_F_NUMA_PREFER | CLIB_MEM_VM_F_NUMA_FORCE))
    {
      int rv;
      rv =
	get_mempolicy (&old_mpol, old_mask, sizeof (old_mask) * 8 + 1, 0, 0);

      if (rv == -1)
	{
	  if ((a->flags & CLIB_MEM_VM_F_NUMA_FORCE) != 0)
	    {
	      err = clib_error_return_unix (0, "get_mempolicy");
	      goto error;
	    }
	  else
	    old_mpol = -1;
	}
    }

  /* if we are creating shared segment, we need file descriptor */
  if (a->flags & CLIB_MEM_VM_F_SHARED)
    {
      /* if hugepages are needed we need to create mount point */
      if (a->flags & CLIB_MEM_VM_F_HUGETLB)
	{
	  char *mount_dir;
	  char template[] = "/tmp/hugepage_mount.XXXXXX";

	  mount_dir = mkdtemp (template);
	  if (mount_dir == 0)
	    return clib_error_return_unix (0, "mkdtemp \'%s\'", template);

	  if (mount ("none", (char *) mount_dir, "hugetlbfs", 0, NULL))
	    {
	      err = clib_error_return_unix (0, "mount hugetlb directory '%s'",
					    mount_dir);
	      goto error;
	    }

	  filename = format (0, "%s/%s%c", mount_dir, a->name, 0);

	  if ((fd = open ((char *) filename, O_CREAT | O_RDWR, 0755)) == -1)
	    {
	      err = clib_error_return_unix (0, "open");
	      goto error;
	    }
	  umount2 ((char *) mount_dir, MNT_DETACH);
	  rmdir ((char *) mount_dir);
	  mmap_flags |= MAP_LOCKED;
	}
      else
	{
	  if ((fd = memfd_create (a->name, MFD_ALLOW_SEALING)) == -1)
	    {
	      err = clib_error_return_unix (0, "memfd_create");
	      goto error;
	    }

	  if ((fcntl (fd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
	    {
	      err = clib_error_return_unix (0, "fcntl (F_ADD_SEALS)");
	      goto error;
	    }
	}
      log2_page_size = clib_mem_vm_get_log2_page_size (fd);
    }
  else				/* not CLIB_MEM_VM_F_SHARED */
    {
      if (a->flags & CLIB_MEM_VM_F_HUGETLB)
	{
	  mmap_flags |= MAP_HUGETLB | MAP_PRIVATE | MAP_ANONYMOUS;
	  log2_page_size = 21;
	}
      else
	{
	  mmap_flags |= MAP_PRIVATE | MAP_ANONYMOUS;
	  log2_page_size = min_log2 (sysconf (_SC_PAGESIZE));
	}
    }

  n_pages = ((a->size - 1) >> log2_page_size) + 1;


  if (a->flags & CLIB_MEM_VM_F_HUGETLB_PREALLOC)
    {
      err = clib_sysfs_prealloc_hugepages (a->numa_node,
					   1 << (log2_page_size - 10),
					   n_pages);
      if (err)
	goto error;

    }

  if (fd != -1)
    if ((ftruncate (fd, a->size)) == -1)
      {
	err = clib_error_return_unix (0, "ftruncate");
	goto error;
      }

  if (old_mpol != -1)
    {
      int rv;
      u64 mask[16] = { 0 };
      mask[0] = 1 << a->numa_node;
      rv = set_mempolicy (2 /* MPOL_BIND */ , mask, sizeof (mask) * 8 + 1);
      if (rv)
	{
	  err = clib_error_return_unix (0, "set_mempolicy");
	  goto error;
	}
    }

  addr = mmap (0, a->size, (PROT_READ | PROT_WRITE), mmap_flags, fd, 0);
  if (addr == MAP_FAILED)
    {
      err = clib_error_return_unix (0, "mmap");
      goto error;
    }

  /* re-apply ole numa memory policy */
  if (old_mpol != -1 &&
      set_mempolicy (old_mpol, old_mask, sizeof (old_mask) * 8 + 1) == -1)
    {
      err = clib_error_return_unix (0, "set_mempolicy");
      goto error;
    }

  a->log2_page_size = log2_page_size;
  a->n_pages = n_pages;
  a->addr = addr;
  a->fd = fd;
  goto done;

error:
  if (fd != -1)
    close (fd);

done:
  vec_free (filename);
  return err;
}

u64 *
clib_mem_vm_get_paddr (void *mem, int log2_page_size, int n_pages)
{
  int pagesize = sysconf (_SC_PAGESIZE);
  int fd;
  int i;
  u64 *r = 0;

  if ((fd = open ((char *) "/proc/self/pagemap", O_RDONLY)) == -1)
    return 0;

  for (i = 0; i < n_pages; i++)
    {
      u64 seek, pagemap = 0;
      uword vaddr = pointer_to_uword (mem) + (((u64) i) << log2_page_size);
      seek = ((u64) vaddr / pagesize) * sizeof (u64);
      if (lseek (fd, seek, SEEK_SET) != seek)
	goto done;

      if (read (fd, &pagemap, sizeof (pagemap)) != (sizeof (pagemap)))
	goto done;

      if ((pagemap & (1ULL << 63)) == 0)
	goto done;

      pagemap &= pow2_mask (55);
      vec_add1 (r, pagemap * pagesize);
    }

done:
  close (fd);
  if (vec_len (r) != n_pages)
    {
      vec_free (r);
      return 0;
    }
  return r;
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
