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

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/mempolicy.h>
#include <linux/memfd.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/time.h>
#include <vppinfra/format.h>
#include <vppinfra/clib_error.h>
#include <vppinfra/linux/syscall.h>
#include <vppinfra/linux/sysfs.h>

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW     0x0004	/* prevent file from growing */
#define F_SEAL_WRITE    0x0008	/* prevent writes */
#endif


uword
clib_mem_get_page_size (void)
{
  return getpagesize ();
}

uword
clib_mem_get_default_hugepage_size (void)
{
  unformat_input_t input;
  static u32 size = 0;
  int fd;

  if (size)
    goto done;

  /*
   * If the kernel doesn't support hugepages, /proc/meminfo won't
   * say anything about it. Use the regular page size as a default.
   */
  size = clib_mem_get_page_size () / 1024;

  if ((fd = open ("/proc/meminfo", 0)) == -1)
    return 0;

  unformat_init_clib_file (&input, fd);

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "Hugepagesize:%_%u kB", &size))
	;
      else
	unformat_skip_line (&input);
    }
  unformat_free (&input);
  close (fd);
done:
  return 1024ULL * size;
}

u64
clib_mem_get_fd_page_size (int fd)
{
  struct stat st = { 0 };
  if (fstat (fd, &st) == -1)
    return 0;
  return st.st_blksize;
}

int
clib_mem_get_fd_log2_page_size (int fd)
{
  return min_log2 (clib_mem_get_fd_page_size (fd));
}

void
clib_mem_vm_randomize_va (uword * requested_va, u32 log2_page_size)
{
  u8 bit_mask = 15;

  if (log2_page_size <= 12)
    bit_mask = 15;
  else if (log2_page_size > 12 && log2_page_size <= 16)
    bit_mask = 3;
  else
    bit_mask = 0;

  *requested_va +=
    (clib_cpu_time_now () & bit_mask) * (1ull << log2_page_size);
}

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif

clib_error_t *
clib_mem_create_fd (char *name, int *fdp)
{
  int fd;

  ASSERT (name);

  if ((fd = memfd_create (name, MFD_ALLOW_SEALING)) == -1)
    return clib_error_return_unix (0, "memfd_create");

  if ((fcntl (fd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
    {
      close (fd);
      return clib_error_return_unix (0, "fcntl (F_ADD_SEALS)");
    }

  *fdp = fd;
  return 0;
}

clib_error_t *
clib_mem_create_hugetlb_fd (char *name, int *fdp)
{
  clib_error_t *err = 0;
  int fd = -1;
  static int memfd_hugetlb_supported = 1;
  char *mount_dir;
  char template[] = "/tmp/hugepage_mount.XXXXXX";
  u8 *filename;

  ASSERT (name);

  if (memfd_hugetlb_supported)
    {
      if ((fd = memfd_create (name, MFD_HUGETLB)) != -1)
	goto done;

      /* avoid further tries if memfd MFD_HUGETLB is not supported */
      if (errno == EINVAL && strnlen (name, 256) <= 249)
	memfd_hugetlb_supported = 0;
    }

  mount_dir = mkdtemp (template);
  if (mount_dir == 0)
    return clib_error_return_unix (0, "mkdtemp \'%s\'", template);

  if (mount ("none", (char *) mount_dir, "hugetlbfs", 0, NULL))
    {
      rmdir ((char *) mount_dir);
      err = clib_error_return_unix (0, "mount hugetlb directory '%s'",
				    mount_dir);
    }

  filename = format (0, "%s/%s%c", mount_dir, name, 0);
  fd = open ((char *) filename, O_CREAT | O_RDWR, 0755);
  umount2 ((char *) mount_dir, MNT_DETACH);
  rmdir ((char *) mount_dir);

  if (fd == -1)
    err = clib_error_return_unix (0, "open");

done:
  if (fd != -1)
    fdp[0] = fd;
  return err;
}

clib_error_t *
clib_mem_vm_ext_alloc (clib_mem_vm_alloc_t * a)
{
  int fd = -1;
  clib_error_t *err = 0;
  void *addr = 0;
  u8 *filename = 0;
  int mmap_flags = 0;
  int log2_page_size;
  int n_pages;
  int old_mpol = -1;
  long unsigned int old_mask[16] = { 0 };

  /* save old numa mem policy if needed */
  if (a->flags & (CLIB_MEM_VM_F_NUMA_PREFER | CLIB_MEM_VM_F_NUMA_FORCE))
    {
      int rv;
      rv = get_mempolicy (&old_mpol, old_mask, sizeof (old_mask) * 8 + 1,
			  0, 0);

      if (rv == -1)
	{
	  if (a->numa_node != 0 && (a->flags & CLIB_MEM_VM_F_NUMA_FORCE) != 0)
	    {
	      err = clib_error_return_unix (0, "get_mempolicy");
	      goto error;
	    }
	  else
	    old_mpol = -1;
	}
    }

  if (a->flags & CLIB_MEM_VM_F_LOCKED)
    mmap_flags |= MAP_LOCKED;

  /* if we are creating shared segment, we need file descriptor */
  if (a->flags & CLIB_MEM_VM_F_SHARED)
    {
      mmap_flags |= MAP_SHARED;
      /* if hugepages are needed we need to create mount point */
      if (a->flags & CLIB_MEM_VM_F_HUGETLB)
	{
	  if ((err = clib_mem_create_hugetlb_fd (a->name, &fd)))
	    goto error;

	  mmap_flags |= MAP_LOCKED;
	}
      else
	{
	  if ((err = clib_mem_create_fd (a->name, &fd)))
	    goto error;
	}

      log2_page_size = clib_mem_get_fd_log2_page_size (fd);
      if (log2_page_size == 0)
	{
	  err = clib_error_return_unix (0, "cannot determine page size");
	  goto error;
	}

      if (a->requested_va)
	{
	  clib_mem_vm_randomize_va (&a->requested_va, log2_page_size);
	  mmap_flags |= MAP_FIXED;
	}
    }
  else				/* not CLIB_MEM_VM_F_SHARED */
    {
      mmap_flags |= MAP_PRIVATE | MAP_ANONYMOUS;
      if (a->flags & CLIB_MEM_VM_F_HUGETLB)
	{
	  mmap_flags |= MAP_HUGETLB;
	  log2_page_size = 21;
	}
      else
	{
	  log2_page_size = min_log2 (sysconf (_SC_PAGESIZE));
	}
    }

  n_pages = ((a->size - 1) >> log2_page_size) + 1;

  if (a->flags & CLIB_MEM_VM_F_HUGETLB_PREALLOC)
    {
      err = clib_sysfs_prealloc_hugepages (a->numa_node, log2_page_size,
					   n_pages);
      if (err)
	goto error;

    }

  if (fd != -1)
    if ((ftruncate (fd, (u64) n_pages * (1 << log2_page_size))) == -1)
      {
	err = clib_error_return_unix (0, "ftruncate");
	goto error;
      }

  if (old_mpol != -1)
    {
      int rv;
      long unsigned int mask[16] = { 0 };
      mask[0] = 1 << a->numa_node;
      rv = set_mempolicy (MPOL_BIND, mask, sizeof (mask) * 8 + 1);
      if (rv == -1 && a->numa_node != 0 &&
	  (a->flags & CLIB_MEM_VM_F_NUMA_FORCE) != 0)
	{
	  err = clib_error_return_unix (0, "set_mempolicy");
	  goto error;
	}
    }

  addr = mmap (uword_to_pointer (a->requested_va, void *), a->size,
	       (PROT_READ | PROT_WRITE), mmap_flags, fd, 0);
  if (addr == MAP_FAILED)
    {
      err = clib_error_return_unix (0, "mmap");
      goto error;
    }

  /* re-apply old numa memory policy */
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

void
clib_mem_vm_ext_free (clib_mem_vm_alloc_t * a)
{
  if (a != 0)
    {
      clib_mem_vm_free (a->addr, 1ull << a->log2_page_size);
      if (a->fd != -1)
	close (a->fd);
    }
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

clib_error_t *
clib_mem_vm_ext_map (clib_mem_vm_map_t * a)
{
  int mmap_flags = MAP_SHARED;
  void *addr;

  if (a->requested_va)
    mmap_flags |= MAP_FIXED;

  addr = (void *) mmap (uword_to_pointer (a->requested_va, void *), a->size,
			PROT_READ | PROT_WRITE, mmap_flags, a->fd, 0);

  if (addr == MAP_FAILED)
    return clib_error_return_unix (0, "mmap");

  a->addr = addr;
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
