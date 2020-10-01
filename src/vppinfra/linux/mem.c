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

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef MFD_HUGE_SHIFT
#define MFD_HUGE_SHIFT 26
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

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

static clib_mem_page_sz_t
legacy_get_log2_default_hugepage_size (void)
{
  clib_mem_page_sz_t log2_page_size = CLIB_MEM_PAGE_SZ_UNKNOWN;
  FILE *fp;
  char tmp[33] = { };

  if ((fp = fopen ("/proc/meminfo", "r")) == NULL)
    return CLIB_MEM_PAGE_SZ_UNKNOWN;

  while (fscanf (fp, "%32s", tmp) > 0)
    if (strncmp ("Hugepagesize:", tmp, 13) == 0)
      {
	u32 size;
	if (fscanf (fp, "%u", &size) > 0)
	  log2_page_size = 10 + min_log2 (size);
	break;
      }

  fclose (fp);
  return log2_page_size;
}

void
clib_mem_main_init ()
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword page_size;
  void *va;
  int fd;

  if (mm->log2_page_sz != CLIB_MEM_PAGE_SZ_UNKNOWN)
    return;

  /* system page size */
  page_size = sysconf (_SC_PAGESIZE);
  mm->log2_page_sz = min_log2 (page_size);

  /* default system hugeppage size */
  if ((fd = memfd_create ("test", MFD_HUGETLB)) != -1)
    {
      mm->log2_default_hugepage_sz = clib_mem_get_fd_log2_page_size (fd);
      close (fd);
    }
  else				/* likely kernel older than 4.14 */
    mm->log2_default_hugepage_sz = legacy_get_log2_default_hugepage_size ();

  /* numa nodes */
  va = mmap (0, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE |
	     MAP_ANONYMOUS, -1, 0);
  if (va == MAP_FAILED)
    return;

  if (mlock (va, page_size))
    goto done;

  for (int i = 0; i < CLIB_MAX_NUMAS; i++)
    {
      int status;
      if (move_pages (0, 1, &va, &i, &status, 0) == 0)
	mm->numa_node_bitmap |= 1ULL << i;
    }

done:
  munmap (va, page_size);
}

u64
clib_mem_get_fd_page_size (int fd)
{
  struct stat st = { 0 };
  if (fstat (fd, &st) == -1)
    return 0;
  return st.st_blksize;
}

clib_mem_page_sz_t
clib_mem_get_fd_log2_page_size (int fd)
{
  uword page_size = clib_mem_get_fd_page_size (fd);
  return page_size ? min_log2 (page_size) : CLIB_MEM_PAGE_SZ_UNKNOWN;
}

void
clib_mem_vm_randomize_va (uword * requested_va,
			  clib_mem_page_sz_t log2_page_size)
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

clib_error_t *
clib_mem_vm_ext_alloc (clib_mem_vm_alloc_t * a)
{
  clib_mem_main_t *mm = &clib_mem_main;
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
	  log2_page_size = CLIB_MEM_PAGE_SZ_DEFAULT_HUGE;
	  mmap_flags |= MAP_LOCKED;
	}
      else
	log2_page_size = CLIB_MEM_PAGE_SZ_DEFAULT;

      if ((fd = clib_mem_vm_create_fd (log2_page_size, "%s", a->name)) == -1)
	{
	  err = clib_error_return (0, "%U", format_clib_error, mm->error);
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
  CLIB_MEM_UNPOISON (addr, a->size);
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

static int
legacy_memfd_create (u8 * name)
{
  clib_mem_main_t *mm = &clib_mem_main;
  int fd = -1;
  char *mount_dir;
  u8 *filename;

  /* create mount directory */
  if ((mount_dir = mkdtemp ("/tmp/hugepage_mount.XXXXXX")) == 0)
    {
      vec_reset_length (mm->error);
      mm->error = clib_error_return_unix (mm->error, "mkdtemp");
      return CLIB_MEM_ERROR;
    }

  if (mount ("none", mount_dir, "hugetlbfs", 0, NULL))
    {
      rmdir ((char *) mount_dir);
      vec_reset_length (mm->error);
      mm->error = clib_error_return_unix (mm->error, "mount");
      return CLIB_MEM_ERROR;
    }

  filename = format (0, "%s/%s%c", mount_dir, name, 0);

  if ((fd = open ((char *) filename, O_CREAT | O_RDWR, 0755)) == -1)
    {
      vec_reset_length (mm->error);
      mm->error = clib_error_return_unix (mm->error, "mkdtemp");
    }

  umount2 ((char *) mount_dir, MNT_DETACH);
  rmdir ((char *) mount_dir);
  vec_free (filename);

  return fd;
}

int
clib_mem_vm_create_fd (clib_mem_page_sz_t log2_page_size, char *fmt, ...)
{
  clib_mem_main_t *mm = &clib_mem_main;
  int fd;
  unsigned int memfd_flags;
  va_list va;
  u8 *s = 0;

  if (log2_page_size == mm->log2_page_sz)
    log2_page_size = CLIB_MEM_PAGE_SZ_DEFAULT;

  switch (log2_page_size)
    {
    case CLIB_MEM_PAGE_SZ_UNKNOWN:
      return CLIB_MEM_ERROR;
    case CLIB_MEM_PAGE_SZ_DEFAULT:
      memfd_flags = MFD_ALLOW_SEALING;
      break;
    case CLIB_MEM_PAGE_SZ_DEFAULT_HUGE:
      memfd_flags = MFD_HUGETLB;
      break;
    default:
      memfd_flags = MFD_HUGETLB | log2_page_size << MFD_HUGE_SHIFT;
    }

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  /* memfd_create maximum string size is 249 chars without trailing zero */
  if (vec_len (s) > 249)
    _vec_len (s) = 249;
  vec_add1 (s, 0);

  /* memfd_create introduced in kernel 3.17, we don't support older kernels */
  fd = memfd_create ((char *) s, memfd_flags);

  /* kernel versions < 4.14 does not support memfd_create for huge pages */
  if (fd == -1 && errno == EINVAL &&
      log2_page_size == CLIB_MEM_PAGE_SZ_DEFAULT_HUGE)
    {
      fd = legacy_memfd_create (s);
    }
  else if (fd == -1)
    {
      vec_reset_length (mm->error);
      mm->error = clib_error_return_unix (mm->error, "memfd_create");
      vec_free (s);
      return CLIB_MEM_ERROR;
    }

  vec_free (s);

  if ((memfd_flags & MFD_ALLOW_SEALING) &&
      ((fcntl (fd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1))
    {
      vec_reset_length (mm->error);
      mm->error = clib_error_return_unix (mm->error, "fcntl (F_ADD_SEALS)");
      close (fd);
      return CLIB_MEM_ERROR;
    }

  return fd;
}

uword
clib_mem_vm_reserve (uword start, uword size, clib_mem_page_sz_t log2_page_sz)
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword pagesize = 1ULL << log2_page_sz;
  uword sys_page_sz = 1ULL << mm->log2_page_sz;
  uword n_bytes;
  void *base = 0, *p;

  size = round_pow2 (size, pagesize);

  /* in adition of requested reservation, we also rserve one system page
   * (typically 4K) adjacent to the start off reservation */

  if (start)
    {
      /* start address is provided, so we just need to make sure we are not
       * replacing existing map */
      if (start & pow2_mask (log2_page_sz))
	return ~0;

      base = (void *) start - sys_page_sz;
      base = mmap (base, size + sys_page_sz, PROT_NONE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      return (base == MAP_FAILED) ? ~0 : start;
    }

  /* to make sure that we get reservation aligned to page_size we need to
   * request one additional page as mmap will return us address which is
   * aligned only to system page size */
  base = mmap (0, size + pagesize, PROT_NONE,
	       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (base == MAP_FAILED)
    return ~0;

  /* return additional space at the end of allocation */
  p = base + size + pagesize;
  n_bytes = (uword) p & pow2_mask (log2_page_sz);
  if (n_bytes)
    {
      p -= n_bytes;
      munmap (p, n_bytes);
    }

  /* return additional space at the start of allocation */
  n_bytes = pagesize - sys_page_sz - n_bytes;
  if (n_bytes)
    {
      munmap (base, n_bytes);
      base += n_bytes;
    }

  return (uword) base + sys_page_sz;
}

clib_mem_vm_map_hdr_t *
clib_mem_vm_get_next_map_hdr (clib_mem_vm_map_hdr_t * hdr)
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword sys_page_sz = 1 << mm->log2_page_sz;
  clib_mem_vm_map_hdr_t *next;
  if (hdr == 0)
    {
      hdr = mm->first_map;
      if (hdr)
	mprotect (hdr, sys_page_sz, PROT_READ);
      return hdr;
    }
  next = hdr->next;
  mprotect (hdr, sys_page_sz, PROT_NONE);
  if (next)
    mprotect (next, sys_page_sz, PROT_READ);
  return next;
}

void *
clib_mem_vm_map_internal (void *base, clib_mem_page_sz_t log2_page_sz,
			  uword size, int fd, uword offset, char *name)
{
  clib_mem_main_t *mm = &clib_mem_main;
  clib_mem_vm_map_hdr_t *hdr;
  uword sys_page_sz = 1 << mm->log2_page_sz;
  int mmap_flags = MAP_FIXED, is_huge = 0;

  if (fd != -1)
    {
      mmap_flags |= MAP_SHARED;
      log2_page_sz = clib_mem_get_fd_log2_page_size (fd);
      if (log2_page_sz > mm->log2_page_sz)
	is_huge = 1;
    }
  else
    {
      mmap_flags |= MAP_PRIVATE | MAP_ANONYMOUS;

      if (log2_page_sz == mm->log2_page_sz)
	log2_page_sz = CLIB_MEM_PAGE_SZ_DEFAULT;

      switch (log2_page_sz)
	{
	case CLIB_MEM_PAGE_SZ_UNKNOWN:
	  /* will fail later */
	  break;
	case CLIB_MEM_PAGE_SZ_DEFAULT:
	  log2_page_sz = mm->log2_page_sz;
	  break;
	case CLIB_MEM_PAGE_SZ_DEFAULT_HUGE:
	  mmap_flags |= MAP_HUGETLB;
	  log2_page_sz = mm->log2_default_hugepage_sz;
	  is_huge = 1;
	  break;
	default:
	  mmap_flags |= MAP_HUGETLB;
	  mmap_flags |= log2_page_sz << MAP_HUGE_SHIFT;
	  is_huge = 1;
	}
    }

  if (log2_page_sz == CLIB_MEM_PAGE_SZ_UNKNOWN)
    return CLIB_MEM_VM_MAP_FAILED;

  size = round_pow2 (size, 1 << log2_page_sz);

  base = (void *) clib_mem_vm_reserve ((uword) base, size, log2_page_sz);

  if (base == (void *) ~0)
    return CLIB_MEM_VM_MAP_FAILED;

  base = mmap (base, size, PROT_READ | PROT_WRITE, mmap_flags, fd, offset);

  if (base == MAP_FAILED)
    return CLIB_MEM_VM_MAP_FAILED;

  if (is_huge && (mlock (base, size) != 0))
    {
      munmap (base, size);
      return CLIB_MEM_VM_MAP_FAILED;
    }

  hdr = mmap (base - sys_page_sz, sys_page_sz, PROT_READ | PROT_WRITE,
	      MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

  if (hdr != base - sys_page_sz)
    {
      munmap (base, size);
      return CLIB_MEM_VM_MAP_FAILED;
    }

  if (mm->last_map)
    {
      mprotect (mm->last_map, sys_page_sz, PROT_READ | PROT_WRITE);
      mm->last_map->next = hdr;
      mprotect (mm->last_map, sys_page_sz, PROT_NONE);
    }
  else
    mm->first_map = hdr;

  hdr->next = 0;
  hdr->prev = mm->last_map;
  mm->last_map = hdr;

  hdr->base_addr = (uword) base;
  hdr->log2_page_sz = log2_page_sz;
  hdr->num_pages = size >> log2_page_sz;
  hdr->fd = fd;
  snprintf (hdr->name, CLIB_VM_MAP_HDR_NAME_MAX_LEN - 1, "%s", (char *) name);
  hdr->name[CLIB_VM_MAP_HDR_NAME_MAX_LEN - 1] = 0;
  mprotect (hdr, sys_page_sz, PROT_NONE);

  CLIB_MEM_UNPOISON (base, size);
  return base;
}

int
clib_mem_vm_unmap (void *base)
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword size, sys_page_sz = 1 << mm->log2_page_sz;
  clib_mem_vm_map_hdr_t *hdr = base - sys_page_sz;;

  if (mprotect (hdr, sys_page_sz, PROT_READ | PROT_WRITE) != 0)
    return CLIB_MEM_ERROR;

  size = hdr->num_pages << hdr->log2_page_sz;
  if (munmap ((void *) hdr->base_addr, size) != 0)
    return CLIB_MEM_ERROR;

  if (hdr->next)
    {
      mprotect (hdr->next, sys_page_sz, PROT_READ | PROT_WRITE);
      hdr->next->prev = hdr->prev;
      mprotect (hdr->next, sys_page_sz, PROT_NONE);
    }
  else
    mm->last_map = hdr->prev;

  if (hdr->prev)
    {
      mprotect (hdr->prev, sys_page_sz, PROT_READ | PROT_WRITE);
      hdr->prev->next = hdr->next;
      mprotect (hdr->prev, sys_page_sz, PROT_NONE);
    }
  else
    mm->first_map = hdr->next;

  if (munmap (hdr, sys_page_sz) != 0)
    return CLIB_MEM_ERROR;

  return 0;
}

void
clib_mem_get_page_stats (void *start, clib_mem_page_sz_t log2_page_size,
			 uword n_pages, clib_mem_page_stats_t * stats)
{
  int i, *status = 0;
  void **ptr = 0;

  log2_page_size = clib_mem_log2_page_size_validate (log2_page_size);

  vec_validate (status, n_pages - 1);
  vec_validate (ptr, n_pages - 1);

  for (i = 0; i < n_pages; i++)
    ptr[i] = start + (i << log2_page_size);

  clib_memset (stats, 0, sizeof (clib_mem_page_stats_t));

  if (move_pages (0, n_pages, ptr, 0, status, 0) != 0)
    {
      stats->unknown = n_pages;
      return;
    }

  for (i = 0; i < n_pages; i++)
    {
      if (status[i] >= 0 && status[i] < CLIB_MAX_NUMAS)
	{
	  stats->mapped++;
	  stats->per_numa[status[i]]++;
	}
      else if (status[i] == -EFAULT)
	stats->not_mapped++;
      else
	stats->unknown++;
    }
}


u64 *
clib_mem_vm_get_paddr (void *mem, clib_mem_page_sz_t log2_page_size,
		       int n_pages)
{
  int pagesize = sysconf (_SC_PAGESIZE);
  int fd;
  int i;
  u64 *r = 0;

  log2_page_size = clib_mem_log2_page_size_validate (log2_page_size);

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

int
clib_mem_set_numa_affinity (u8 numa_node, int force)
{
  clib_mem_main_t *mm = &clib_mem_main;
  long unsigned int mask[16] = { 0 };
  int mask_len = sizeof (mask) * 8 + 1;

  /* no numa support */
  if (mm->numa_node_bitmap == 0)
    {
      if (numa_node)
	{
	  vec_reset_length (mm->error);
	  mm->error = clib_error_return (mm->error, "%s: numa not supported",
					 (char *) __func__);
	  return CLIB_MEM_ERROR;
	}
      else
	return 0;
    }

  mask[0] = 1 << numa_node;

  if (set_mempolicy (force ? MPOL_BIND : MPOL_PREFERRED, mask, mask_len))
    goto error;

  vec_reset_length (mm->error);
  return 0;

error:
  vec_reset_length (mm->error);
  mm->error = clib_error_return_unix (mm->error, (char *) __func__);
  return CLIB_MEM_ERROR;
}

int
clib_mem_set_default_numa_affinity ()
{
  clib_mem_main_t *mm = &clib_mem_main;

  if (set_mempolicy (MPOL_DEFAULT, 0, 0))
    {
      vec_reset_length (mm->error);
      mm->error = clib_error_return_unix (mm->error, (char *) __func__);
      return CLIB_MEM_ERROR;
    }
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
