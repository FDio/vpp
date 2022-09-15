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
#include <vppinfra/lock.h>
#include <vppinfra/time.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format.h>
#include <vppinfra/clib_error.h>
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

static void
map_lock ()
{
  while (clib_atomic_test_and_set (&clib_mem_main.map_lock))
    CLIB_PAUSE ();
}

static void
map_unlock ()
{
  clib_atomic_release (&clib_mem_main.map_lock);
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
  long sysconf_page_size;
  uword page_size;
  void *va;
  int fd;

  if (mm->log2_page_sz != CLIB_MEM_PAGE_SZ_UNKNOWN)
    return;

  /* system page size */
  sysconf_page_size = sysconf (_SC_PAGESIZE);
  if (sysconf_page_size < 0)
    {
      clib_panic ("Could not determine the page size");
    }
  page_size = sysconf_page_size;
  mm->log2_page_sz = min_log2 (page_size);

  /* default system hugeppage size */
  if ((fd = syscall (__NR_memfd_create, "test", MFD_HUGETLB)) != -1)
    {
      mm->log2_default_hugepage_sz = clib_mem_get_fd_log2_page_size (fd);
      close (fd);
    }
  else				/* likely kernel older than 4.14 */
    mm->log2_default_hugepage_sz = legacy_get_log2_default_hugepage_size ();

  mm->log2_sys_default_hugepage_sz = mm->log2_default_hugepage_sz;

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
      if (syscall (__NR_move_pages, 0, 1, &va, &i, &status, 0) == 0)
	mm->numa_node_bitmap |= 1ULL << i;
    }

done:
  munmap (va, page_size);
}

__clib_export u64
clib_mem_get_fd_page_size (int fd)
{
  struct stat st = { 0 };
  if (fstat (fd, &st) == -1)
    return 0;
  return st.st_blksize;
}

__clib_export clib_mem_page_sz_t
clib_mem_get_fd_log2_page_size (int fd)
{
  uword page_size = clib_mem_get_fd_page_size (fd);
  return page_size ? min_log2 (page_size) : CLIB_MEM_PAGE_SZ_UNKNOWN;
}

__clib_export void
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

static int
legacy_memfd_create (u8 * name)
{
  clib_mem_main_t *mm = &clib_mem_main;
  int fd = -1;
  char *mount_dir;
  u8 *temp;
  u8 *filename;

  /*
   * Since mkdtemp will modify template string "/tmp/hugepage_mount.XXXXXX",
   * it must not be a string constant, but should be declared as
   * a character array.
   */
  temp = format (0, "/tmp/hugepage_mount.XXXXXX%c", 0);

  /* create mount directory */
  if ((mount_dir = mkdtemp ((char *) temp)) == 0)
    {
      vec_free (temp);
      vec_reset_length (mm->error);
      mm->error = clib_error_return_unix (mm->error, "mkdtemp");
      return CLIB_MEM_ERROR;
    }

  if (mount ("none", mount_dir, "hugetlbfs", 0, NULL))
    {
      vec_free (temp);
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
  vec_free (temp);

  return fd;
}

__clib_export int
clib_mem_vm_create_fd (clib_mem_page_sz_t log2_page_size, char *fmt, ...)
{
  clib_mem_main_t *mm = &clib_mem_main;
  int fd;
  unsigned int memfd_flags;
  va_list va;
  u8 *s = 0;

  if (log2_page_size == mm->log2_page_sz)
    log2_page_size = CLIB_MEM_PAGE_SZ_DEFAULT;
  else if (log2_page_size == mm->log2_sys_default_hugepage_sz)
    log2_page_size = CLIB_MEM_PAGE_SZ_DEFAULT_HUGE;

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
    vec_set_len (s, 249);
  vec_add1 (s, 0);

  /* memfd_create introduced in kernel 3.17, we don't support older kernels */
  fd = syscall (__NR_memfd_create, (char *) s, memfd_flags);

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

__clib_export clib_mem_vm_map_hdr_t *
clib_mem_vm_get_next_map_hdr (clib_mem_vm_map_hdr_t * hdr)
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword sys_page_sz = 1ULL << mm->log2_page_sz;
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
  uword sys_page_sz = 1ULL << mm->log2_page_sz;
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

  size = round_pow2 (size, 1ULL << log2_page_sz);

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

  map_lock ();

  if (mm->last_map)
    {
      mprotect (mm->last_map, sys_page_sz, PROT_READ | PROT_WRITE);
      mm->last_map->next = hdr;
      mprotect (mm->last_map, sys_page_sz, PROT_NONE);
    }
  else
    mm->first_map = hdr;

  clib_mem_unpoison (hdr, sys_page_sz);
  hdr->next = 0;
  hdr->prev = mm->last_map;
  snprintf (hdr->name, CLIB_VM_MAP_HDR_NAME_MAX_LEN - 1, "%s", (char *) name);
  mm->last_map = hdr;

  hdr->base_addr = (uword) base;
  hdr->log2_page_sz = log2_page_sz;
  hdr->num_pages = size >> log2_page_sz;
  hdr->fd = fd;
  hdr->name[CLIB_VM_MAP_HDR_NAME_MAX_LEN - 1] = 0;
  mprotect (hdr, sys_page_sz, PROT_NONE);

  map_unlock ();

  clib_mem_unpoison (base, size);
  return base;
}

__clib_export int
clib_mem_vm_unmap (void *base)
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword size, sys_page_sz = 1ULL << mm->log2_page_sz;
  clib_mem_vm_map_hdr_t *hdr = base - sys_page_sz;;

  map_lock ();
  if (mprotect (hdr, sys_page_sz, PROT_READ | PROT_WRITE) != 0)
    goto out;

  size = hdr->num_pages << hdr->log2_page_sz;
  if (munmap ((void *) hdr->base_addr, size) != 0)
    goto out;

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

  map_unlock ();

  if (munmap (hdr, sys_page_sz) != 0)
    return CLIB_MEM_ERROR;

  return 0;
out:
  map_unlock ();
  return CLIB_MEM_ERROR;
}

__clib_export void
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
  stats->total = n_pages;
  stats->log2_page_sz = log2_page_size;

  if (syscall (__NR_move_pages, 0, n_pages, ptr, 0, status, 0) != 0)
    {
      stats->unknown = n_pages;
      goto done;
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

done:
  vec_free (status);
  vec_free (ptr);
}


__clib_export u64 *
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

__clib_export int
clib_mem_set_numa_affinity (u8 numa_node, int force)
{
  clib_mem_main_t *mm = &clib_mem_main;
  clib_bitmap_t *bmp = 0;
  int rv;

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

  bmp = clib_bitmap_set (bmp, numa_node, 1);

  rv = syscall (__NR_set_mempolicy, force ? MPOL_BIND : MPOL_PREFERRED, bmp,
		vec_len (bmp) * sizeof (bmp[0]) * 8 + 1);

  clib_bitmap_free (bmp);
  vec_reset_length (mm->error);

  if (rv)
    {
      mm->error = clib_error_return_unix (mm->error, (char *) __func__);
      return CLIB_MEM_ERROR;
    }

  return 0;
}

__clib_export int
clib_mem_set_default_numa_affinity ()
{
  clib_mem_main_t *mm = &clib_mem_main;

  if (syscall (__NR_set_mempolicy, MPOL_DEFAULT, 0, 0))
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
