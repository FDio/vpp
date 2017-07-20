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
/*
 * physmem.c: Unix physical memory
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <vlib/vlib.h>
#include <vlib/physmem.h>

static void *
unix_physmem_alloc_aligned (vlib_main_t * vm, vlib_physmem_region_index_t idx,
			    uword n_bytes, uword alignment)
{
  vlib_physmem_region_t *pr = vlib_physmem_get_region (vm, idx);
  uword lo_offset, hi_offset;
  uword *to_free = 0;

  if (pr->heap == 0)
    return 0;

  /* IO memory is always at least cache aligned. */
  alignment = clib_max (alignment, CLIB_CACHE_LINE_BYTES);

  while (1)
    {
      mheap_get_aligned (pr->heap, n_bytes,
			 /* align */ alignment,
			 /* align offset */ 0,
			 &lo_offset);

      /* Allocation failed? */
      if (lo_offset == ~0)
	break;

      /* Make sure allocation does not span DMA physical chunk boundary. */
      hi_offset = lo_offset + n_bytes - 1;

      if ((lo_offset >> pr->log2_page_size) ==
	  (hi_offset >> pr->log2_page_size))
	break;

      /* Allocation would span chunk boundary, queue it to be freed as soon as
         we find suitable chunk. */
      vec_add1 (to_free, lo_offset);
    }

  if (to_free != 0)
    {
      uword i;
      for (i = 0; i < vec_len (to_free); i++)
	mheap_put (pr->heap, to_free[i]);
      vec_free (to_free);
    }

  return lo_offset != ~0 ? pr->heap + lo_offset : 0;
}

static void
unix_physmem_free (vlib_main_t * vm, vlib_physmem_region_index_t idx, void *x)
{
  vlib_physmem_region_t *pr = vlib_physmem_get_region (vm, idx);
  /* Return object to region's heap. */
  mheap_put (pr->heap, x - pr->heap);
}

static u64
get_page_paddr (int fd, uword addr)
{
  int pagesize = sysconf (_SC_PAGESIZE);
  u64 seek, pagemap = 0;

  seek = ((u64) addr / pagesize) * sizeof (u64);
  if (lseek (fd, seek, SEEK_SET) != seek)
    {
      clib_unix_warning ("lseek to 0x%llx", seek);
      return 0;
    }
  if (read (fd, &pagemap, sizeof (pagemap)) != (sizeof (pagemap)))
    {
      clib_unix_warning ("read ptbits");
      return 0;
    }
  if ((pagemap & (1ULL << 63)) == 0)
    return 0;

  pagemap &= pow2_mask (55);

  return pagemap * pagesize;
}


u8
numa_node_for_addr (uword vaddr)
{
  int fd;
  unformat_input_t input;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 ret = 0xff;

  fd = open ("/proc/self/numa_maps", O_RDONLY);
  if (fd < 0)
    return ~0;

  unformat_init_unix_file (&input, fd);
  while (unformat_user (&input, unformat_line_input, line_input))
    {
      u64 addr;
      u32 page_size = 0;
      u32 numa_node = ~0, numa_pages = ~0;

      if (!unformat (line_input, "%lx", &addr))
	{
	  unformat_free (line_input);
	  continue;
	}
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  u8 *str;
	  if (unformat (line_input, "kernelpagesize_kB=%u", &page_size))
	    ;
	  else if (unformat (line_input, "N%u=%u", &numa_node, &numa_pages))
	    ;
	  else if (unformat (line_input, "%s", &str))
	    vec_free (str);
	}
      unformat_free (line_input);

      if (numa_pages == ~0)
	continue;
      if (vaddr < addr)
	continue;
      if (vaddr > addr + page_size * 1024 * numa_pages)
	continue;

      ret = numa_node;
      goto done;
    }

done:
  unformat_free (&input);
  close (fd);
  return ret;
}

static clib_error_t *
unix_physmem_region_alloc (vlib_main_t * vm, char *name, u32 size,
			   u8 numa_node, u32 flags,
			   vlib_physmem_region_index_t * idx)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  vlib_physmem_region_t *pr;
  clib_error_t *error = 0;
  void *mem = 0;
  int fd = -1, pagemap_fd = -1;
  u8 log2_page_size;
  int n_pages;
  u8 index = vec_len (vpm->regions);
  u8 *mount_dir = 0;
  u8 *filename;
  struct stat st;

  if (index >= 256)
    return clib_error_return (0, "maximum number of regions reached");

  if ((pagemap_fd = open ((char *) "/proc/self/pagemap", O_RDONLY)) == -1)
    {
      error = clib_error_return_unix (0, "open '/proc/self/pagemap'");
      goto error;
    }

  mount_dir = format (0, "/run/vpp/physmem_region%d%c", index, 0);
  filename = format (0, "%s/mem%c", mount_dir, 0);

  unlink ((char *) mount_dir);

  if (mkdir ((char *) mount_dir, 0755))
    {
      error = clib_error_return_unix (0, "mkdir '%s'", mount_dir);
      goto error;
    }

  if (mount ("none", (char *) mount_dir, "hugetlbfs", 0, NULL))
    {
      error = clib_error_return_unix (0, "mount hugetlb directory '%s'",
				      mount_dir);
      goto error;
    }

  if ((fd = open ((char *) filename, O_CREAT | O_RDWR, 0755)) == -1)
    {
      error = clib_error_return_unix (0, "open");
      goto error;
    }

  if (fstat (fd, &st))
    {
      error = clib_error_return_unix (0, "fstat");
      goto error;
    }

  log2_page_size = min_log2 (st.st_blksize);
  n_pages = ((size - 1) >> log2_page_size) + 1;
  size = n_pages * (1 << log2_page_size);

  if ((ftruncate (fd, size)) == -1)
    {
      error = clib_error_return_unix (0, "ftruncate length: %d", size);
      goto error;
    }

  int old_policy = 0;
  u64 old_mask[16] = { 0 };
  u64 mask[16] = { 0 };
  int rv;

  rv = syscall (__NR_get_mempolicy, &old_policy, old_mask, 1025, 0, 0);
  if (rv == -1)
    clib_unix_warning ("get_mempolicy");

  mask[0] = 1 << numa_node;
  rv = syscall (__NR_set_mempolicy, 2 /* MPOL_BIND */ , mask, 1025);
  if (rv == -1)
    clib_unix_warning ("set_mempolicy");

  mem = mmap (0, size, (PROT_READ | PROT_WRITE),
	      MAP_SHARED | MAP_HUGETLB | MAP_LOCKED, fd, 0);

  if (mem == MAP_FAILED)
    {
      mem = 0;
      error = clib_error_return_unix (0, "mmap");
      goto error;
    }

  rv = syscall (__NR_set_mempolicy, old_policy, old_mask, 1025);
  if (rv == -1)
    clib_unix_warning ("set_mempolicy");

  pool_get (vpm->regions, pr);
  pr->index = pr - vpm->regions;
  pr->fd = fd;
  pr->va_start = pointer_to_uword (mem);
  pr->va_size = n_pages << log2_page_size;
  pr->va_end = pr->va_start + pr->va_size;
  pr->page_mask = (1 << log2_page_size) - 1;
  pr->n_pages = n_pages;
  pr->log2_page_size = log2_page_size;
  pr->numa_node = numa_node_for_addr (pr->va_start);
  pr->mem = mem;

  pr->name = format (0, "%s", name);

  if (flags & VLIB_PHYSMEM_F_INIT_MHEAP)
    {
      pr->heap = mheap_alloc_with_flags (pr->mem, pr->va_size,
					 /* Don't want mheap mmap/munmap with IO memory. */
					 MHEAP_FLAG_DISABLE_VM |
					 MHEAP_FLAG_THREAD_SAFE);
      fformat (stdout, "%U", format_mheap, pr->heap, /* verbose */ 1);
    }

  if (flags & VLIB_PHYSMEM_F_HAVE_BUFFERS)
    {
      vlib_buffer_add_mem_range (vm, pr->va_start, pr->va_size);
    }

  *idx = pr->index;

  int i;
  for (i = 0; i < n_pages; i++)
    {
      uword vaddr = pr->va_start + (((u64) i) << log2_page_size);
      u64 page_paddr = get_page_paddr (pagemap_fd, vaddr);
      vec_add1 (pr->page_table, page_paddr);
    }

  goto done;

error:
  if (fd > -1)
    close (fd);

  if (mem)
    munmap (mem, size);

done:
  umount2 ((char *) mount_dir, MNT_DETACH);
  rmdir ((char *) mount_dir);
  vec_free (mount_dir);
  vec_free (filename);
  if (pagemap_fd > -1)
    close (pagemap_fd);
  return error;
}

static void
unix_physmem_region_free (vlib_main_t * vm, vlib_physmem_region_index_t idx)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  vlib_physmem_region_t *pr = vlib_physmem_get_region (vm, idx);

  if (pr->fd > 0)
    close (pr->fd);
  munmap (pr->mem, pr->va_size);
  vec_free (pr->name);
  pool_put (vpm->regions, pr);
}

clib_error_t *
unix_physmem_init (vlib_main_t * vm, int physical_memory_required)
{
  clib_error_t *error = 0;

  /* Avoid multiple calls. */
  if (vm->os_physmem_alloc_aligned)
    return error;

  vm->os_physmem_alloc_aligned = unix_physmem_alloc_aligned;
  vm->os_physmem_free = unix_physmem_free;
  vm->os_physmem_region_alloc = unix_physmem_region_alloc;
  vm->os_physmem_region_free = unix_physmem_region_free;
  return 0;
}

static clib_error_t *
show_physmem (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  vlib_physmem_region_t *pr;

  /* *INDENT-OFF* */
  pool_foreach (pr, vpm->regions, (
    {
      vlib_cli_output (vm, "index %u name '%s' page-size %uKB num-pages %d\n",
		       pr->index, pr->name, (1 << (pr->log2_page_size -10)),
		       pr->n_pages);
      if (pr->heap)
	vlib_cli_output (vm, "  %U", format_mheap, pr->heap, /* verbose */ 1);
      else
	vlib_cli_output (vm, "  No physmem allocated.");
    }));
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_physmem_command, static) = {
  .path = "show physmem",
  .short_help = "Show physical memory allocation",
  .function = show_physmem,
};
/* *INDENT-ON* */

#if 0
static clib_error_t *
vlib_physmem_configure (vlib_main_t * vm, unformat_input_t * input)
{
  physmem_main_t *pm = &physmem_main;
  u32 size_in_mb;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "no-huge") || unformat (input, "no-huge-pages"))
	pm->no_hugepages = 1;

      else if (unformat (input, "size-in-mb %d", &size_in_mb) ||
	       unformat (input, "size %d", &size_in_mb))
	pm->mem_size = size_in_mb << 20;
      else
	return unformat_parse_error (input);
    }

  unformat_free (input);
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (vlib_physmem_configure, "physmem");
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
