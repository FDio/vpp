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
#include <numa.h>
#include <numaif.h>

#include <vppinfra/linux/syscall.h>
#include <vppinfra/linux/sysfs.h>
#include <vlib/vlib.h>
#include <vlib/physmem.h>
#include <vlib/unix/unix.h>

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

      if (pr->flags & VLIB_PHYSMEM_F_FAKE)
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

static clib_error_t *
unix_physmem_region_alloc (vlib_main_t * vm, char *name, u32 size,
			   u8 numa_node, u32 flags,
			   vlib_physmem_region_index_t * idx)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  vlib_physmem_region_t *pr;
  clib_error_t *error = 0;
  clib_mem_vm_alloc_t alloc = { 0 };


  if (geteuid () != 0 && (flags & VLIB_PHYSMEM_F_FAKE) == 0)
    return clib_error_return (0, "not allowed");

  pool_get (vpm->regions, pr);

  if ((pr - vpm->regions) >= 256)
    {
      error = clib_error_return (0, "maximum number of regions reached");
      goto error;
    }

  alloc.name = name;
  alloc.size = size;
  alloc.numa_node = numa_node;
  alloc.flags |= CLIB_MEM_VM_F_HUGETLB_PREALLOC | CLIB_MEM_VM_F_SHARED;

  if ((flags & VLIB_PHYSMEM_F_FAKE) == 0)
    {
      alloc.flags |= CLIB_MEM_VM_F_HUGETLB;
      alloc.flags |= CLIB_MEM_VM_F_NUMA_FORCE;
    }
  else
    {
      alloc.flags |= CLIB_MEM_VM_F_NUMA_PREFER;
    }

  error = clib_mem_vm_ext_alloc (&alloc);
  if (error)
    goto error;

  pr->index = pr - vpm->regions;
  pr->flags = flags;
  pr->fd = alloc.fd;
  pr->mem = alloc.addr;
  pr->log2_page_size = alloc.log2_page_size;
  pr->n_pages = alloc.n_pages;
  pr->size = pr->n_pages << pr->log2_page_size;
  pr->page_mask = (1 << pr->log2_page_size) - 1;
  pr->numa_node = numa_node;
  pr->name = format (0, "%s", name);

  if ((flags & VLIB_PHYSMEM_F_FAKE) == 0)
    {
      int i;
      for (i = 0; i < pr->n_pages; i++)
	{
	  void *ptr = pr->mem + (i << pr->log2_page_size);
	  int node;
	  move_pages (0, 1, &ptr, 0, &node, 0);
	  if (numa_node != node)
	    {
	      clib_warning ("physmem page for region \'%s\' allocated on the"
			    " wrong numa node (requested %u actual %u)",
			    pr->name, pr->numa_node, node, i);
	      break;
	    }
	}
      pr->page_table = clib_mem_vm_get_paddr (pr->mem, pr->log2_page_size,
					      pr->n_pages);
    }

  if (flags & VLIB_PHYSMEM_F_INIT_MHEAP)
    {
      pr->heap = mheap_alloc_with_flags (pr->mem, pr->size,
					 /* Don't want mheap mmap/munmap with IO memory. */
					 MHEAP_FLAG_DISABLE_VM |
					 MHEAP_FLAG_THREAD_SAFE);
    }

  if (flags & VLIB_PHYSMEM_F_HAVE_BUFFERS)
    {
      vlib_buffer_add_mem_range (vm, pointer_to_uword (pr->mem), pr->size);
    }

  *idx = pr->index;

  goto done;

error:
  memset (pr, 0, sizeof (*pr));
  pool_put (vpm->regions, pr);

done:
  return error;
}

static void
unix_physmem_region_free (vlib_main_t * vm, vlib_physmem_region_index_t idx)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  vlib_physmem_region_t *pr = vlib_physmem_get_region (vm, idx);

  if (pr->fd > 0)
    close (pr->fd);
  munmap (pr->mem, pr->size);
  vec_free (pr->name);
  pool_put (vpm->regions, pr);
}

clib_error_t *
unix_physmem_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  /* Avoid multiple calls. */
  if (vm->os_physmem_alloc_aligned)
    return error;

  vm->os_physmem_alloc_aligned = unix_physmem_alloc_aligned;
  vm->os_physmem_free = unix_physmem_free;
  vm->os_physmem_region_alloc = unix_physmem_region_alloc;
  vm->os_physmem_region_free = unix_physmem_region_free;

  return error;
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
      vlib_cli_output (vm, "index %u name '%s' page-size %uKB num-pages %d "
		       "numa-node %u fd %d\n",
		       pr->index, pr->name, (1 << (pr->log2_page_size -10)),
		       pr->n_pages, pr->numa_node, pr->fd);
      if (pr->heap)
	vlib_cli_output (vm, "  %U", format_mheap, pr->heap, /* verbose */ 1);
      else
	vlib_cli_output (vm, "  no heap\n");
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
