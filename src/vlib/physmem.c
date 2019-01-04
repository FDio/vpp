/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <vppinfra/linux/syscall.h>
#include <vppinfra/linux/sysfs.h>
#include <vlib/vlib.h>
#include <vlib/physmem.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vlib/linux/vfio.h>

clib_error_t *
vlib_physmem_shared_map_create (vlib_main_t * vm, char *name, uword size,
				u32 log2_page_sz, u32 numa_node,
				u32 * map_index)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  vlib_physmem_map_t *map;
  clib_pmalloc_arena_t *a;
  clib_error_t *error = 0;
  void *va;
  uword i;

  va = clib_pmalloc_create_shared_arena (pm, name, size, log2_page_sz,
					 numa_node);

  if (va == 0)
    return clib_error_return (0, "%U", format_clib_error,
			      clib_pmalloc_last_error (pm));

  a = clib_pmalloc_get_arena (pm, va);

  pool_get (vpm->maps, map);
  *map_index = map->index = map - vpm->maps;
  map->base = va;
  map->fd = a->fd;
  map->n_pages = a->n_pages * a->subpages_per_page;
  map->log2_page_size = a->log2_subpage_sz;
  map->numa_node = a->numa_node;

  for (i = 0; i < a->n_pages; i++)
    {
      uword pa =
	clib_pmalloc_get_pa (pm, (u8 *) va + (i << a->log2_subpage_sz));

      /* maybe iova */
      if (pa == 0)
	pa = pointer_to_uword (va);

      vec_add1 (map->page_table, pa);
    }

  return error;
}

vlib_physmem_map_t *
vlib_physmem_get_map (vlib_main_t * vm, u32 index)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  return pool_elt_at_index (vpm->maps, index);
}

clib_error_t *
vlib_physmem_init (vlib_main_t * vm)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  clib_error_t *error = 0;
  u64 *pt = 0;
  void *p;

  /* check if pagemap is accessible */
  pt = clib_mem_vm_get_paddr (&pt, min_log2 (sysconf (_SC_PAGESIZE)), 1);
  if (pt && pt[0])
    vpm->flags |= VLIB_PHYSMEM_MAIN_F_HAVE_PAGEMAP;
  vec_free (pt);

  if ((error = linux_vfio_init (vm)))
    return error;

  p = clib_mem_alloc_aligned (sizeof (clib_pmalloc_main_t),
			      CLIB_CACHE_LINE_BYTES);
  memset (p, 0, sizeof (clib_pmalloc_main_t));
  vpm->pmalloc_main = (clib_pmalloc_main_t *) p;
  clib_pmalloc_init (vpm->pmalloc_main, 0);

  return error;
}

static clib_error_t *
show_physmem (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 verbose = 0, map = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else if (unformat (line_input, "v"))
	    verbose = 1;
	  else if (unformat (line_input, "detail"))
	    verbose = 2;
	  else if (unformat (line_input, "d"))
	    verbose = 2;
	  else if (unformat (line_input, "map"))
	    map = 1;
	  else
	    break;
	}
      unformat_free (line_input);
    }

  if (map)
    vlib_cli_output (vm, " %U", format_pmalloc_map, vpm->pmalloc_main);
  else
    vlib_cli_output (vm, " %U", format_pmalloc, vpm->pmalloc_main, verbose);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_physmem_command, static) = {
  .path = "show physmem",
  .short_help = "show physmem [verbose | detail | map]",
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
