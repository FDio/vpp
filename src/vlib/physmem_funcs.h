/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* physmem.h: virtual <-> physical memory mapping for VLIB buffers */

#ifndef included_vlib_physmem_funcs_h
#define included_vlib_physmem_funcs_h

#include <vppinfra/clib.h>
#include <vppinfra/clib_error.h>
#include <vlib/physmem.h>
#include <vlib/main.h>

clib_error_t *vlib_physmem_init (vlib_main_t * vm);
clib_error_t *vlib_physmem_shared_map_create (vlib_main_t * vm, char *name,
					      uword size, u32 log2_page_sz,
					      u32 numa_node, u32 * map_index);

vlib_physmem_map_t *vlib_physmem_get_map (vlib_main_t * vm, u32 index);

always_inline void *
vlib_physmem_alloc_aligned (vlib_main_t * vm, uword n_bytes, uword alignment)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return clib_pmalloc_alloc_aligned (pm, n_bytes, alignment);
}

always_inline void *
vlib_physmem_alloc_aligned_on_numa (vlib_main_t * vm, uword n_bytes,
				    uword alignment, u32 numa_node)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return clib_pmalloc_alloc_aligned_on_numa (pm, n_bytes, alignment,
					     numa_node);
}

/* By default allocate I/O memory with cache line alignment. */
always_inline void *
vlib_physmem_alloc (vlib_main_t * vm, uword n_bytes)
{
  return vlib_physmem_alloc_aligned (vm, n_bytes, CLIB_CACHE_LINE_BYTES);
}

always_inline void *
vlib_physmem_alloc_from_map (vlib_main_t * vm, u32 physmem_map_index,
			     uword n_bytes, uword alignment)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  vlib_physmem_map_t *map = vlib_physmem_get_map (vm, physmem_map_index);
  return clib_pmalloc_alloc_from_arena (pm, map->base, n_bytes,
					CLIB_CACHE_LINE_BYTES);
}

always_inline void
vlib_physmem_free (vlib_main_t * vm, void *p)
{
  if (p)
    clib_pmalloc_free (vm->physmem_main.pmalloc_main, p);
}

always_inline u64
vlib_physmem_get_page_index (vlib_main_t * vm, void *mem)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return clib_pmalloc_get_page_index (pm, mem);
}

always_inline u64
vlib_physmem_get_pa (vlib_main_t * vm, void *mem)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return clib_pmalloc_get_pa (pm, mem);
}

always_inline clib_error_t *
vlib_physmem_last_error (struct vlib_main_t * vm)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return pm->error;
}

#endif /* included_vlib_physmem_funcs_h */
