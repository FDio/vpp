/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* physmem.h: virtual <-> physical memory mapping for VLIB buffers */

#ifndef included_vlib_physmem_h
#define included_vlib_physmem_h

#include <vppinfra/pmalloc.h>

typedef struct
{
  int index;
  int fd;
  void *base;
  u32 n_pages;
  uword *page_table;
  u32 log2_page_size;
  u32 numa_node;
} vlib_physmem_map_t;

typedef struct
{
  u32 flags;
  uword base_addr;
  uword max_size;
#define VLIB_PHYSMEM_MAIN_F_HAVE_PAGEMAP	(1 << 0)
#define VLIB_PHYSMEM_MAIN_F_HAVE_IOMMU		(1 << 1)
  vlib_physmem_map_t *maps;
  clib_pmalloc_main_t *pmalloc_main;
} vlib_physmem_main_t;

#endif /* included_vlib_physmem_h */
