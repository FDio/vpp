/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/time.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>

clib_mem_main_t clib_mem_main;

clib_mem_vm_map_t *
clib_mem_vm_map_register (void *base, u8 log2_page_sz, uword n_pages,
			  u8 * name)
{
  clib_mem_main_t *mm = &clib_mem_main;
  clib_mem_vm_map_t *m;
  u32 index = 0;

  vec_foreach_index (index, mm->vm_maps)
  {
    m = vec_elt_at_index (mm->vm_maps, index);
    if (m->base >= pointer_to_uword (base))
      break;
  }

  vec_insert (mm->vm_maps, 1, index);
  m = vec_elt_at_index (mm->vm_maps, index);

  m->base = pointer_to_uword (base);
  m->log2_page_sz = log2_page_sz;
  m->n_pages = n_pages;
  m->name = name;
  m->fd = -1;
  return m;
}

u8 *
format_clib_mem_vm_maps (u8 * s, va_list * args)
{
  clib_mem_main_t *mm = &clib_mem_main;
  clib_mem_vm_map_t *m;

  s = format (s, "%-14s %8s %8s %8s %8s %8s %5s\n", "Base", "PageSz",
	      "NumPages", "NotMap", "Numa0", "Numa1", "Name");
  vec_foreach (m, mm->vm_maps)
  {
    clib_mem_vm_numa_page_stats_t stats;
    clib_mem_vm_get_numa_page_stats ((void *) m->base, m->n_pages,
				     m->log2_page_sz, &stats);

    s = format (s, "0x%0lx %8U %8lu", m->base,
		format_log2_page_size, m->log2_page_sz, m->n_pages, m->name);

    s = format (s, "%8u ", stats.not_mapped);
    s = format (s, "%8u ", stats.n_pages_per_numa[0]);
    s = format (s, "%8u ", stats.n_pages_per_numa[1]);
    s = format (s, "%v\n", m->name);
  }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
