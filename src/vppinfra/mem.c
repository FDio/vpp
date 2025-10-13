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
#include <vppinfra/clib_error.h>
#include <sys/mman.h>
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

__clib_export clib_mem_main_t clib_mem_main;

__clib_export uword
clib_mem_vm_reserve (uword start, uword size, clib_mem_page_sz_t log2_page_sz,
		     u8 log2_align)
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword pagesize = 1ULL << log2_page_sz;
  uword sys_page_sz = 1ULL << mm->log2_page_sz;
  uword align_bytes = 0;

  if (log2_align && log2_align < log2_page_sz)
    log2_align = 0;
  if (log2_align)
    align_bytes = 1ULL << log2_align;

  size = round_pow2 (size, pagesize);

  if (start)
    {
      int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
      void *addr;

      if (start & pow2_mask (log2_page_sz))
	return ~0;

      if (align_bytes && (start & (align_bytes - 1)))
	return ~0;

      addr = (void *) (start - sys_page_sz);

      if (mmap (addr, size + sys_page_sz, PROT_NONE, flags, -1, 0) ==
	  MAP_FAILED)
	return ~0;

      return start;
    }
  else
    {
      uword reserve = size;
      void *region;
      uword region_start, region_end;
      uword usable_start, header_start, usable_end;
      uword front, back;

      if (align_bytes)
	reserve += align_bytes;

      reserve = round_pow2 (reserve, pagesize);
      region = mmap (0, reserve + pagesize, PROT_NONE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

      if (region == MAP_FAILED)
	return ~0;

      region_start = pointer_to_uword (region);
      region_end = region_start + reserve + pagesize;
      usable_start = region_start + sys_page_sz;

      if (align_bytes)
	usable_start = round_pow2 (usable_start, align_bytes);
      else
	usable_start = round_pow2 (usable_start, pagesize);

      header_start = usable_start - sys_page_sz;
      usable_end = usable_start + size;

      front = header_start > region_start ? header_start - region_start : 0;
      back = region_end > usable_end ? region_end - usable_end : 0;

      if (front)
	munmap ((void *) region_start, front);
      if (back)
	munmap ((void *) usable_end, back);

      return usable_start;
    }
}

__clib_export void *
clib_mem_vm_map (void *base, uword size, clib_mem_page_sz_t log2_page_sz,
		 char *fmt, ...)
{
  va_list va;
  void *rv;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  vec_add1 (s, 0);
  rv =
    clib_mem_vm_map_internal (base, log2_page_sz, size, -1, 0, 0, (char *) s);
  va_end (va);
  vec_free (s);
  return rv;
}

__clib_export void *
clib_mem_vm_map_stack (uword size, clib_mem_page_sz_t log2_page_sz,
		       char *fmt, ...)
{
  va_list va;
  void *rv;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  vec_add1 (s, 0);
  rv = clib_mem_vm_map_internal (0, log2_page_sz, size, -1, 0, 0, (char *) s);
  va_end (va);
  vec_free (s);
  return rv;
}

__clib_export void *
clib_mem_vm_map_shared (void *base, uword size, int fd, uword offset,
			char *fmt, ...)
{
  va_list va;
  void *rv;
  u8 *s;
  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  vec_add1 (s, 0);
  rv = clib_mem_vm_map_internal (base, 0, size, fd, 0, offset, (char *) s);
  va_end (va);
  vec_free (s);
  return rv;
}

u8 *
format_clib_mem_page_stats (u8 * s, va_list * va)
{
  clib_mem_page_stats_t *stats = va_arg (*va, clib_mem_page_stats_t *);
  u32 indent = format_get_indent (s) + 2;

  s = format (s, "page stats: page-size %U, total %lu, mapped %lu, "
	      "not-mapped %lu", format_log2_page_size, stats->log2_page_sz,
	      stats->total, stats->mapped, stats->not_mapped);

  if (stats->unknown)
    s = format (s, ", unknown %lu", stats->unknown);

  for (int i = 0; i < CLIB_MAX_NUMAS; i++)
    if (stats->per_numa[i])
      s = format (s, "\n%Unuma %u: %lu pages, %U bytes",
		  format_white_space, indent, i,
		  stats->per_numa[i],
		  format_memory_size,
		  stats->per_numa[i] << stats->log2_page_sz);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
