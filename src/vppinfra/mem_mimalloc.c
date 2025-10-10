/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <mimalloc.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <vppinfra/mem.h>
#include <vppinfra/os.h>
#include <vppinfra/format.h>

#define CLIB_MEM_MIMALLOC_STUB()                                              \
  do                                                                          \
    {                                                                         \
      fprintf (stderr, "%s: FIXME\n", __func__);                              \
    }                                                                         \
  while (0)

struct clib_mem_heap_t
{
  /* base address */
  void *base;

  /* backend heap handle (mi_heap_t *) */
  mi_heap_t *mi_heap;

  /* total heap size */
  uword size;

  /* page size (log2) */
  clib_mem_page_sz_t log2_page_sz : 8;

  u32 locked : 1;
  u32 unmap_on_destroy : 1;
  u32 traced : 1;

  mi_arena_id_t arena_id;

  /* heap name */
  char name[0];
};

static_always_inline clib_mem_heap_t *
clib_mem_heap_create_internal (void *base, uword memory_size,
			       clib_mem_page_sz_t log2_page_sz, int is_locked,
			       const char *name, int set_current)
{
  clib_mem_heap_t *heap = 0;
  mi_heap_t *mi_heap = 0;
  mi_arena_id_t arena_id = 0;
  u8 mi_min_align_log2;
  size_t region_size = memory_size;
  int owns_mapping = 0;
  size_t name_len = (name && name[0]) ? strlen (name) + 1 : 1;

  if (memory_size == 0)
    return 0;

  clib_mem_main_init ();
  mi_process_init ();
  mi_thread_init ();
  mi_min_align_log2 = min_log2 (mi_arena_min_alignment ());

  if (base == 0)
    {
      log2_page_sz = clib_mem_log2_page_size_validate (log2_page_sz);
      size_t page_bytes = clib_mem_page_bytes (log2_page_sz);
      region_size = round_pow2 (memory_size, page_bytes);
      char map_name[64];
      const char *use_name = name && name[0] ? name : "heap";
      snprintf (map_name, sizeof (map_name), "%s", use_name);
      base = clib_mem_vm_map_internal (0, log2_page_sz, region_size, -1,
				       mi_min_align_log2, 0, map_name);
      if (base == CLIB_MEM_VM_MAP_FAILED)
	return 0;
      owns_mapping = 1;
    }
  else
    log2_page_sz = CLIB_MEM_PAGE_SZ_UNKNOWN;

  clib_memset (base, 0, region_size);

  if (!mi_manage_os_memory_ex (base, region_size, 0 /* is_committed */,
			       0 /* is_large */, 0 /* is_zero */,
			       -1 /* numa */, 0 /* exclusive */, &arena_id))
    goto error;

  mi_heap = mi_heap_new_in_arena (arena_id);
  if (!mi_heap)
    goto error;

  heap = mi_heap_malloc_small (mi_heap, sizeof (clib_mem_heap_t) + name_len);
  if (!heap)
    goto error;

  *heap = (clib_mem_heap_t){
    .base = base,
    .mi_heap = mi_heap,
    .size = region_size,
    .log2_page_sz = log2_page_sz,
    .locked = is_locked ? 1 : 0,
    .unmap_on_destroy = owns_mapping ? 1 : 0,
    .traced = 0,
    .arena_id = arena_id,
  };

  char *dst = (char *) (heap + 1);
  if (name && name[0])
    memcpy (dst, name, name_len);
  else
    dst[0] = 0;

  if (set_current)
    {
      clib_mem_set_heap (heap);
      mi_heap_set_default (mi_heap);
    }

  return heap;

error:
  if (heap)
    mi_free (heap);
  if (mi_heap)
    mi_heap_delete (mi_heap);
  if (owns_mapping && base && base != CLIB_MEM_VM_MAP_FAILED)
    clib_mem_vm_unmap (base);
  return 0;
}

static void *
clib_mem_heap_alloc_internal (void *heap_handle, uword size, uword align,
			      int fail_on_oom)
{
  clib_mem_heap_t *heap = heap_handle ? heap_handle : clib_mem_get_heap ();
  mi_heap_t *mi_heap;
  void *p;

  if (heap == 0)
    {
      if (fail_on_oom)
	os_out_of_memory ();
      return 0;
    }

  mi_heap = heap->mi_heap;
  if (mi_heap == 0)
    {
      if (fail_on_oom)
	os_out_of_memory ();
      return 0;
    }

  if (heap->traced)
    CLIB_MEM_MIMALLOC_STUB ();

  align = clib_max (align, (uword) CLIB_MEM_MIN_ALIGN);
  ASSERT (is_pow2 (align));

  p = mi_heap_malloc_aligned (mi_heap, (size_t) size, (size_t) align);

  if (PREDICT_FALSE (p == 0))
    {
      if (fail_on_oom)
	os_out_of_memory ();
      return 0;
    }

  clib_mem_unpoison (p, size);
  return p;
}

typedef struct
{
  uword used_full;
  uword used_user;
  uword reserved;
  uword committed;
  uword used_count;
} clib_mi_usage_t;

static bool
clib_mimalloc_area_accumulate (const mi_heap_t *mi_heap,
			       const mi_heap_area_t *area, void *block,
			       size_t block_size, void *arg)
{
  clib_mi_usage_t *stats = (clib_mi_usage_t *) arg;

  /* We request visit_blocks = false, so block should always be NULL. */
  if (block != 0)
    return true;

  stats->reserved += (uword) area->reserved;
  stats->committed += (uword) area->committed;
  stats->used_count += (uword) area->used;
  stats->used_user += (uword) area->used * (uword) area->block_size;
  stats->used_full += (uword) area->used * (uword) area->full_block_size;
  return true;
}

static bool
clib_mimalloc_collect_stats (clib_mem_heap_t *heap, clib_mi_usage_t *stats)
{
  if (stats)
    clib_memset (stats, 0, sizeof (*stats));

  if (heap == 0 || heap->mi_heap == 0)
    return false;

  return mi_heap_visit_blocks (heap->mi_heap, false,
			       clib_mimalloc_area_accumulate, stats);
}

static bool
clib_mimalloc_fill_usage (clib_mem_heap_t *heap, clib_mem_usage_t *usage,
			  clib_mi_usage_t *stats_out)
{
  clib_mi_usage_t stats = { 0 };
  uword total = 0;
  uword used = 0;
  uword committed = 0;
  bool have_stats;

  clib_memset (usage, 0, sizeof (*usage));
  if (stats_out)
    clib_memset (stats_out, 0, sizeof (*stats_out));

  if (heap == 0)
    return false;

  total = heap->size;
  usage->bytes_total = total;
  usage->bytes_max = total;

  have_stats = clib_mimalloc_collect_stats (heap, &stats);
  if (!have_stats)
    {
      if (stats_out)
	*stats_out = stats;
      return false;
    }

  if (stats.reserved != 0)
    {
      if (heap->size != 0)
	total = clib_min ((uword) stats.reserved, heap->size);
      else
	total = (uword) stats.reserved;
      usage->bytes_total = total;
      usage->bytes_max = total;
    }

  used = stats.used_full;
  if (used > total)
    used = total;

  committed = stats.committed;
  if (committed > total)
    committed = total;

  uword used_user = stats.used_user;
  if (used_user > used)
    used_user = used;

  usage->object_count = stats.used_count;
  usage->bytes_used = used;
  usage->bytes_free = total > used ? total - used : 0;
  usage->bytes_overhead = used > used_user ? used - used_user : 0;
  usage->bytes_free_reclaimed = total > committed ? total - committed : 0;
  usage->bytes_used_sbrk = 0;
  usage->bytes_used_mmap = committed;

  if (stats_out)
    *stats_out = stats;

  return true;
}

__clib_export void *
clib_mem_init (void *memory, uword memory_size)
{
  fprintf (stderr, "%s: memory %p memory_size %lu\n", __func__, memory,
	   memory_size);

  return clib_mem_heap_create_internal (
    memory, memory_size, CLIB_MEM_PAGE_SZ_DEFAULT, 1, "main heap", 1);
}

__clib_export void *
clib_mem_init_with_page_size (uword memory_size,
			      clib_mem_page_sz_t log2_page_sz)
{
  return clib_mem_heap_create_internal (0, memory_size, log2_page_sz, 1,
					"main heap", 1);
}

__clib_export void *
clib_mem_init_thread_safe (void *memory, uword memory_size)
{
  return clib_mem_heap_create_internal (
    memory, memory_size, CLIB_MEM_PAGE_SZ_DEFAULT, 1, "main heap", 1);
}

__clib_export void
clib_mem_destroy (void)
{
  clib_mem_heap_t *heap = clib_mem_get_heap ();
  clib_mem_heap_t copy = *heap;
  clib_mem_set_heap (0);

  if (heap->mi_heap)
    mi_heap_delete (heap->mi_heap);

  if (heap->unmap_on_destroy && copy.base &&
      copy.base != CLIB_MEM_VM_MAP_FAILED)
    clib_mem_vm_unmap (copy.base);
}

__clib_export u8 *
format_clib_mem_usage (u8 *s, va_list *va)
{
  (void) s;
  (void) va;
  CLIB_MEM_MIMALLOC_STUB ();
  return 0;
}

__clib_export u8 *
format_clib_mem_heap (u8 *s, va_list *va)
{
  clib_mem_heap_t *heap = va_arg (*va, clib_mem_heap_t *);
  int verbose = va_arg (*va, int);
  clib_mem_usage_t usage;
  clib_mi_usage_t stats;
  bool have_stats;
  u32 indent;

  if (heap == 0)
    heap = clib_mem_get_heap ();

  if (heap == 0)
    return format (s, "no heap");

  indent = format_get_indent (s) + 2;
  have_stats = clib_mimalloc_fill_usage (heap, &usage, &stats);

  s =
    format (s, "base %p, size %U", heap->base, format_memory_size, heap->size);

  if (heap->locked)
    s = format (s, ", locked");
  if (heap->unmap_on_destroy)
    s = format (s, ", unmap-on-destroy");
  if (heap->traced)
    s = format (s, ", traced");
  if (heap->arena_id != 0)
    s = format (s, ", arena %llu", (unsigned long long) heap->arena_id);
  s = format (s, ", name '%s'", heap->name);

  if (heap->log2_page_sz != CLIB_MEM_PAGE_SZ_UNKNOWN && heap->base)
    {
      clib_mem_page_stats_t page_stats;
      clib_mem_get_page_stats (heap->base, heap->log2_page_sz,
			       heap->size >> heap->log2_page_sz, &page_stats);
      s = format (s, "\n%U%U", format_white_space, indent,
		  format_clib_mem_page_stats, &page_stats);
    }

  s =
    format (s, "\n%Utotal: %U, used: %U, free: %U", format_white_space, indent,
	    format_memory_size, usage.bytes_total, format_memory_size,
	    usage.bytes_used, format_memory_size, usage.bytes_free);
  s = format (
    s, "\n%Ucommitted: %U, reclaimed: %U, overhead: %U", format_white_space,
    indent, format_memory_size, usage.bytes_used_mmap, format_memory_size,
    usage.bytes_free_reclaimed, format_memory_size, usage.bytes_overhead);

  if (verbose > 0 && have_stats)
    {
      uword internal = (stats.used_full > stats.used_user) ?
			 stats.used_full - stats.used_user :
			 0;
      s = format (s, "\n%Ublocks: %llu, payload: %U, internal: %U",
		  format_white_space, indent + 2,
		  (unsigned long long) stats.used_count, format_memory_size,
		  stats.used_user, format_memory_size, internal);
      s = format (s, "\n%Ureserved: %U, committed: %U", format_white_space,
		  indent + 2, format_memory_size, stats.reserved,
		  format_memory_size, stats.committed);
    }

  return s;
}

__clib_export void
clib_mem_get_heap_usage (clib_mem_heap_t *heap, clib_mem_usage_t *usage)
{
  clib_mimalloc_fill_usage (heap, usage, 0);
}

__clib_export void
mheap_trace (clib_mem_heap_t *heap, int enable)
{
  (void) heap;
  (void) enable;
  CLIB_MEM_MIMALLOC_STUB ();
}

__clib_export void
clib_mem_trace (int enable)
{
  (void) enable;
  CLIB_MEM_MIMALLOC_STUB ();
}

__clib_export int
clib_mem_is_traced (void)
{
  CLIB_MEM_MIMALLOC_STUB ();
  return 0;
}

__clib_export uword
clib_mem_trace_enable_disable (uword enable)
{
  (void) enable;
  CLIB_MEM_MIMALLOC_STUB ();
  return 0;
}

__clib_export mheap_trace_t *
clib_mem_trace_dup (clib_mem_heap_t *heap)
{
  (void) heap;
  CLIB_MEM_MIMALLOC_STUB ();
  return 0;
}

__clib_export clib_mem_heap_t *
clib_mem_create_heap (void *base, uword size, int is_locked, char *fmt, ...)
{
  clib_mem_heap_t *heap;
  char *name;
  u8 *s = 0;
  clib_mem_page_sz_t log2_page_sz = clib_mem_get_log2_page_size ();

  if (fmt == 0)
    name = "";
  else if (strchr (fmt, '%'))
    {
      va_list va;
      va_start (va, fmt);
      s = va_format (0, fmt, &va);
      vec_add1 (s, 0);
      va_end (va);
      name = (char *) s;
    }
  else
    name = fmt;

  heap = clib_mem_heap_create_internal (base, size, log2_page_sz, is_locked,
					name, 0);
  vec_free (s);
  return heap;
}

__clib_export void
clib_mem_destroy_heap (clib_mem_heap_t *heap)
{
  (void) heap;
  CLIB_MEM_MIMALLOC_STUB ();
}

__clib_export uword
clib_mem_get_heap_free_space (clib_mem_heap_t *heap)
{
  clib_mi_usage_t usage = { 0 };
  uword total_size;

  if (heap == 0 || heap->mi_heap == 0)
    return 0;

  total_size = heap->size;

  if (!mi_heap_visit_blocks (heap->mi_heap, false,
			     clib_mimalloc_area_accumulate, &usage))
    return 0;

  if (usage.used_full >= total_size)
    return 0;

  return total_size - usage.used_full;
}

__clib_export void *
clib_mem_get_heap_base (clib_mem_heap_t *heap)
{
  if (heap == 0)
    return 0;
  return heap->base;
}

__clib_export uword
clib_mem_get_heap_size (clib_mem_heap_t *heap)
{
  if (heap == 0)
    return 0;
  return heap->size;
}

__clib_export void *
clib_mem_alloc (uword size)
{
  return clib_mem_heap_alloc_internal (0, size, CLIB_MEM_MIN_ALIGN, 1);
}

__clib_export void *
clib_mem_alloc_or_null (uword size)
{
  return clib_mem_heap_alloc_internal (0, size, CLIB_MEM_MIN_ALIGN, 0);
}

__clib_export void *
clib_mem_alloc_aligned (uword size, uword align)
{
  return clib_mem_heap_alloc_internal (0, size, align, 1);
}

__clib_export void *
clib_mem_alloc_aligned_or_null (uword size, uword align)
{
  return clib_mem_heap_alloc_internal (0, size, align, 0);
}

__clib_export void *
clib_mem_heap_alloc (void *heap, uword size)
{
  return clib_mem_heap_alloc_internal (heap, size, CLIB_MEM_MIN_ALIGN, 1);
}

__clib_export void *
clib_mem_heap_alloc_aligned (void *heap, uword size, uword align)
{
  return clib_mem_heap_alloc_internal (heap, size, align, 1);
}

__clib_export void *
clib_mem_heap_alloc_or_null (void *heap, uword size)
{
  return clib_mem_heap_alloc_internal (heap, size, CLIB_MEM_MIN_ALIGN, 0);
}

__clib_export void *
clib_mem_heap_alloc_aligned_or_null (void *heap, uword size, uword align)
{
  return clib_mem_heap_alloc_internal (heap, size, align, 0);
}

__clib_export void *
clib_mem_heap_realloc_aligned (void *heap, void *p, uword new_size,
			       uword align)
{
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_heap ();
  mi_heap_t *mi_heap;
  size_t old_size = 0;
  void *new_ptr;

  if (h == 0)
    {
      if (new_size && align)
	os_out_of_memory ();
      return 0;
    }

  mi_heap = h->mi_heap;
  if (mi_heap == 0)
    {
      if (new_size && align)
	os_out_of_memory ();
      return 0;
    }

  align = clib_max (align, (uword) CLIB_MEM_MIN_ALIGN);
  ASSERT (is_pow2 (align));

  if (p == 0)
    return clib_mem_heap_alloc_internal (h, new_size, align, 1);

  old_size = mi_usable_size (p);

  if (new_size == old_size)
    return p;

  if (new_size == 0)
    {
      if (old_size)
	clib_mem_unpoison (p, old_size);
      mi_free (p);
      return 0;
    }

  new_ptr =
    mi_heap_realloc_aligned (mi_heap, p, (size_t) new_size, (size_t) align);

  if (PREDICT_FALSE (new_ptr == 0))
    {
      os_out_of_memory ();
      return 0;
    }

  clib_mem_unpoison (new_ptr, new_size);
  return new_ptr;
}

__clib_export void *
clib_mem_heap_realloc (void *heap, void *p, uword new_size)
{
  return clib_mem_heap_realloc_aligned (heap, p, new_size, CLIB_MEM_MIN_ALIGN);
}

__clib_export void *
clib_mem_realloc_aligned (void *p, uword new_size, uword align)
{
  return clib_mem_heap_realloc_aligned (0, p, new_size, align);
}

__clib_export void *
clib_mem_realloc (void *p, uword new_size)
{
  return clib_mem_heap_realloc_aligned (0, p, new_size, CLIB_MEM_MIN_ALIGN);
}

__clib_export uword
clib_mem_heap_is_heap_object (void *heap, void *p)
{
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_per_cpu_heap ();

  if (h == 0 || h->mi_heap == 0 || p == 0)
    return 0;

  return mi_heap_contains_block (h->mi_heap, p);
}

__clib_export uword
clib_mem_is_heap_object (void *p)
{
  return clib_mem_heap_is_heap_object (0, p);
}

__clib_export void
clib_mem_heap_free (void *heap, void *p)
{
  clib_mem_heap_t *h;
  mi_heap_t *mi_heap;
  uword size;

  if (!p)
    return;

  h = heap ? heap : clib_mem_get_heap ();
  if (h == 0)
    {
      mi_free (p);
      return;
    }

  mi_heap = h->mi_heap;
  if (mi_heap == 0)
    {
      mi_free (p);
      return;
    }

  if (PREDICT_FALSE (h->traced))
    CLIB_MEM_MIMALLOC_STUB ();

  ASSERT (mi_heap_contains_block (mi_heap, p));

  size = clib_mem_size (p);
  clib_mem_poison (p, size);
  mi_free (p);
}

__clib_export void
clib_mem_free (void *p)
{
  clib_mem_heap_free (0, p);
}

__clib_export uword
clib_mem_size (void *p)
{
  if (!p)
    return 0;

  return (uword) mi_usable_size (p);
}

__clib_export void
clib_mem_free_s (void *p)
{
  (void) p;
  CLIB_MEM_MIMALLOC_STUB ();
}

__clib_export u8 *
format_clib_mem_heap_name (u8 *s, va_list *va)
{
  clib_mem_heap_t *h = va_arg (*va, clib_mem_heap_t *);
  return format (s, "%s", h->name);
}
