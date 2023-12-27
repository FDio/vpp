/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2025 Cisco and/or its affiliates.
 */

#include <vppinfra/format.h>
#include <vppinfra/dlmalloc.h>
#include <vppinfra/os.h>
#include <vppinfra/lock.h>
#include <vppinfra/hash.h>
#include <vppinfra/stack.h>

#define foreach_clib_mem_heap_flag                                            \
  _ (locked, "locked")                                                        \
  _ (traced, "traced")                                                        \
  _ (unmap_on_destroy, "unmap-on-destroy")

struct clib_mem_heap_t
{
  /* base address */
  void *base;

  /* dlmalloc mspace */
  void *mspace;

  /* heap size */
  uword size;

  /* page size (log2) */
  clib_mem_page_sz_t log2_page_sz : 8;

  /* flags */
#define _(f, str) u8 f : 1;
  foreach_clib_mem_heap_flag;
#undef _

  /* name - _MUST_ be last */
  char name[0];
};

static clib_mem_heap_t *
clib_mem_create_heap_internal (void *base, uword size,
			       clib_mem_page_sz_t log2_page_sz, int is_locked,
			       char *name)
{
  clib_mem_heap_t h = {}, *hp;
  size_t sz;
  size_t align = __alignof (clib_mem_heap_t);

  if (base == 0)
    {
      log2_page_sz = clib_mem_log2_page_size_validate (log2_page_sz);
      size = round_pow2 (size, clib_mem_page_bytes (log2_page_sz));
      base = clib_mem_vm_map_internal (0, log2_page_sz, size, -1, 0, 0,
				       "main heap");

      if (base == CLIB_MEM_VM_MAP_FAILED)
	return 0;

      h.unmap_on_destroy = 1;
    }
  else
    {
      clib_mem_vm_map_hdr_t *hdr = 0;
      log2_page_sz = clib_mem_get_log2_page_size ();
      while ((hdr = clib_mem_vm_get_next_map_hdr (hdr)))
	{
	  if (pointer_to_uword (base) >= hdr->base_addr &&
	      pointer_to_uword (base) <
		hdr->base_addr + (hdr->num_pages << hdr->log2_page_sz))
	    log2_page_sz = hdr->log2_page_sz;
	}
    }

  if (is_locked)
    h.locked = 1;

  h.base = base;
  h.size = size;
  h.log2_page_sz = log2_page_sz;
  h.mspace = create_mspace_with_base (base, size, is_locked);
  mspace_disable_expand (h.mspace);
  clib_mem_poison (mspace_least_addr (h.mspace), mspace_footprint (h.mspace));

  sz = round_pow2 (sizeof (clib_mem_heap_t) + strlen (name) + 1, align);
  hp = mspace_memalign (h.mspace, align, sz);
  clib_mem_unpoison (hp, sz);
  *hp = h;

  strcpy (hp->name, name);

  if (clib_mem_main.heaps)
    {
      clib_mem_heap_t *old = clib_mem_get_heap ();
      clib_mem_set_heap (clib_mem_main.main_heap);
      vec_add1 (clib_mem_main.heaps, hp);
      clib_mem_set_heap (old);
    }

  return hp;
}

/* Initialize CLIB heap based on memory/size given by user.
   Set memory to 0 and CLIB will try to allocate its own heap. */
static void *
clib_mem_init_internal (clib_mem_init_ex_args_t *a)
{
  clib_mem_heap_t *h;

  clib_mem_main_init ();

  h = clib_mem_create_heap_internal (a->base_addr, a->memory_size,
				     a->log2_page_sz, 1 /*is_locked */,
				     "main heap");

  ASSERT (clib_mem_main.main_heap == 0);
  ASSERT (clib_mem_main.heaps == 0);
  clib_mem_main.main_heap = h;
  clib_mem_main.heaps = 0;
  clib_mem_thread_init ();
  clib_mem_set_heap (h);
  vec_add1 (clib_mem_main.heaps, h);
  clib_mem_main.alloc_free_intercept = a->alloc_free_intercept;

  return h;
}

__clib_export void *
clib_mem_init (void *memory, uword memory_size)
{
  return clib_mem_init_internal (&(clib_mem_init_ex_args_t){
    .base_addr = memory,
    .memory_size = memory_size,
    .log2_page_sz = CLIB_MEM_PAGE_SZ_DEFAULT,
  });
}

__clib_export void *
clib_mem_init_ex (clib_mem_init_ex_args_t *a)
{
  return clib_mem_init_internal (a);
}

__clib_export void
clib_mem_destroy (void)
{
  clib_mem_main_t *mm = &clib_mem_main;
  clib_mem_heap_t *heap = clib_mem_main.main_heap;
  clib_mem_thread_main_t *t = clib_mem_main.threads;

  if (heap == clib_mem_trace_get_current_heap ())
    clib_mem_trace_heap (heap, 0);

  for (int i = vec_len (clib_mem_main.heaps) - 1; i >= 0; i--)
    clib_mem_destroy_heap (clib_mem_main.heaps[i]);

  clib_mem_set_heap (0);
  clib_mem_main.main_heap = 0;
  mm->alloc_free_intercept = 0;

  while (t)
    {
      clib_mem_thread_main_t *n = t->next;
      *t = (clib_mem_thread_main_t){};
      t = n;
    }
}

__clib_export u8 *
format_clib_mem_usage (u8 *s, va_list *va)
{
  int verbose = va_arg (*va, int);
  return format (s, "$$$$ heap at %llx verbose %d", clib_mem_get_heap (),
		 verbose);
}

/*
 * Magic decoder ring for mallinfo stats (ala dlmalloc):
 *
 * size_t arena;     / * Non-mmapped space allocated (bytes) * /
 * size_t ordblks;   / * Number of free chunks * /
 * size_t smblks;    / * Number of free fastbin blocks * /
 * size_t hblks;     / * Number of mmapped regions * /
 * size_t hblkhd;    / * Space allocated in mmapped regions (bytes) * /
 * size_t usmblks;   / * Maximum total allocated space (bytes) * /
 * size_t fsmblks;   / * Space in freed fastbin blocks (bytes) * /
 * size_t uordblks;  / * Total allocated space (bytes) * /
 * size_t fordblks;  / * Total free space (bytes) * /
 * size_t keepcost;  / * Top-most, releasable space (bytes) * /
 *
 */

u8 *
format_msize (u8 * s, va_list * va)
{
  uword a = va_arg (*va, uword);

  if (a >= 1ULL << 30)
    s = format (s, "%.2fG", (((f64) a) / ((f64) (1ULL << 30))));
  else if (a >= 1ULL << 20)
    s = format (s, "%.2fM", (((f64) a) / ((f64) (1ULL << 20))));
  else if (a >= 1ULL << 10)
    s = format (s, "%.2fK", (((f64) a) / ((f64) (1ULL << 10))));
  else
    s = format (s, "%lld", a);
  return s;
}

__clib_export u8 *
format_clib_mem_heap (u8 * s, va_list * va)
{
  clib_mem_heap_t *heap = va_arg (*va, clib_mem_heap_t *);
  int verbose = va_arg (*va, int);
  struct dlmallinfo mi;
  u32 indent = format_get_indent (s) + 2;

  if (heap == 0)
    heap = clib_mem_get_heap ();

  mi = mspace_mallinfo_slow (heap->mspace);

  s = format (s, "base %p, size %U",
	      heap->base, format_memory_size, heap->size);

#define _(f, str)                                                             \
  if (heap->f)                                                                \
    s = format (s, ", %s", str);
  foreach_clib_mem_heap_flag;
#undef _

  s = format (s, ", name '%s'", heap->name);

  if (heap->log2_page_sz != CLIB_MEM_PAGE_SZ_UNKNOWN)
    {
      clib_mem_page_stats_t stats;
      uword page_size = 1ull << heap->log2_page_sz;
      uword base = round_down_pow2 (pointer_to_uword (heap->base), page_size);
      uword n_pages = round_pow2 (heap->size, page_size) >> heap->log2_page_sz;
      clib_mem_get_page_stats ((void *) base, heap->log2_page_sz, n_pages,
			       &stats);
      s = format (s, "\n%U%U", format_white_space, indent,
		  format_clib_mem_page_stats, &stats);
    }

  s = format (s, "\n%Utotal: %U, used: %U, free: %U, trimmable: %U",
	      format_white_space, indent,
	      format_msize, mi.arena,
	      format_msize, mi.uordblks,
	      format_msize, mi.fordblks, format_msize, mi.keepcost);
  if (verbose > 0)
    {
      s = format (s, "\n%Ufree chunks %llu free fastbin blks %llu",
		  format_white_space, indent + 2, mi.ordblks, mi.smblks);
      s = format (s, "\n%Umax total allocated %U",
		  format_white_space, indent + 2, format_msize, mi.usmblks);
    }

  if (heap->traced)
    s = format (s, "\n%U", format_clib_mem_trace, clib_mem_trace_get_main (),
		verbose);
  return s;
}

__clib_export __clib_flatten void
clib_mem_get_heap_usage (clib_mem_heap_t *heap, clib_mem_usage_t *usage)
{
  struct dlmallinfo mi = mspace_mallinfo_fast (heap->mspace);

  usage->bytes_total = mi.arena; /* non-mmapped space allocated from system */
  usage->bytes_used = mi.uordblks;	    /* total allocated space */
  usage->bytes_free = mi.fordblks;	    /* total free space */
  usage->bytes_used_mmap = mi.hblkhd;	    /* space in mmapped regions */
  usage->bytes_max = mi.usmblks;	    /* maximum total allocated space */
  usage->bytes_overhead = mi.keepcost; /* releasable (via malloc_trim) space */

  /* Not supported */
  usage->bytes_used_sbrk = 0;
  usage->object_count = 0;
  usage->bytes_free_reclaimed = 0;
}

/* Call serial number for debugger breakpoints. */
uword clib_mem_validate_serial = 0;

int
clib_mem_is_traced (void)
{
  clib_mem_heap_t *h = clib_mem_get_heap ();
  return (h->traced) != 0;
}

__clib_export clib_mem_heap_t *
clib_mem_create_heap (void *base, uword size, int is_locked, char *fmt, ...)
{
  clib_mem_page_sz_t log2_page_sz = clib_mem_get_log2_page_size ();
  clib_mem_heap_t *h;
  char *name;
  u8 *s = 0;

  if (fmt == 0)
    {
      name = "";
    }
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

  h = clib_mem_create_heap_internal (base, size, log2_page_sz, is_locked,
				     name);
  vec_free (s);
  return h;
}

__clib_export void
clib_mem_destroy_heap (clib_mem_heap_t * h)
{
  if (h->mspace == clib_mem_trace_get_current_heap ())
    clib_mem_trace_heap (h, 0);

  for (u32 i = 0; i < vec_len (clib_mem_main.heaps); i++)
    if (clib_mem_main.heaps[i] == h)
      {
      vec_del1 (clib_mem_main.heaps, i);
      if (vec_len (clib_mem_main.heaps) == 0)
	vec_free (clib_mem_main.heaps);
      break;
      }

  destroy_mspace (h->mspace);
  if (h->unmap_on_destroy)
    clib_mem_vm_unmap (h->base);
}

__clib_export __clib_flatten uword
clib_mem_get_heap_free_space (clib_mem_heap_t *h)
{
  struct dlmallinfo dlminfo = mspace_mallinfo_fast (h->mspace);
  return dlminfo.fordblks;
}

__clib_export __clib_flatten void *
clib_mem_get_heap_base (clib_mem_heap_t *h)
{
  return h->base;
}

__clib_export __clib_flatten uword
clib_mem_get_heap_size (clib_mem_heap_t *heap)
{
  return heap->size;
}

/* Memory allocator which may call os_out_of_memory() if it fails */
static inline void *
clib_mem_heap_alloc_inline (void *heap, uword size, uword align,
			    int os_out_of_memory_on_failure)
{
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_heap ();
  void *p;

  align = clib_max (CLIB_MEM_MIN_ALIGN, align);

  p = mspace_memalign (h->mspace, align, size);

  if (PREDICT_FALSE (0 == p))
    {
      if (os_out_of_memory_on_failure)
	os_out_of_memory ();
      return 0;
    }

  if (PREDICT_FALSE (h->traced))
    clib_mem_trace_get (h, pointer_to_uword (p), clib_mem_size (p));

  clib_mem_unpoison (p, size);
  return p;
}

/* Memory allocator which calls os_out_of_memory() when it fails */
__clib_export __clib_flatten void *
clib_mem_alloc (uword size)
{
  return clib_mem_heap_alloc_inline (0, size, CLIB_MEM_MIN_ALIGN,
				     /* os_out_of_memory */ 1);
}

__clib_export __clib_flatten void *
clib_mem_alloc_aligned (uword size, uword align)
{
  return clib_mem_heap_alloc_inline (0, size, align,
				     /* os_out_of_memory */ 1);
}

/* Memory allocator which calls os_out_of_memory() when it fails */
__clib_export __clib_flatten void *
clib_mem_alloc_or_null (uword size)
{
  return clib_mem_heap_alloc_inline (0, size, CLIB_MEM_MIN_ALIGN,
				     /* os_out_of_memory */ 0);
}

__clib_export __clib_flatten void *
clib_mem_alloc_aligned_or_null (uword size, uword align)
{
  return clib_mem_heap_alloc_inline (0, size, align,
				     /* os_out_of_memory */ 0);
}

__clib_export __clib_flatten void *
clib_mem_heap_alloc (void *heap, uword size)
{
  return clib_mem_heap_alloc_inline (heap, size, CLIB_MEM_MIN_ALIGN,
				     /* os_out_of_memory */ 1);
}

__clib_export __clib_flatten void *
clib_mem_heap_alloc_aligned (void *heap, uword size, uword align)
{
  return clib_mem_heap_alloc_inline (heap, size, align,
				     /* os_out_of_memory */ 1);
}

__clib_export __clib_flatten void *
clib_mem_heap_alloc_or_null (void *heap, uword size)
{
  return clib_mem_heap_alloc_inline (heap, size, CLIB_MEM_MIN_ALIGN,
				     /* os_out_of_memory */ 0);
}

__clib_export __clib_flatten void *
clib_mem_heap_alloc_aligned_or_null (void *heap, uword size, uword align)
{
  return clib_mem_heap_alloc_inline (heap, size, align,
				     /* os_out_of_memory */ 0);
}

__clib_export __clib_flatten void *
clib_mem_heap_realloc_aligned (void *heap, void *p, uword new_size,
			       uword align)
{
  uword old_alloc_size;
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_heap ();
  void *new;

  ASSERT (count_set_bits (align) == 1);

  old_alloc_size = p ? mspace_usable_size (p) : 0;

  if (new_size == old_alloc_size)
    return p;

  if (p && pointer_is_aligned (p, align) &&
      mspace_realloc_in_place (h->mspace, p, new_size))
    {
      clib_mem_unpoison (p, new_size);
      if (PREDICT_FALSE (h->traced))
	{
	clib_mem_trace_put (h, pointer_to_uword (p), old_alloc_size);
	clib_mem_trace_get (h, pointer_to_uword (p), clib_mem_size (p));
	}
    }
  else
    {
      new = clib_mem_heap_alloc_inline (h, new_size, align, 1);

      clib_mem_unpoison (new, new_size);
      if (old_alloc_size)
	{
	  clib_mem_unpoison (p, old_alloc_size);
	  clib_memcpy_fast (new, p, clib_min (new_size, old_alloc_size));
	  clib_mem_heap_free (h, p);
	}
      p = new;
    }

  return p;
}

__clib_export __clib_flatten void *
clib_mem_heap_realloc (void *heap, void *p, uword new_size)
{
  return clib_mem_heap_realloc_aligned (heap, p, new_size, CLIB_MEM_MIN_ALIGN);
}

__clib_export __clib_flatten void *
clib_mem_realloc_aligned (void *p, uword new_size, uword align)
{
  return clib_mem_heap_realloc_aligned (0, p, new_size, align);
}

__clib_export __clib_flatten void *
clib_mem_realloc (void *p, uword new_size)
{
  return clib_mem_heap_realloc_aligned (0, p, new_size, CLIB_MEM_MIN_ALIGN);
}

__clib_export __clib_flatten uword
clib_mem_heap_is_heap_object (void *heap, void *p)
{
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_heap ();
  return mspace_is_heap_object (h->mspace, p);
}

__clib_export __clib_flatten uword
clib_mem_is_heap_object (void *p)
{
  return clib_mem_heap_is_heap_object (0, p);
}

__clib_export __clib_flatten void
clib_mem_heap_free (void *heap, void *p)
{
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_heap ();
  uword size = clib_mem_size (p);

  /* Make sure object is in the correct heap. */
  ASSERT (clib_mem_heap_is_heap_object (h, p));

  if (PREDICT_FALSE (h->traced))
    clib_mem_trace_put (h, pointer_to_uword (p), size);
  clib_mem_poison (p, clib_mem_size (p));

  mspace_free (h->mspace, p);
}

__clib_export __clib_flatten void
clib_mem_free (void *p)
{
  clib_mem_heap_free (0, p);
}

__clib_export __clib_flatten uword
clib_mem_size (void *p)
{
  return mspace_usable_size (p);
}

__clib_export void
clib_mem_free_s (void *p)
{
  uword size = clib_mem_size (p);
  clib_mem_unpoison (p, size);
  memset_s_inline (p, size, 0, size);
  clib_mem_free (p);
}
__clib_export u8 *
format_clib_mem_heap_name (u8 *s, va_list *va)
{
  clib_mem_heap_t *h = va_arg (*va, clib_mem_heap_t *);
  return format (s, "%s", h->name);
}

void
clib_mem_heap_set_trace (clib_mem_heap_t *h, int enabled)
{
  h->traced = (enabled != 0);
}
