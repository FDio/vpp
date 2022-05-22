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

#include <vppinfra/format.h>
#include <vppinfra/dlmalloc.h>
#include <vppinfra/os.h>
#include <vppinfra/lock.h>
#include <vppinfra/hash.h>
#include <vppinfra/elf_clib.h>

typedef struct
{
  /* Address of callers: outer first, inner last. */
  uword callers[12];

  /* Count of allocations with this traceback. */
  u32 n_allocations;

  /* Count of bytes allocated with this traceback. */
  u32 n_bytes;

  /* Offset of this item */
  uword offset;
} mheap_trace_t;

typedef struct
{
  clib_spinlock_t lock;
  uword enabled;

  mheap_trace_t *traces;

  /* Indices of free traces. */
  u32 *trace_free_list;

  /* Hash table mapping callers to trace index. */
  uword *trace_by_callers;

  /* Hash table mapping mheap offset to trace index. */
  uword *trace_index_by_offset;

  /* So we can easily shut off current segment trace, if any */
  void *current_traced_mheap;

} mheap_trace_main_t;

mheap_trace_main_t mheap_trace_main;

void
mheap_get_trace (uword offset, uword size)
{
  mheap_trace_main_t *tm = &mheap_trace_main;
  mheap_trace_t *t;
  uword i, n_callers, trace_index, *p;
  mheap_trace_t trace;
  uword save_enabled;

  if (tm->enabled == 0 || (clib_mem_get_heap () != tm->current_traced_mheap))
    return;

  /* Spurious Coverity warnings be gone. */
  clib_memset (&trace, 0, sizeof (trace));

  clib_spinlock_lock (&tm->lock);

  /* Turn off tracing to avoid embarrassment... */
  save_enabled = tm->enabled;
  tm->enabled = 0;

  /* Skip our frame and mspace_get_aligned's frame */
  n_callers = clib_backtrace (trace.callers, ARRAY_LEN (trace.callers), 2);
  if (n_callers == 0)
    goto out;

  if (!tm->trace_by_callers)
    tm->trace_by_callers =
      hash_create_shmem (0, sizeof (trace.callers), sizeof (uword));

  p = hash_get_mem (tm->trace_by_callers, &trace.callers);
  if (p)
    {
      trace_index = p[0];
      t = tm->traces + trace_index;
    }
  else
    {
      i = vec_len (tm->trace_free_list);
      if (i > 0)
	{
	  trace_index = tm->trace_free_list[i - 1];
	  vec_set_len (tm->trace_free_list, i - 1);
	}
      else
	{
	  mheap_trace_t *old_start = tm->traces;
	  mheap_trace_t *old_end = vec_end (tm->traces);

	  vec_add2 (tm->traces, t, 1);

	  if (tm->traces != old_start)
	    {
	      hash_pair_t *p;
	      mheap_trace_t *q;
            /* *INDENT-OFF* */
	    hash_foreach_pair (p, tm->trace_by_callers,
            ({
              q = uword_to_pointer (p->key, mheap_trace_t *);
              ASSERT (q >= old_start && q < old_end);
	      p->key = pointer_to_uword (tm->traces + (q - old_start));
	    }));
            /* *INDENT-ON* */
	    }
	  trace_index = t - tm->traces;
	}

      t = tm->traces + trace_index;
      t[0] = trace;
      t->n_allocations = 0;
      t->n_bytes = 0;
      hash_set_mem (tm->trace_by_callers, t->callers, trace_index);
    }

  t->n_allocations += 1;
  t->n_bytes += size;
  t->offset = offset;		/* keep a sample to autopsy */
  hash_set (tm->trace_index_by_offset, offset, t - tm->traces);

out:
  tm->enabled = save_enabled;
  clib_spinlock_unlock (&tm->lock);
}

void
mheap_put_trace (uword offset, uword size)
{
  mheap_trace_t *t;
  uword trace_index, *p;
  mheap_trace_main_t *tm = &mheap_trace_main;
  uword save_enabled;

  if (tm->enabled == 0)
    return;

  clib_spinlock_lock (&tm->lock);

  /* Turn off tracing for a moment */
  save_enabled = tm->enabled;
  tm->enabled = 0;

  p = hash_get (tm->trace_index_by_offset, offset);
  if (!p)
    {
      tm->enabled = save_enabled;
      clib_spinlock_unlock (&tm->lock);
      return;
    }

  trace_index = p[0];
  hash_unset (tm->trace_index_by_offset, offset);
  ASSERT (trace_index < vec_len (tm->traces));

  t = tm->traces + trace_index;
  ASSERT (t->n_allocations > 0);
  ASSERT (t->n_bytes >= size);
  t->n_allocations -= 1;
  t->n_bytes -= size;
  if (t->n_allocations == 0)
    {
      hash_unset_mem (tm->trace_by_callers, t->callers);
      vec_add1 (tm->trace_free_list, trace_index);
      clib_memset (t, 0, sizeof (t[0]));
    }
  tm->enabled = save_enabled;
  clib_spinlock_unlock (&tm->lock);
}

always_inline void
mheap_trace_main_free (mheap_trace_main_t * tm)
{
  vec_free (tm->traces);
  vec_free (tm->trace_free_list);
  hash_free (tm->trace_by_callers);
  hash_free (tm->trace_index_by_offset);
}

static clib_mem_heap_t *
clib_mem_create_heap_internal (void *base, uword size,
			       clib_mem_page_sz_t log2_page_sz, int is_locked,
			       char *name)
{
  clib_mem_heap_t *h;
  u8 flags = 0;
  int sz = sizeof (clib_mem_heap_t);

  if (base == 0)
    {
      log2_page_sz = clib_mem_log2_page_size_validate (log2_page_sz);
      size = round_pow2 (size, clib_mem_page_bytes (log2_page_sz));
      base = clib_mem_vm_map_internal (0, log2_page_sz, size, -1, 0,
				       "main heap");

      if (base == CLIB_MEM_VM_MAP_FAILED)
	return 0;

      flags = CLIB_MEM_HEAP_F_UNMAP_ON_DESTROY;
    }
  else
    log2_page_sz = CLIB_MEM_PAGE_SZ_UNKNOWN;

  if (is_locked)
    flags |= CLIB_MEM_HEAP_F_LOCKED;

  h = base;
  h->base = base;
  h->size = size;
  h->log2_page_sz = log2_page_sz;
  h->flags = flags;
  sz = strlen (name);
  strcpy (h->name, name);
  sz = round_pow2 (sz + sizeof (clib_mem_heap_t), 16);
  h->mspace = create_mspace_with_base (base + sz, size - sz, is_locked);

  mspace_disable_expand (h->mspace);

  clib_mem_poison (mspace_least_addr (h->mspace),
		   mspace_footprint (h->mspace));

  return h;
}

/* Initialize CLIB heap based on memory/size given by user.
   Set memory to 0 and CLIB will try to allocate its own heap. */
static void *
clib_mem_init_internal (void *base, uword size,
			clib_mem_page_sz_t log2_page_sz)
{
  clib_mem_heap_t *h;

  clib_mem_main_init ();

  h = clib_mem_create_heap_internal (base, size, log2_page_sz,
				     1 /*is_locked */ , "main heap");

  clib_mem_set_heap (h);

  if (mheap_trace_main.lock == 0)
    clib_spinlock_init (&mheap_trace_main.lock);

  return h;
}

__clib_export void *
clib_mem_init (void *memory, uword memory_size)
{
  return clib_mem_init_internal (memory, memory_size,
				 CLIB_MEM_PAGE_SZ_DEFAULT);
}

__clib_export void *
clib_mem_init_with_page_size (uword memory_size,
			      clib_mem_page_sz_t log2_page_sz)
{
  return clib_mem_init_internal (0, memory_size, log2_page_sz);
}

__clib_export void *
clib_mem_init_thread_safe (void *memory, uword memory_size)
{
  return clib_mem_init_internal (memory, memory_size,
				 CLIB_MEM_PAGE_SZ_DEFAULT);
}

__clib_export void
clib_mem_destroy (void)
{
  mheap_trace_main_t *tm = &mheap_trace_main;
  clib_mem_heap_t *heap = clib_mem_get_heap ();

  if (tm->enabled && heap->mspace == tm->current_traced_mheap)
    tm->enabled = 0;

  destroy_mspace (heap->mspace);
  clib_mem_vm_unmap (heap);
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

static int
mheap_trace_sort (const void *_t1, const void *_t2)
{
  const mheap_trace_t *t1 = _t1;
  const mheap_trace_t *t2 = _t2;
  word cmp;

  cmp = (word) t2->n_bytes - (word) t1->n_bytes;
  if (!cmp)
    cmp = (word) t2->n_allocations - (word) t1->n_allocations;
  return cmp;
}

u8 *
format_mheap_trace (u8 * s, va_list * va)
{
  mheap_trace_main_t *tm = va_arg (*va, mheap_trace_main_t *);
  int verbose = va_arg (*va, int);
  int have_traces = 0;
  int i;

  clib_spinlock_lock (&tm->lock);
  if (vec_len (tm->traces) > 0 &&
      clib_mem_get_heap () == tm->current_traced_mheap)
    {
      have_traces = 1;

      /* Make a copy of traces since we'll be sorting them. */
      mheap_trace_t *t, *traces_copy;
      u32 indent, total_objects_traced;

      traces_copy = vec_dup (tm->traces);

      qsort (traces_copy, vec_len (traces_copy), sizeof (traces_copy[0]),
	     mheap_trace_sort);

      total_objects_traced = 0;
      s = format (s, "\n");
      vec_foreach (t, traces_copy)
      {
	/* Skip over free elements. */
	if (t->n_allocations == 0)
	  continue;

	total_objects_traced += t->n_allocations;

	/* When not verbose only report allocations of more than 1k. */
	if (!verbose && t->n_bytes < 1024)
	  continue;

	if (t == traces_copy)
	  s = format (s, "%=9s%=9s %=10s Traceback\n", "Bytes", "Count",
		      "Sample");
	s = format (s, "%9d%9d %p", t->n_bytes, t->n_allocations, t->offset);
	indent = format_get_indent (s);
	for (i = 0; i < ARRAY_LEN (t->callers) && t->callers[i]; i++)
	  {
	    if (i > 0)
	      s = format (s, "%U", format_white_space, indent);
#if defined(CLIB_UNIX) && !defined(__APPLE__)
	    /* $$$$ does this actually work? */
	    s =
	      format (s, " %U\n", format_clib_elf_symbol_with_address,
		      t->callers[i]);
#else
	    s = format (s, " %p\n", t->callers[i]);
#endif
	  }
      }

      s = format (s, "%d total traced objects\n", total_objects_traced);

      vec_free (traces_copy);
    }
  clib_spinlock_unlock (&tm->lock);
  if (have_traces == 0)
    s = format (s, "no traced allocations\n");

  return s;
}

__clib_export u8 *
format_clib_mem_heap (u8 * s, va_list * va)
{
  clib_mem_heap_t *heap = va_arg (*va, clib_mem_heap_t *);
  int verbose = va_arg (*va, int);
  struct dlmallinfo mi;
  mheap_trace_main_t *tm = &mheap_trace_main;
  u32 indent = format_get_indent (s) + 2;

  if (heap == 0)
    heap = clib_mem_get_heap ();

  mi = mspace_mallinfo (heap->mspace);

  s = format (s, "base %p, size %U",
	      heap->base, format_memory_size, heap->size);

#define _(i,v,str) \
  if (heap->flags & CLIB_MEM_HEAP_F_##v) s = format (s, ", %s", str);
  foreach_clib_mem_heap_flag;
#undef _

  s = format (s, ", name '%s'", heap->name);

  if (heap->log2_page_sz != CLIB_MEM_PAGE_SZ_UNKNOWN)
    {
      clib_mem_page_stats_t stats;
      clib_mem_get_page_stats (heap->base, heap->log2_page_sz,
			       heap->size >> heap->log2_page_sz, &stats);
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

  if (heap->flags & CLIB_MEM_HEAP_F_TRACED)
    s = format (s, "\n%U", format_mheap_trace, tm, verbose);
  return s;
}

__clib_export __clib_flatten void
clib_mem_get_heap_usage (clib_mem_heap_t *heap, clib_mem_usage_t *usage)
{
  struct dlmallinfo mi = mspace_mallinfo (heap->mspace);

  usage->bytes_total = mi.arena; /* non-mmapped space allocated from system */
  usage->bytes_used = mi.uordblks;	    /* total allocated space */
  usage->bytes_free = mi.fordblks;	    /* total free space */
  usage->bytes_used_mmap = mi.hblkhd;	    /* space in mmapped regions */
  usage->bytes_max = mi.usmblks;	    /* maximum total allocated space */
  usage->bytes_free_reclaimed = mi.ordblks; /* number of free chunks */
  usage->bytes_overhead = mi.keepcost; /* releasable (via malloc_trim) space */

  /* Not supported */
  usage->bytes_used_sbrk = 0;
  usage->object_count = 0;
}

/* Call serial number for debugger breakpoints. */
uword clib_mem_validate_serial = 0;

__clib_export void
mheap_trace (clib_mem_heap_t * h, int enable)
{
  if (enable)
    h->flags |= CLIB_MEM_HEAP_F_TRACED;
  else
    h->flags &= ~CLIB_MEM_HEAP_F_TRACED;

  if (enable == 0)
    mheap_trace_main_free (&mheap_trace_main);
}

__clib_export void
clib_mem_trace (int enable)
{
  mheap_trace_main_t *tm = &mheap_trace_main;
  void *current_heap = clib_mem_get_heap ();

  tm->enabled = enable;
  mheap_trace (current_heap, enable);

  if (enable)
    tm->current_traced_mheap = current_heap;
  else
    tm->current_traced_mheap = 0;
}

int
clib_mem_is_traced (void)
{
  clib_mem_heap_t *h = clib_mem_get_heap ();
  return (h->flags &= CLIB_MEM_HEAP_F_TRACED) != 0;
}

__clib_export uword
clib_mem_trace_enable_disable (uword enable)
{
  uword rv;
  mheap_trace_main_t *tm = &mheap_trace_main;

  rv = tm->enabled;
  tm->enabled = enable;
  return rv;
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
  mheap_trace_main_t *tm = &mheap_trace_main;

  if (tm->enabled && h->mspace == tm->current_traced_mheap)
    tm->enabled = 0;

  destroy_mspace (h->mspace);
  if (h->flags & CLIB_MEM_HEAP_F_UNMAP_ON_DESTROY)
    clib_mem_vm_unmap (h->base);
}

__clib_export __clib_flatten uword
clib_mem_get_heap_free_space (clib_mem_heap_t *h)
{
  struct dlmallinfo dlminfo = mspace_mallinfo (h->mspace);
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
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_per_cpu_heap ();
  void *p;

  align = clib_max (CLIB_MEM_MIN_ALIGN, align);

  p = mspace_memalign (h->mspace, align, size);

  if (PREDICT_FALSE (0 == p))
    {
      if (os_out_of_memory_on_failure)
	os_out_of_memory ();
      return 0;
    }

  if (PREDICT_FALSE (h->flags & CLIB_MEM_HEAP_F_TRACED))
    mheap_get_trace (pointer_to_uword (p), clib_mem_size (p));

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
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_per_cpu_heap ();
  void *new;

  ASSERT (count_set_bits (align) == 1);

  old_alloc_size = p ? mspace_usable_size (p) : 0;

  if (new_size == old_alloc_size)
    return p;

  if (p && pointer_is_aligned (p, align) &&
      mspace_realloc_in_place (h->mspace, p, new_size))
    {
      clib_mem_unpoison (p, new_size);
      if (PREDICT_FALSE (h->flags & CLIB_MEM_HEAP_F_TRACED))
	{
	  mheap_put_trace (pointer_to_uword (p), old_alloc_size);
	  mheap_get_trace (pointer_to_uword (p), clib_mem_size (p));
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
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_per_cpu_heap ();
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
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_per_cpu_heap ();
  uword size = clib_mem_size (p);

  /* Make sure object is in the correct heap. */
  ASSERT (clib_mem_heap_is_heap_object (h, p));

  if (PREDICT_FALSE (h->flags & CLIB_MEM_HEAP_F_TRACED))
    mheap_put_trace (pointer_to_uword (p), size);
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
