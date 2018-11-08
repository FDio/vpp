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

void *clib_per_cpu_mheaps[CLIB_MAX_MHEAPS];

typedef struct
{
  /* Address of callers: outer first, inner last. */
  uword callers[12];

  /* Count of allocations with this traceback. */
#if CLIB_VEC64 > 0
  u64 n_allocations;
#else
  u32 n_allocations;
#endif

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

  if (tm->enabled == 0)
    return;

  /* Spurious Coverity warnings be gone. */
  memset (&trace, 0, sizeof (trace));

  /* Skip our frame and mspace_get_aligned's frame */
  n_callers = clib_backtrace (trace.callers, ARRAY_LEN (trace.callers), 2);
  if (n_callers == 0)
    return;

  /* $$$ This looks like dreck to remove... */
  if (0)
    for (i = n_callers; i < ARRAY_LEN (trace.callers); i++)
      trace.callers[i] = 0;

  clib_spinlock_lock (&tm->lock);

  /* Turn off tracing to avoid embarrassment... */
  save_enabled = tm->enabled;
  tm->enabled = 0;

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
	  _vec_len (tm->trace_free_list) = i - 1;
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
      memset (t, 0, sizeof (t[0]));
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

/* Initialize CLIB heap based on memory/size given by user.
   Set memory to 0 and CLIB will try to allocate its own heap. */
void *
clib_mem_init (void *memory, uword memory_size)
{
  u8 *heap;

  if (memory)
    {
      heap = create_mspace_with_base (memory, memory_size, 1 /* locked */ );
      mspace_disable_expand (heap);
    }
  else
    heap = create_mspace (memory_size, 1 /* locked */ );

  clib_mem_set_heap (heap);

  if (mheap_trace_main.lock == 0)
    clib_spinlock_init (&mheap_trace_main.lock);

  return heap;
}

void *
clib_mem_init_thread_safe (void *memory, uword memory_size)
{
  return clib_mem_init (memory, memory_size);
}

#ifdef CLIB_LINUX_KERNEL
#include <asm/page.h>

uword
clib_mem_get_page_size (void)
{
  return PAGE_SIZE;
}
#endif

#ifdef CLIB_UNIX
uword
clib_mem_get_page_size (void)
{
  return getpagesize ();
}
#endif

/* Make a guess for standalone. */
#ifdef CLIB_STANDALONE
uword
clib_mem_get_page_size (void)
{
  return 4096;
}
#endif

u8 *
format_clib_mem_usage (u8 * s, va_list * va)
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
  if (vec_len (tm->traces) > 0)
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


u8 *
format_mheap (u8 * s, va_list * va)
{
  void *heap = va_arg (*va, u8 *);
  int verbose = va_arg (*va, int);
  struct dlmallinfo mi;
  mheap_trace_main_t *tm = &mheap_trace_main;

  mi = mspace_mallinfo (heap);

  s = format (s, "total: %U, used: %U, free: %U, trimmable: %U",
	      format_msize, mi.arena,
	      format_msize, mi.uordblks,
	      format_msize, mi.fordblks, format_msize, mi.keepcost);
  if (verbose > 0)
    {
      s = format (s, "\n    free chunks %llu free fastbin blks %llu",
		  mi.ordblks, mi.smblks);
      s =
	format (s, "\n    max total allocated %U", format_msize, mi.usmblks);
    }

  s = format (s, "\n%U", format_mheap_trace, tm, verbose);
  return s;
}

void
clib_mem_usage (clib_mem_usage_t * u)
{
  clib_warning ("unimp");
}

/* Call serial number for debugger breakpoints. */
uword clib_mem_validate_serial = 0;

void
clib_mem_validate (void)
{
  clib_warning ("unimp");
}

void
mheap_trace (void *v, int enable)
{
  (void) mspace_enable_disable_trace (v, enable);

  if (enable == 0)
    mheap_trace_main_free (&mheap_trace_main);
}

void
clib_mem_trace (int enable)
{
  mheap_trace_main_t *tm = &mheap_trace_main;

  tm->enabled = enable;
  mheap_trace (clib_mem_get_heap (), enable);
}

uword
clib_mem_trace_enable_disable (uword enable)
{
  uword rv;
  mheap_trace_main_t *tm = &mheap_trace_main;

  rv = tm->enabled;
  tm->enabled = enable;
  return rv;
}

/*
 * These API functions seem like layering violations, but
 * by introducing them we greatly reduce the number
 * of code changes required to use dlmalloc spaces
 */
void *
mheap_alloc_with_lock (void *memory, uword size, int locked)
{
  void *rv;
  if (memory == 0)
    return create_mspace (size, locked);
  else
    {
      rv = create_mspace_with_base (memory, size, locked);
      if (rv)
	mspace_disable_expand (rv);
      return rv;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
