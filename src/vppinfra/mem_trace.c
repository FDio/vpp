/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2025 Cisco and/or its affiliates.
 */

#include <vppinfra/format.h>
#include <vppinfra/os.h>
#include <vppinfra/lock.h>
#include <vppinfra/hash.h>
#include <vppinfra/stack.h>
#include <vppinfra/elf_clib.h>

typedef struct clib_mem_trace_main_t
{
  u8 lock;

  clib_mem_trace_t *traces;

  /* Indices of free traces. */
  u32 *trace_free_list;

  /* Hash table mapping callers to trace index. */
  uword *trace_by_callers;

  /* Hash table mapping heap offset to trace index. */
  uword *trace_index_by_offset;

  /* So we can easily shut off current segment trace, if any */
  clib_mem_heap_t *current_traced_heap;

} clib_mem_trace_main_t;

clib_mem_trace_main_t clib_mem_trace_main;

void
clib_mem_trace_get (const clib_mem_heap_t *heap, uword offset, uword size)
{
  clib_mem_trace_main_t *tm = &clib_mem_trace_main;
  clib_mem_trace_t *t;
  uword i, trace_index, *p;
  clib_mem_trace_t trace = {};
  int n_callers;

  if (heap != tm->current_traced_heap ||
      clib_mem_thread_main.trace_thread_disable)
    return;

  CLIB_SPINLOCK_LOCK (tm->lock);

  /* heap could have changed while we were waiting on the lock */
  if (heap != tm->current_traced_heap)
    goto out;

  /* Turn off tracing for this thread to avoid embarrassment... */
  clib_mem_thread_main.trace_thread_disable = 1;

  /* Skip our frame and mspace_get_aligned's frame */
  n_callers =
    clib_stack_frame_get_raw (trace.callers, ARRAY_LEN (trace.callers), 2);
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
	  clib_mem_trace_t *old_start = tm->traces;
	  clib_mem_trace_t *old_end = vec_end (tm->traces);

	  vec_add2 (tm->traces, t, 1);

	  if (tm->traces != old_start)
	    {
	      hash_pair_t *p;
	      clib_mem_trace_t *q;
	      hash_foreach_pair (
		p, tm->trace_by_callers, ({
		  q = uword_to_pointer (p->key, clib_mem_trace_t *);
		  ASSERT (q >= old_start && q < old_end);
		  p->key = pointer_to_uword (tm->traces + (q - old_start));
		}));
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
  t->offset = offset; /* keep a sample to autopsy */
  hash_set (tm->trace_index_by_offset, offset, t - tm->traces);

out:
  clib_mem_thread_main.trace_thread_disable = 0;
  CLIB_SPINLOCK_UNLOCK (tm->lock);
}

void
clib_mem_trace_put (const clib_mem_heap_t *heap, uword offset, uword size)
{
  clib_mem_trace_t *t;
  uword trace_index, *p;
  clib_mem_trace_main_t *tm = &clib_mem_trace_main;

  if (heap != tm->current_traced_heap ||
      clib_mem_thread_main.trace_thread_disable)
    return;

  CLIB_SPINLOCK_LOCK (tm->lock);

  /* heap could have changed while we were waiting on the lock */
  if (heap != tm->current_traced_heap)
    goto out;

  /* Turn off tracing for this thread for a moment */
  clib_mem_thread_main.trace_thread_disable = 1;

  p = hash_get (tm->trace_index_by_offset, offset);
  if (!p)
    goto out;

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

out:
  clib_mem_thread_main.trace_thread_disable = 0;
  CLIB_SPINLOCK_UNLOCK (tm->lock);
}

always_inline void
clib_mem_trace_main_free (clib_mem_trace_main_t *tm)
{
  ASSERT (tm->lock);
  tm->current_traced_heap = 0;
  vec_free (tm->traces);
  vec_free (tm->trace_free_list);
  hash_free (tm->trace_by_callers);
  hash_free (tm->trace_index_by_offset);
  clib_mem_thread_main.trace_thread_disable = 0;
}

static int
clib_mem_trace_sort (const void *_t1, const void *_t2)
{
  const clib_mem_trace_t *t1 = _t1;
  const clib_mem_trace_t *t2 = _t2;
  word cmp;

  cmp = (word) t2->n_bytes - (word) t1->n_bytes;
  if (!cmp)
    cmp = (word) t2->n_allocations - (word) t1->n_allocations;
  return cmp;
}

u8 *
format_clib_mem_trace (u8 *s, va_list *va)
{
  clib_mem_trace_main_t *tm = va_arg (*va, clib_mem_trace_main_t *);
  int verbose = va_arg (*va, int);
  int have_traces = 0;
  int i;
  int n = 0;

  CLIB_SPINLOCK_LOCK (tm->lock);
  if (vec_len (tm->traces) > 0 &&
      clib_mem_get_heap () == tm->current_traced_heap)
    {
      have_traces = 1;

      /* Make a copy of traces since we'll be sorting them. */
      clib_mem_trace_t *t, *traces_copy;
      u32 indent, total_objects_traced;

      traces_copy = vec_dup (tm->traces);

      qsort (traces_copy, vec_len (traces_copy), sizeof (traces_copy[0]),
	     clib_mem_trace_sort);

      total_objects_traced = 0;
      s = format (s, "\n");
      vec_foreach (t, traces_copy)
	{
	  /* Skip over free elements. */
	  if (t->n_allocations == 0)
	    continue;

	  total_objects_traced += t->n_allocations;

	  /* When not verbose only report the 50 biggest allocations */
	  if (!verbose && n >= 50)
	    continue;
	  n++;

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
	      s = format (s, " %U\n", format_clib_elf_symbol_with_address,
			  t->callers[i]);
#else
	      s = format (s, " %p\n", t->callers[i]);
#endif
	    }
	}

      s = format (s, "%d total traced objects\n", total_objects_traced);

      vec_free (traces_copy);
    }
  CLIB_SPINLOCK_UNLOCK (tm->lock);
  if (have_traces == 0)
    s = format (s, "no traced allocations\n");

  return s;
}

__clib_export void
clib_mem_trace_heap (clib_mem_heap_t *h, int enable)
{
  clib_mem_trace_main_t *tm = &clib_mem_trace_main;

  CLIB_SPINLOCK_LOCK (tm->lock);

  if (tm->current_traced_heap != 0 && tm->current_traced_heap != h)
    {
      clib_warning ("tracing already enabled for another heap, ignoring");
      goto out;
    }

  if (enable)
    {
      clib_mem_heap_set_trace (h, 1);
      tm->current_traced_heap = h;
    }
  else
    {
      clib_mem_heap_set_trace (h, 0);
      clib_mem_trace_main_free (&clib_mem_trace_main);
    }

out:
  CLIB_SPINLOCK_UNLOCK (tm->lock);
}

__clib_export void
clib_mem_trace (int enable)
{
  void *current_heap = clib_mem_get_heap ();
  clib_mem_trace_heap (current_heap, enable);
}

__clib_export uword
clib_mem_trace_enable_disable (uword enable)
{
  uword rv = !clib_mem_thread_main.trace_thread_disable;
  clib_mem_thread_main.trace_thread_disable = !enable;
  return rv;
}

__clib_export clib_mem_trace_t *
clib_mem_trace_dup (clib_mem_heap_t *heap)
{
  clib_mem_trace_main_t *tm = &clib_mem_trace_main;
  clib_mem_trace_t *traces_copy = 0;

  CLIB_SPINLOCK_LOCK (tm->lock);
  if (vec_len (tm->traces) > 0 && heap == tm->current_traced_heap)
    {
      traces_copy = vec_dup (tm->traces);
      qsort (traces_copy, vec_len (traces_copy), sizeof (traces_copy[0]),
	     clib_mem_trace_sort);
    }
  CLIB_SPINLOCK_UNLOCK (tm->lock);
  return traces_copy;
}

clib_mem_trace_main_t *
clib_mem_trace_get_main ()
{
  return &clib_mem_trace_main;
}

clib_mem_heap_t *
clib_mem_trace_get_current_heap ()
{
  clib_mem_trace_main_t *tm = &clib_mem_trace_main;
  return tm->current_traced_heap;
}
