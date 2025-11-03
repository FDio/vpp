/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2025 Cisco and/or its affiliates.
 */

#include <vppinfra/format.h>
#include <vppinfra/dlmalloc.h>
#include <vppinfra/os.h>
#include <vppinfra/lock.h>
#include <vppinfra/hash.h>
#include <vppinfra/elf_clib.h>
#include <vppinfra/stack.h>

#define CLIB_MEM_SLAB_LOG2_SZ 16
static const u32 slab_class_sizes[] = { 16, 32, 64 };

typedef union
{
  struct
  {
    u64 slab_addr : (64 - CLIB_MEM_SLAB_LOG2_SZ);
    u64 slab_slot : CLIB_MEM_SLAB_LOG2_SZ;
  };
  u64 as_u64;
} clib_mem_slab_slot_t;

static_always_inline int
clib_mem_slab_class_from_size (uword size)
{
  for (int i = 0; i < ARRAY_LEN (slab_class_sizes); i++)
    if (size <= slab_class_sizes[i])
      return i;
  return -1;
}

typedef struct clib_mem_slab_thread_t clib_mem_slab_thread_t;
typedef struct clib_mem_slab_t clib_mem_slab_t;

struct clib_mem_slab_t
{
#define CLIB_MEM_SLAB_COOKIE 0xf19a7e2ca1b9f1b4ULL
  u64 cookie;
  u32 chunk_size;
  u32 n_free;
  u32 n_chunks;
  u8 class_index;
  clib_thread_index_t thread_index;
  clib_mem_heap_t *heap;
  clib_mem_slab_thread_t *heap_thread;
  clib_mem_slab_t *next;
} __clib_aligned (CLIB_CACHE_LINE_BYTES);

struct clib_mem_slab_thread_t
{
  clib_thread_index_t thread_index;
  clib_mem_heap_t *heap;
  struct
  {
    clib_mem_slab_t *slabs;
    clib_mem_slab_slot_t local_free;
    clib_mem_slab_slot_t remote_free;
  } classes[ARRAY_LEN (slab_class_sizes)];
};

static_always_inline clib_mem_slab_slot_t
clib_mem_slab_slot_encode (clib_mem_slab_t *slab, u32 slot)
{
  return (clib_mem_slab_slot_t){
    .slab_addr = pointer_to_uword (slab) >> CLIB_MEM_SLAB_LOG2_SZ,
    .slab_slot = slot,
  };
}

static_always_inline clib_mem_slab_t *
clib_mem_slab_slot_decode (clib_mem_slab_slot_t s)
{
  return uword_to_pointer ((s.slab_addr << CLIB_MEM_SLAB_LOG2_SZ),
			   clib_mem_slab_t *);
}

static_always_inline clib_mem_slab_slot_t *
clib_mem_slab_slot_ptr (clib_mem_slab_t *slab, u32 slot)
{
  return (clib_mem_slab_slot_t *) (((u8 *) slab) +
				   ((uword) slot * slab->chunk_size));
}

#define foreach_clib_mem_heap_flag                                            \
  _ (locked, "locked")                                                        \
  _ (slab, "slab")                                                            \
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

  /* per-thread mains */
  clib_thread_index_t n_threads;
  u8 thread_array_lock;
  clib_mem_slab_thread_t **threads;

  /* name - _MUST_ be last */
  char name[0];
};

typedef struct
{
  clib_spinlock_t lock;

  mheap_trace_t *traces;

  /* Indices of free traces. */
  u32 *trace_free_list;

  /* Hash table mapping callers to trace index. */
  uword *trace_by_callers;

  /* Hash table mapping mheap offset to trace index. */
  uword *trace_index_by_offset;

  /* So we can easily shut off current segment trace, if any */
  const clib_mem_heap_t *current_traced_mheap;

} mheap_trace_main_t;

mheap_trace_main_t mheap_trace_main;

static_always_inline clib_mem_slab_t *
clib_mem_slab_new (clib_mem_slab_thread_t *thread, u32 chunk_size)
{
  clib_mem_heap_t *h;
  clib_mem_slab_t *slab;
  uword slab_size = ((uword) 1) << CLIB_MEM_SLAB_LOG2_SZ;
  u32 total_slots;
  int class_index;
  uword slab_uword;
  uword header_end;
  u32 first_slot;

  h = thread->heap;

  chunk_size = clib_max (chunk_size, (u32) CLIB_MEM_MIN_ALIGN);
  chunk_size = round_pow2 (chunk_size, CLIB_MEM_MIN_ALIGN);

  class_index = clib_mem_slab_class_from_size (chunk_size);

  slab = mspace_memalign (h->mspace, slab_size, slab_size);
  if (PREDICT_FALSE (slab == 0))
    return 0;

  clib_mem_unpoison (slab, slab_size);

  slab_uword = pointer_to_uword (slab);
  header_end = pointer_to_uword (slab + 1);
  total_slots = slab_size / chunk_size;
  first_slot = (u32) ((header_end - slab_uword + chunk_size - 1) / chunk_size);

  if (PREDICT_FALSE (first_slot >= total_slots))
    {
      mspace_free (h->mspace, slab);
      return 0;
    }

  u32 slots = total_slots - first_slot;
  typeof (thread->classes[0]) *class = thread->classes + class_index;

  *slab = (clib_mem_slab_t){
    .cookie = CLIB_MEM_SLAB_COOKIE,
    .chunk_size = chunk_size,
    .n_free = slots,
    .n_chunks = slots,
    .class_index = (u8) class_index,
    .thread_index = thread->thread_index,
    .heap = h,
    .heap_thread = thread,
    .next = class->slabs,
  };

  clib_mem_slab_slot_t tail = class->local_free;
  for (u32 slot = total_slots; slot-- > first_slot;)
    {
      clib_mem_slab_slot_t *entry = clib_mem_slab_slot_ptr (slab, slot);
      entry->as_u64 = tail.as_u64;
      tail = clib_mem_slab_slot_encode (slab, slot);
    }

  class->local_free = tail;

  clib_mem_poison (((u8 *) slab) + ((uword) first_slot * chunk_size),
		   (uword) slots * chunk_size);

  class->slabs = slab;
  return slab;
}

static_always_inline void
clib_mem_slab_thread_init (clib_mem_heap_t *h, clib_thread_index_t ti)
{
  void *p;

  ASSERT (h->slab == 1);

  CLIB_SPINLOCK_LOCK (h->thread_array_lock);

  if (ti >= h->n_threads)
    {
      u32 old_n = h->n_threads;
      u32 n = ti + 1;
      u32 sz = sizeof (clib_mem_slab_thread_t *);

      p = mspace_realloc (h->mspace, h->threads, n * sz);

      if (PREDICT_FALSE (p == 0))
	goto done;

      h->threads = p;
      clib_memset (h->threads + old_n, 0, (n - old_n) * sz);
      h->n_threads = n;
    }

  if (h->threads[ti] == 0)
    {
      p = mspace_memalign (h->mspace, __alignof(clib_mem_slab_thread_t),
			   sizeof (clib_mem_slab_thread_t));

      if (PREDICT_FALSE (p == 0))
	goto done;

      h->threads[ti] = p;

      *h->threads[ti] = (clib_mem_slab_thread_t){
	.thread_index = ti,
	.heap = h,
      };

      for (int ci = 0; ci < ARRAY_LEN (slab_class_sizes); ci++)
	{
	  h->threads[ti]->classes[ci].slabs = 0;
	  h->threads[ti]->classes[ci].local_free.as_u64 = 0;
	  h->threads[ti]->classes[ci].remote_free.as_u64 = 0;
	}
    }

done:
  CLIB_SPINLOCK_UNLOCK (h->thread_array_lock);
}

static_always_inline clib_mem_slab_thread_t *
clib_mem_slab_get_thread (clib_mem_heap_t *h)
{
  clib_thread_index_t ti = os_get_thread_index ();
  static __thread clib_mem_heap_t *cached_heap = 0;
  static __thread clib_mem_slab_thread_t *cached_thread = 0;
  clib_mem_slab_thread_t *t = 0;

  if (cached_heap == h && cached_thread != 0)
    return cached_thread;

  CLIB_SPINLOCK_LOCK (h->thread_array_lock);
  t = h->threads[ti];
  CLIB_SPINLOCK_UNLOCK (h->thread_array_lock);

  cached_heap = h, cached_thread = t;

  return t;
}

static void
mheap_get_trace_internal (const clib_mem_heap_t *heap, uword offset,
			  uword size)
{
  mheap_trace_main_t *tm = &mheap_trace_main;
  mheap_trace_t *t;
  uword i, trace_index, *p;
  mheap_trace_t trace = {};
  int n_callers;

  if (heap != tm->current_traced_mheap ||
      clib_mem_thread_main.mheap_trace_thread_disable)
    return;

  clib_spinlock_lock (&tm->lock);

  /* heap could have changed while we were waiting on the lock */
  if (heap != tm->current_traced_mheap)
    goto out;

  /* Turn off tracing for this thread to avoid embarrassment... */
  clib_mem_thread_main.mheap_trace_thread_disable = 1;

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
	  mheap_trace_t *old_start = tm->traces;
	  mheap_trace_t *old_end = vec_end (tm->traces);

	  vec_add2 (tm->traces, t, 1);

	  if (tm->traces != old_start)
	    {
	      hash_pair_t *p;
	      mheap_trace_t *q;
	    hash_foreach_pair (p, tm->trace_by_callers,
            ({
              q = uword_to_pointer (p->key, mheap_trace_t *);
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
  t->offset = offset;		/* keep a sample to autopsy */
  hash_set (tm->trace_index_by_offset, offset, t - tm->traces);

out:
  clib_mem_thread_main.mheap_trace_thread_disable = 0;
  clib_spinlock_unlock (&tm->lock);
}

static void
mheap_put_trace_internal (const clib_mem_heap_t *heap, uword offset,
			  uword size)
{
  mheap_trace_t *t;
  uword trace_index, *p;
  mheap_trace_main_t *tm = &mheap_trace_main;

  if (heap != tm->current_traced_mheap ||
      clib_mem_thread_main.mheap_trace_thread_disable)
    return;

  clib_spinlock_lock (&tm->lock);

  /* heap could have changed while we were waiting on the lock */
  if (heap != tm->current_traced_mheap)
    goto out;

  /* Turn off tracing for this thread for a moment */
  clib_mem_thread_main.mheap_trace_thread_disable = 1;

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
  clib_mem_thread_main.mheap_trace_thread_disable = 0;
  clib_spinlock_unlock (&tm->lock);
}

void
mheap_get_trace (uword offset, uword size)
{
  mheap_get_trace_internal (clib_mem_get_heap (), offset, size);
}

void
mheap_put_trace (uword offset, uword size)
{
  mheap_put_trace_internal (clib_mem_get_heap (), offset, size);
}

always_inline void
mheap_trace_main_free (mheap_trace_main_t * tm)
{
  CLIB_SPINLOCK_ASSERT_LOCKED (&tm->lock);
  tm->current_traced_mheap = 0;
  vec_free (tm->traces);
  vec_free (tm->trace_free_list);
  hash_free (tm->trace_by_callers);
  hash_free (tm->trace_index_by_offset);
  clib_mem_thread_main.mheap_trace_thread_disable = 0;
}

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

  h.base = base;
  h.size = size;
  h.log2_page_sz = log2_page_sz;
  h.locked = is_locked != 0,
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

static_always_inline clib_mem_slab_t *
clib_mem_slab_get_from_ptr (void *p)
{
  uword addr = pointer_to_uword (p);
  uword slab_mask = (((uword) 1) << CLIB_MEM_SLAB_LOG2_SZ) - 1;
  clib_mem_slab_t *slab =
    uword_to_pointer (addr & ~slab_mask, clib_mem_slab_t *);
  if (slab->cookie == CLIB_MEM_SLAB_COOKIE)
    return slab;
  return 0;
}

static_always_inline void *
clib_mem_slab_alloc (uword size, uword align)
{
  clib_mem_heap_t *h = clib_mem_get_heap ();
  clib_mem_slab_thread_t *thread;
  uword need = size;
  int class_index;
  u8 *chunk;
  clib_mem_slab_slot_t head;
  clib_mem_slab_t *slab;
  clib_mem_slab_slot_t *next;
  clib_mem_slab_slot_t next_head;
  u32 slot;

  if (align > need)
    need = align;

  class_index = clib_mem_slab_class_from_size (need);
  if (class_index < 0)
    return 0;

  if (PREDICT_FALSE (h == 0 || h->slab == 0))
    return 0;

  thread = clib_mem_slab_get_thread (h);

  if (PREDICT_FALSE (thread == 0))
    {
      clib_mem_slab_thread_init (h, os_get_thread_index ());
      thread = clib_mem_slab_get_thread (h);
      if (PREDICT_FALSE (thread == 0))
	return 0;
    }

  typeof (thread->classes[0]) *class = thread->classes + class_index;

  if (__atomic_load_n (&class->remote_free.as_u64, __ATOMIC_RELAXED))
    {
      u64 head =
	__atomic_exchange_n (&class->remote_free.as_u64, 0, __ATOMIC_ACQUIRE);
      clib_mem_slab_slot_t node = (clib_mem_slab_slot_t){ .as_u64 = head };
      clib_mem_slab_slot_t *tail_next = 0;

      while (1)
	{
	  slab = clib_mem_slab_slot_decode (node);
	  slot = node.slab_slot;
	  next = clib_mem_slab_slot_ptr (slab, slot);
	  u8 *slot_chunk = (u8 *) next;

	  clib_mem_unpoison (slot_chunk, slab->chunk_size);
	  slab->n_free++;

	  clib_mem_slab_slot_t next_node = *next;
	  clib_mem_poison (slot_chunk, slab->chunk_size);

	  if (next_node.as_u64 == 0)
	    {
	      tail_next = next;
	      break;
	    }

	  node = next_node;
	}

      ASSERT (tail_next != 0);
      tail_next->as_u64 = class->local_free.as_u64;
      class->local_free.as_u64 = head;
    }

  if (class->local_free.as_u64 == 0)
    {
      clib_mem_slab_t *new_slab =
	clib_mem_slab_new (thread, slab_class_sizes[class_index]);
      if (PREDICT_FALSE (new_slab == 0))
	return 0;
    }

  if (class->local_free.as_u64 == 0)
    return 0;

  head = class->local_free;
  slab = clib_mem_slab_slot_decode (head);
  slot = head.slab_slot;
  next = clib_mem_slab_slot_ptr (slab, slot);
  chunk = (u8 *) next;

  clib_mem_unpoison (chunk, slab->chunk_size);
  next_head = *next;
  class->local_free = next_head;
  *next = (clib_mem_slab_slot_t){ .as_u64 = 0 };
  ASSERT (slab->n_free > 0);
  slab->n_free--;
  return chunk;
}

static_always_inline int
clib_mem_slab_free (void *p)
{
  clib_mem_slab_t *slab = clib_mem_slab_get_from_ptr (p);
  clib_mem_slab_slot_t node, *next;
  typeof (slab->heap_thread->classes[0]) *class;
  u64 head, *rfree;
  u32 index;

  if (!slab)
    return 0;

  index = (u32) ((pointer_to_uword (p) - pointer_to_uword (slab)) /
		 slab->chunk_size);
  class = slab->heap_thread->classes + slab->class_index;
  node = clib_mem_slab_slot_encode (slab, index);
  next = clib_mem_slab_slot_ptr (slab, index);

  if (os_get_thread_index () == slab->thread_index)
    {
      next->as_u64 = class->local_free.as_u64;
      class->local_free = node;
      slab->n_free++;
      ASSERT (slab->n_free <= slab->n_chunks);
      goto done;
    }

  rfree = &class->remote_free.as_u64;
retry_remote:
  next->as_u64 = head = __atomic_load_n (rfree, __ATOMIC_RELAXED);
  if (!__atomic_compare_exchange_n (rfree, &head, node.as_u64, 0,
				    __ATOMIC_RELEASE, __ATOMIC_RELAXED))
    goto retry_remote;

done:
  clib_mem_poison ((u8 *) next, slab->chunk_size);

  return 1;
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
  if (a->per_thread_slabs)
    {
      clib_mem_slab_thread_init (h, os_get_thread_index ());
      h->slab = 1;
    }

  ASSERT (clib_mem_main.main_heap == 0);
  ASSERT (clib_mem_main.heaps == 0);
  clib_mem_main.main_heap = h;
  clib_mem_main.heaps = 0;
  clib_mem_thread_init ();
  clib_mem_set_heap (h);
  vec_add1 (clib_mem_main.heaps, h);
  clib_mem_main.alloc_free_intercept = a->alloc_free_intercept;

  if (mheap_trace_main.lock == 0)
    {
      /* clib_spinlock_init() dynamically allocates the spinlock in the current
       * per-cpu heap, but it is used for all traces accross all heaps and
       * hence we can't really allocate it in the current per-cpu heap as it
       * could be destroyed later */
      static struct clib_spinlock_s mheap_trace_main_lock = {};
      mheap_trace_main.lock = &mheap_trace_main_lock;
    }

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
  mheap_trace_main_t *tm = &mheap_trace_main;
  clib_mem_heap_t *heap = clib_mem_main.main_heap;
  clib_mem_thread_main_t *t = clib_mem_main.threads;

  if (heap->mspace == tm->current_traced_mheap)
    mheap_trace (heap, 0);

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
  int n = 0;

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

#define _(f, str)                                                             \
  if (heap->f)                                                                \
    s = format (s, ", %s", str);
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
  mheap_trace_main_t *tm = &mheap_trace_main;

  clib_spinlock_lock (&tm->lock);

  if (tm->current_traced_mheap != 0 && tm->current_traced_mheap != h)
    {
      clib_warning ("tracing already enabled for another heap, ignoring");
      goto out;
    }

  if (enable)
    {
      h->traced = 1;
      tm->current_traced_mheap = h;
    }
  else
    {
      h->traced = 0;
      mheap_trace_main_free (&mheap_trace_main);
    }

out:
  clib_spinlock_unlock (&tm->lock);
}

__clib_export void
clib_mem_trace (int enable)
{
  void *current_heap = clib_mem_get_heap ();
  mheap_trace (current_heap, enable);
}

int
clib_mem_is_traced (void)
{
  clib_mem_heap_t *h = clib_mem_get_heap ();
  return (h->traced) != 0;
}

__clib_export uword
clib_mem_trace_enable_disable (uword enable)
{
  uword rv = !clib_mem_thread_main.mheap_trace_thread_disable;
  clib_mem_thread_main.mheap_trace_thread_disable = !enable;
  return rv;
}

__clib_export mheap_trace_t *
clib_mem_trace_dup (clib_mem_heap_t *heap)
{
  mheap_trace_main_t *tm = &mheap_trace_main;
  mheap_trace_t *traces_copy = 0;

  clib_spinlock_lock (&tm->lock);
  if (vec_len (tm->traces) > 0 && heap == tm->current_traced_mheap)
    {
      traces_copy = vec_dup (tm->traces);
      qsort (traces_copy, vec_len (traces_copy), sizeof (traces_copy[0]),
	     mheap_trace_sort);
    }
  clib_spinlock_unlock (&tm->lock);
  return traces_copy;
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

  if (h->mspace == tm->current_traced_mheap)
    mheap_trace (h, 0);

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
  clib_mem_heap_t *h = heap ? heap : clib_mem_get_heap ();
  void *p = 0;

  align = clib_max (CLIB_MEM_MIN_ALIGN, align);

  if (h->slab)
    {
      clib_thread_index_t ti = os_get_thread_index ();
      clib_mem_slab_thread_init (h, ti);
      if (size <= 64 && align <= 64)
	p = clib_mem_slab_alloc (size, align);
    }

  if (p == 0)
    p = mspace_memalign (h->mspace, align, size);

  if (PREDICT_FALSE (0 == p))
    {
      if (os_out_of_memory_on_failure)
	os_out_of_memory ();
      return 0;
    }

  if (PREDICT_FALSE (h->traced))
    mheap_get_trace_internal (h, pointer_to_uword (p), clib_mem_size (p));

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
	  mheap_put_trace_internal (h, pointer_to_uword (p), old_alloc_size);
	  mheap_get_trace_internal (h, pointer_to_uword (p),
				    clib_mem_size (p));
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
    mheap_put_trace_internal (h, pointer_to_uword (p), size);
  clib_mem_poison (p, clib_mem_size (p));

  if (h->slab && clib_mem_slab_free (p))
    return;

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
