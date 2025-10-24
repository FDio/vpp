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
/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef _included_clib_mem_h
#define _included_clib_mem_h

#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>

#include <vppinfra/clib.h>	/* uword, etc */
#include <vppinfra/clib_error.h>

#include <vppinfra/os.h>
#include <vppinfra/string.h>	/* memcpy, clib_memset */
#ifdef CLIB_SANITIZE_ADDR
#include <sanitizer/asan_interface.h>
#endif

#define CLIB_MAX_MHEAPS 256
#define CLIB_MAX_NUMAS 16
#define CLIB_MEM_VM_MAP_FAILED ((void *) ~0)
#define CLIB_MEM_ERROR (-1)
#define CLIB_MEM_LOG2_MIN_ALIGN (3)
#define CLIB_MEM_MIN_ALIGN	(1 << CLIB_MEM_LOG2_MIN_ALIGN)

typedef enum
{
  CLIB_MEM_PAGE_SZ_UNKNOWN = 0,
  CLIB_MEM_PAGE_SZ_DEFAULT = 1,
  CLIB_MEM_PAGE_SZ_DEFAULT_HUGE = 2,
  CLIB_MEM_PAGE_SZ_4K = 12,
  CLIB_MEM_PAGE_SZ_16K = 14,
  CLIB_MEM_PAGE_SZ_64K = 16,
  CLIB_MEM_PAGE_SZ_1M = 20,
  CLIB_MEM_PAGE_SZ_2M = 21,
  CLIB_MEM_PAGE_SZ_16M = 24,
  CLIB_MEM_PAGE_SZ_32M = 25,
  CLIB_MEM_PAGE_SZ_512M = 29,
  CLIB_MEM_PAGE_SZ_1G = 30,
  CLIB_MEM_PAGE_SZ_16G = 34,
} clib_mem_page_sz_t;

typedef struct _clib_mem_vm_map_hdr
{
  /* base address */
  uword base_addr;

  /* number of pages */
  uword num_pages;

  /* page size (log2) */
  clib_mem_page_sz_t log2_page_sz;

  /* file descriptor, -1 if memory is not shared */
  int fd;

  /* allocation mame */
#define CLIB_VM_MAP_HDR_NAME_MAX_LEN 64
  char name[CLIB_VM_MAP_HDR_NAME_MAX_LEN];

  /* linked list */
  struct _clib_mem_vm_map_hdr *prev, *next;
} clib_mem_vm_map_hdr_t;

#define foreach_clib_mem_heap_flag                                            \
  _ (0, LOCKED, "locked")                                                     \
  _ (1, UNMAP_ON_DESTROY, "unmap-on-destroy")                                 \
  _ (2, TRACED, "traced")

typedef enum
{
#define _(i, v, s) CLIB_MEM_HEAP_F_##v = (1 << i),
  foreach_clib_mem_heap_flag
#undef _
} clib_mem_heap_flag_t;

struct clib_mem_heap_t;
typedef struct clib_mem_heap_t clib_mem_heap_t;

typedef struct
{
  /* log2 system page size */
  clib_mem_page_sz_t log2_page_sz;

  /* log2 default hugepage size */
  clib_mem_page_sz_t log2_default_hugepage_sz;

  /* log2 system default hugepage size */
  clib_mem_page_sz_t log2_sys_default_hugepage_sz;

  /* flags */
  u8 alloc_free_intercept : 1;

  /* bitmap of available numa nodes */
  u32 numa_node_bitmap;

  /* per CPU heaps */
  void *per_cpu_mheaps[CLIB_MAX_MHEAPS];

  /* per NUMA heaps */
  void *per_numa_mheaps[CLIB_MAX_NUMAS];

  /* memory maps */
  clib_mem_vm_map_hdr_t *first_map, *last_map;

  /* map lock */
  u8 map_lock;

  /* last error */
  clib_error_t *error;
} clib_mem_main_t;

extern clib_mem_main_t clib_mem_main;

/* Unspecified NUMA socket */
#define VEC_NUMA_UNSPECIFIED (0xFF)

static_always_inline void
clib_mem_poison (const void volatile *p, uword s)
{
#ifdef CLIB_SANITIZE_ADDR
  ASAN_POISON_MEMORY_REGION (p, s);
#endif
}

static_always_inline void
clib_mem_unpoison (const void volatile *p, uword s)
{
#ifdef CLIB_SANITIZE_ADDR
  ASAN_UNPOISON_MEMORY_REGION (p, s);
#endif
}

always_inline clib_mem_heap_t *
clib_mem_get_per_cpu_heap (void)
{
  int cpu = os_get_thread_index ();
  return clib_mem_main.per_cpu_mheaps[cpu];
}

always_inline void *
clib_mem_set_per_cpu_heap (void *new_heap)
{
  int cpu = os_get_thread_index ();
  void *old = clib_mem_main.per_cpu_mheaps[cpu];
  clib_mem_main.per_cpu_mheaps[cpu] = new_heap;
  return old;
}

always_inline void *
clib_mem_get_per_numa_heap (u32 numa_id)
{
  ASSERT (numa_id < ARRAY_LEN (clib_mem_main.per_numa_mheaps));
  return clib_mem_main.per_numa_mheaps[numa_id];
}

always_inline void *
clib_mem_set_per_numa_heap (void *new_heap)
{
  int numa = os_get_numa_index ();
  void *old = clib_mem_main.per_numa_mheaps[numa];
  clib_mem_main.per_numa_mheaps[numa] = new_heap;
  return old;
}

always_inline void
clib_mem_set_thread_index (void)
{
  /*
   * Find an unused slot in the per-cpu-mheaps array,
   * and grab it for this thread. We need to be able to
   * push/pop the thread heap without affecting other thread(s).
   */
  int i;
  if (__os_thread_index != 0)
    return;
  for (i = 0; i < ARRAY_LEN (clib_mem_main.per_cpu_mheaps); i++)
    if (clib_atomic_bool_cmp_and_swap (&clib_mem_main.per_cpu_mheaps[i],
				       0, clib_mem_main.per_cpu_mheaps[0]))
      {
	os_set_thread_index (i);
	break;
      }
  ASSERT (__os_thread_index > 0);
}

/* Memory allocator which calls os_out_of_memory() when it fails */
void *clib_mem_alloc (uword size);
void *clib_mem_alloc_aligned (uword size, uword align);
void *clib_mem_alloc_or_null (uword size);
void *clib_mem_alloc_aligned_or_null (uword size, uword align);
void *clib_mem_realloc (void *p, uword new_size);
void *clib_mem_realloc_aligned (void *p, uword new_size, uword align);
uword clib_mem_is_heap_object (void *p);
void clib_mem_free (void *p);

void *clib_mem_heap_alloc (void *heap, uword size);
void *clib_mem_heap_alloc_aligned (void *heap, uword size, uword align);
void *clib_mem_heap_alloc_or_null (void *heap, uword size);
void *clib_mem_heap_alloc_aligned_or_null (void *heap, uword size,
					   uword align);
void *clib_mem_heap_realloc (void *heap, void *p, uword new_size);
void *clib_mem_heap_realloc_aligned (void *heap, void *p, uword new_size,
				     uword align);
uword clib_mem_heap_is_heap_object (void *heap, void *p);
void clib_mem_heap_free (void *heap, void *p);

uword clib_mem_size (void *p);
void clib_mem_free_s (void *p);

/* Memory allocator which panics when it fails.
   Use macro so that clib_panic macro can expand __func__ and __LINE__. */
#define clib_mem_alloc_aligned_no_fail(size,align)				\
({										\
  uword _clib_mem_alloc_size = (size);						\
  void * _clib_mem_alloc_p;							\
  _clib_mem_alloc_p = clib_mem_alloc_aligned (_clib_mem_alloc_size, (align));	\
  if (! _clib_mem_alloc_p)							\
    clib_panic ("failed to allocate %d bytes", _clib_mem_alloc_size);		\
  _clib_mem_alloc_p;								\
})

#define clib_mem_alloc_no_fail(size) clib_mem_alloc_aligned_no_fail(size,1)

/* Alias to stack allocator for naming consistency. */
#define clib_mem_alloc_stack(bytes) __builtin_alloca(bytes)

always_inline clib_mem_heap_t *
clib_mem_get_heap (void)
{
  return clib_mem_get_per_cpu_heap ();
}

always_inline clib_mem_heap_t *
clib_mem_set_heap (clib_mem_heap_t * heap)
{
  return clib_mem_set_per_cpu_heap (heap);
}

void clib_mem_destroy_heap (clib_mem_heap_t * heap);
clib_mem_heap_t *clib_mem_create_heap (void *base, uword size, int is_locked,
				       char *fmt, ...);

void clib_mem_main_init ();
void *clib_mem_init (void *base, uword size);

typedef struct
{
  void *base_addr;
  uword memory_size;
  clib_mem_page_sz_t log2_page_sz;
} clib_mem_init_ex_args_t;
void *clib_mem_init_ex (clib_mem_init_ex_args_t *args);

void clib_mem_exit (void);

typedef struct
{
  /* Address of callers: outer first, inner last. */
  void *callers[12];

  /* Count of allocations with this traceback. */
  u32 n_allocations;

  /* Count of bytes allocated with this traceback. */
  u32 n_bytes;

  /* Offset of this item */
  uword offset;
} mheap_trace_t;

void clib_mem_trace (int enable);

int clib_mem_is_traced (void);

mheap_trace_t *clib_mem_trace_dup (clib_mem_heap_t *heap);

typedef struct
{
  /* Total number of objects allocated. */
  uword object_count;

  /* Total allocated bytes.  Bytes used and free.
     used + free = total */
  uword bytes_total, bytes_used, bytes_free;

  /* Number of bytes used by mheap data structure overhead
     (e.g. free lists, mheap header). */
  uword bytes_overhead;

  /* Amount of free space returned to operating system. */
  uword bytes_free_reclaimed;

  /* For malloc which puts small objects in sbrk region and
     large objects in mmap'ed regions. */
  uword bytes_used_sbrk;
  uword bytes_used_mmap;

  /* Max. number of bytes in this heap. */
  uword bytes_max;
} clib_mem_usage_t;

void clib_mem_get_heap_usage (clib_mem_heap_t * heap,
			      clib_mem_usage_t * usage);

void *clib_mem_get_heap_base (clib_mem_heap_t * heap);
uword clib_mem_get_heap_size (clib_mem_heap_t * heap);
uword clib_mem_get_heap_free_space (clib_mem_heap_t * heap);

u8 *format_clib_mem_usage (u8 * s, va_list * args);
u8 *format_clib_mem_heap (u8 * s, va_list * va);
u8 *format_clib_mem_heap_name (u8 *s, va_list *va);
u8 *format_clib_mem_page_stats (u8 * s, va_list * va);

/* Allocate virtual address space. */
always_inline void *
clib_mem_vm_alloc (uword size)
{
  void *mmap_addr;
  uword flags = MAP_PRIVATE;

#ifdef MAP_ANONYMOUS
  flags |= MAP_ANONYMOUS;
#endif

  mmap_addr = mmap (0, size, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (mmap_addr == (void *) -1)
    mmap_addr = 0;
  else
    clib_mem_unpoison (mmap_addr, size);

  return mmap_addr;
}

always_inline void
clib_mem_vm_free (void *addr, uword size)
{
  munmap (addr, size);
}

void *clib_mem_vm_map_internal (void *base, clib_mem_page_sz_t log2_page_sz,
				uword size, int fd, u8 log2_align,
				uword offset, char *name);

void *clib_mem_vm_map (void *start, uword size,
		       clib_mem_page_sz_t log2_page_size, char *fmt, ...);
void *clib_mem_vm_map_stack (uword size, clib_mem_page_sz_t log2_page_size,
			     char *fmt, ...);
void *clib_mem_vm_map_shared (void *start, uword size, int fd, uword offset,
			      char *fmt, ...);
int clib_mem_vm_unmap (void *base);
clib_mem_vm_map_hdr_t *clib_mem_vm_get_next_map_hdr (clib_mem_vm_map_hdr_t *
						     hdr);

static_always_inline clib_mem_page_sz_t
clib_mem_get_log2_page_size (void)
{
  return clib_mem_main.log2_page_sz;
}

static_always_inline uword
clib_mem_get_page_size (void)
{
  return 1ULL << clib_mem_main.log2_page_sz;
}

static_always_inline void
clib_mem_set_log2_default_hugepage_size (clib_mem_page_sz_t log2_page_sz)
{
  clib_mem_main.log2_default_hugepage_sz = log2_page_sz;
}

static_always_inline clib_mem_page_sz_t
clib_mem_get_log2_default_hugepage_size ()
{
  return clib_mem_main.log2_default_hugepage_sz;
}

static_always_inline uword
clib_mem_get_default_hugepage_size (void)
{
  return 1ULL << clib_mem_main.log2_default_hugepage_sz;
}

int clib_mem_vm_create_fd (clib_mem_page_sz_t log2_page_size, char *fmt, ...);
uword clib_mem_get_fd_page_size (int fd);
clib_mem_page_sz_t clib_mem_get_fd_log2_page_size (int fd);
uword clib_mem_vm_reserve (uword start, uword size, u8 log2_align);
u64 *clib_mem_vm_get_paddr (void *mem, clib_mem_page_sz_t log2_page_size,
			    int n_pages);
void clib_mem_destroy (void);
int clib_mem_set_numa_affinity (u8 numa_node, int force);
int clib_mem_set_default_numa_affinity ();
void clib_mem_vm_randomize_va (uword * requested_va,
			       clib_mem_page_sz_t log2_page_size);
void mheap_trace (clib_mem_heap_t * v, int enable);
uword clib_mem_trace_enable_disable (uword enable);
void clib_mem_trace (int enable);

always_inline uword
clib_mem_round_to_page_size (uword size, clib_mem_page_sz_t log2_page_size)
{
  ASSERT (log2_page_size != CLIB_MEM_PAGE_SZ_UNKNOWN);

  if (log2_page_size == CLIB_MEM_PAGE_SZ_DEFAULT)
    log2_page_size = clib_mem_get_log2_page_size ();
  else if (log2_page_size == CLIB_MEM_PAGE_SZ_DEFAULT_HUGE)
    log2_page_size = clib_mem_get_log2_default_hugepage_size ();

  return round_pow2 (size, 1ULL << log2_page_size);
}

typedef struct
{
  clib_mem_page_sz_t log2_page_sz;
  uword total;
  uword mapped;
  uword not_mapped;
  uword per_numa[CLIB_MAX_NUMAS];
  uword unknown;
} clib_mem_page_stats_t;

void clib_mem_get_page_stats (void *start, clib_mem_page_sz_t log2_page_size,
			      uword n_pages, clib_mem_page_stats_t * stats);

static_always_inline int
vlib_mem_get_next_numa_node (int numa)
{
  clib_mem_main_t *mm = &clib_mem_main;
  u32 bitmap = mm->numa_node_bitmap;

  if (numa >= 0)
    bitmap &= ~pow2_mask (numa + 1);
  if (bitmap == 0)
    return -1;

  return count_trailing_zeros (bitmap);
}

static_always_inline clib_mem_page_sz_t
clib_mem_log2_page_size_validate (clib_mem_page_sz_t log2_page_size)
{
  if (log2_page_size == CLIB_MEM_PAGE_SZ_DEFAULT)
    return clib_mem_get_log2_page_size ();
  if (log2_page_size == CLIB_MEM_PAGE_SZ_DEFAULT_HUGE)
    return clib_mem_get_log2_default_hugepage_size ();
  return log2_page_size;
}

static_always_inline uword
clib_mem_page_bytes (clib_mem_page_sz_t log2_page_size)
{
  return 1ULL << clib_mem_log2_page_size_validate (log2_page_size);
}

static_always_inline clib_error_t *
clib_mem_get_last_error (void)
{
  return clib_mem_main.error;
}

/* bulk allocator */

typedef void *clib_mem_bulk_handle_t;
clib_mem_bulk_handle_t clib_mem_bulk_init (u32 elt_sz, u32 align,
					   u32 min_elts_per_chunk);
void clib_mem_bulk_destroy (clib_mem_bulk_handle_t h);
void *clib_mem_bulk_alloc (clib_mem_bulk_handle_t h);
void clib_mem_bulk_free (clib_mem_bulk_handle_t h, void *p);
u8 *format_clib_mem_bulk (u8 *s, va_list *args);

#include <vppinfra/error.h>	/* clib_panic */

#endif /* _included_clib_mem_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
