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

#include <vppinfra/dlmalloc.h>

#include <vppinfra/os.h>
#include <vppinfra/string.h>	/* memcpy, clib_memset */
#include <vppinfra/sanitizer.h>

#define CLIB_MAX_MHEAPS 256
#define CLIB_MAX_NUMAS 8

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

/* Unspecified NUMA socket */
#define VEC_NUMA_UNSPECIFIED (0xFF)

/* Per CPU heaps. */
extern void *clib_per_cpu_mheaps[CLIB_MAX_MHEAPS];
extern void *clib_per_numa_mheaps[CLIB_MAX_NUMAS];

#define CLIB_MEM_LIBC_HEAP_SIZE (1U<<30)

/* libc heap */
extern void *clib_mem_libc_mheap;

void *clib_mem_init_internal (void *memory, uword memory_size, int set_heap,
			      int init_trace_lock);
void *clib_mem_init (void *heap, uword size);
void *clib_mem_init_thread_safe (void *memory, uword memory_size);
void *clib_mem_init_thread_safe_numa (void *memory, uword memory_size,
				      u8 numa);
void clib_mem_exit (void);
uword clib_mem_get_page_size (void);
void clib_mem_validate (void);
void clib_mem_trace_ex (void *heap, int enable);
void clib_mem_trace (int enable);
int clib_mem_is_traced (void);

static_always_inline void *
clib_mem_libc_heap_get (void)
{
  if (PREDICT_FALSE (0 == clib_mem_libc_mheap))
    clib_mem_libc_mheap =
      clib_mem_init_internal (0, CLIB_MEM_LIBC_HEAP_SIZE, 0, 0);
  return clib_mem_libc_mheap;
}

always_inline void *
clib_mem_get_per_cpu_heap (void)
{
  int cpu = os_get_thread_index ();
  return clib_per_cpu_mheaps[cpu];
}

always_inline void *
clib_mem_set_per_cpu_heap (u8 * new_heap)
{
  int cpu = os_get_thread_index ();
  void *old = clib_per_cpu_mheaps[cpu];
  clib_per_cpu_mheaps[cpu] = new_heap;
  return old;
}

always_inline void *
clib_mem_get_per_numa_heap (u32 numa_id)
{
  ASSERT (numa_id < ARRAY_LEN (clib_per_numa_mheaps));
  return clib_per_numa_mheaps[numa_id];
}

always_inline void *
clib_mem_set_per_numa_heap (u8 * new_heap)
{
  int numa = os_get_numa_index ();
  void *old = clib_per_numa_mheaps[numa];
  clib_per_numa_mheaps[numa] = new_heap;
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
  for (i = 0; i < ARRAY_LEN (clib_per_cpu_mheaps); i++)
    if (clib_atomic_bool_cmp_and_swap (&clib_per_cpu_mheaps[i],
				       0, clib_per_cpu_mheaps[0]))
      {
	os_set_thread_index (i);
	break;
      }
  ASSERT (__os_thread_index > 0);
}

always_inline uword
clib_mem_size_nocheck (void *p)
{
  return mspace_usable_size_with_delta (p);
}

/* Memory allocator which may call os_out_of_memory() if it fails */
always_inline void *
clib_mem_alloc_aligned_at_offset_ex (void *heap, uword size, uword align,
				     uword align_offset,
				     int os_out_of_memory_on_failure)
{
  void *p;

  if (align_offset > align)
    {
      if (align > 0)
	align_offset %= align;
      else
	align_offset = align;
    }

  p = mspace_get_aligned (heap, size, align, align_offset);

  if (PREDICT_FALSE (0 == p))
    {
      if (os_out_of_memory_on_failure)
	os_out_of_memory ();
      return 0;
    }

  CLIB_MEM_UNPOISON (p, size);
  return p;
}

always_inline void *
clib_mem_get_heap (void)
{
  return clib_mem_get_per_cpu_heap ();
}

/* Memory allocator which may call os_out_of_memory() if it fails */
always_inline void *
clib_mem_alloc_aligned_at_offset (uword size, uword align, uword align_offset,
				  int os_out_of_memory_on_failure)
{
  return clib_mem_alloc_aligned_at_offset_ex (clib_mem_get_heap (), size,
					      align, align_offset,
					      os_out_of_memory_on_failure);
}

/* Memory allocator which calls os_out_of_memory() when it fails */
always_inline void *
clib_mem_alloc (uword size)
{
  return clib_mem_alloc_aligned_at_offset (size, /* align */ 1,
					   /* align_offset */ 0,
					   /* os_out_of_memory */ 1);
}

always_inline void *
clib_mem_alloc_aligned (uword size, uword align)
{
  return clib_mem_alloc_aligned_at_offset (size, align, /* align_offset */ 0,
					   /* os_out_of_memory */ 1);
}

/* Memory allocator which calls os_out_of_memory() when it fails */
always_inline void *
clib_mem_alloc_or_null (uword size)
{
  return clib_mem_alloc_aligned_at_offset (size, /* align */ 1,
					   /* align_offset */ 0,
					   /* os_out_of_memory */ 0);
}

always_inline void *
clib_mem_alloc_aligned_or_null (uword size, uword align)
{
  return clib_mem_alloc_aligned_at_offset (size, align, /* align_offset */ 0,
					   /* os_out_of_memory */ 0);
}



/* Memory allocator which panics when it fails.
   Use macro so that clib_panic macro can expand __FUNCTION__ and __LINE__. */
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

always_inline uword
clib_mem_is_heap_object_ex (void *heap, void *p)
{
  return mspace_is_heap_object (heap, p);
}

always_inline uword
clib_mem_is_heap_object (void *p)
{
  return clib_mem_is_heap_object_ex (clib_mem_get_per_cpu_heap (), p);
}

always_inline void
clib_mem_free_ex (void *heap, void *p)
{
  /* Make sure object is in the correct heap. */
  ASSERT (clib_mem_is_heap_object_ex (heap, p));

  CLIB_MEM_POISON (p, clib_mem_size_nocheck (p));

  mspace_put (heap, p);
}

always_inline void
clib_mem_free (void *p)
{
  clib_mem_free_ex (clib_mem_get_heap (), p);
}

always_inline uword
clib_mem_size_ex (void *heap, void *p)
{
  ASSERT (clib_mem_is_heap_object_ex (heap, p));
  return clib_mem_size_nocheck (p);
}

always_inline void *
clib_mem_realloc_ex (void *heap, void *p, uword new_size, uword old_size)
{
  void *q;

  if (clib_mem_size_ex (heap, p) >= new_size)
    return p;

  q = clib_mem_alloc_aligned_at_offset_ex (heap, new_size, 0, 0, 1);
  if (q)
    {
      uword copy_size;
      if (old_size < new_size)
	copy_size = old_size;
      else
	copy_size = new_size;
      clib_memcpy_fast (q, p, copy_size);
      clib_mem_free_ex (heap, p);
    }
  return q;
}

always_inline void *
clib_mem_realloc (void *p, uword new_size, uword old_size)
{
  return clib_mem_realloc_ex (clib_mem_get_heap (), p, new_size, old_size);
}


always_inline uword
clib_mem_size (void *p)
{
  return clib_mem_size_ex (clib_mem_get_heap (), p);
}

always_inline void
clib_mem_free_s (void *p)
{
  uword size = clib_mem_size (p);
  CLIB_MEM_UNPOISON (p, size);
  memset_s_inline (p, size, 0, size);
  clib_mem_free (p);
}

always_inline void *
clib_mem_set_heap (void *heap)
{
  return clib_mem_set_per_cpu_heap (heap);
}

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

void clib_mem_usage (clib_mem_usage_t * usage);

u8 *format_clib_mem_usage (u8 * s, va_list * args);

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
    CLIB_MEM_UNPOISON (mmap_addr, size);

  return mmap_addr;
}

always_inline void
clib_mem_vm_free (void *addr, uword size)
{
  munmap (addr, size);
}

always_inline void *
clib_mem_vm_unmap (void *addr, uword size)
{
  void *mmap_addr;
  uword flags = MAP_PRIVATE | MAP_FIXED;

  /* To unmap we "map" with no protection.  If we actually called
     munmap then other callers could steal the address space.  By
     changing to PROT_NONE the kernel can free up the pages which is
     really what we want "unmap" to mean. */
  mmap_addr = mmap (addr, size, PROT_NONE, flags, -1, 0);
  if (mmap_addr == (void *) -1)
    mmap_addr = 0;
  else
    CLIB_MEM_UNPOISON (mmap_addr, size);

  return mmap_addr;
}

always_inline void *
clib_mem_vm_map (void *addr, uword size)
{
  void *mmap_addr;
  uword flags = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;

  mmap_addr = mmap (addr, size, (PROT_READ | PROT_WRITE), flags, -1, 0);
  if (mmap_addr == (void *) -1)
    mmap_addr = 0;
  else
    CLIB_MEM_UNPOISON (mmap_addr, size);

  return mmap_addr;
}

typedef struct
{
#define CLIB_MEM_VM_F_SHARED (1 << 0)
#define CLIB_MEM_VM_F_HUGETLB (1 << 1)
#define CLIB_MEM_VM_F_NUMA_PREFER (1 << 2)
#define CLIB_MEM_VM_F_NUMA_FORCE (1 << 3)
#define CLIB_MEM_VM_F_HUGETLB_PREALLOC (1 << 4)
#define CLIB_MEM_VM_F_LOCKED (1 << 5)
  u32 flags; /**< vm allocation flags:
                <br> CLIB_MEM_VM_F_SHARED: request shared memory, file
		descriptor will be provided on successful allocation.
                <br> CLIB_MEM_VM_F_HUGETLB: request hugepages.
		<br> CLIB_MEM_VM_F_NUMA_PREFER: numa_node field contains valid
		numa node preference.
		<br> CLIB_MEM_VM_F_NUMA_FORCE: fail if setting numa policy fails.
		<br> CLIB_MEM_VM_F_HUGETLB_PREALLOC: pre-allocate hugepages if
		number of available pages is not sufficient.
		<br> CLIB_MEM_VM_F_LOCKED: request locked memory.
             */
  char *name; /**< Name for memory allocation, set by caller. */
  uword size; /**< Allocation size, set by caller. */
  int numa_node; /**< numa node preference. Valid if CLIB_MEM_VM_F_NUMA_PREFER set. */
  void *addr; /**< Pointer to allocated memory, set on successful allocation. */
  int fd; /**< File descriptor, set on successful allocation if CLIB_MEM_VM_F_SHARED is set. */
  int log2_page_size;		/* Page size in log2 format, set on successful allocation. */
  int n_pages;			/* Number of pages. */
  uword requested_va;		/**< Request fixed position mapping */
} clib_mem_vm_alloc_t;

clib_error_t *clib_mem_create_fd (char *name, int *fdp);
clib_error_t *clib_mem_create_hugetlb_fd (char *name, int *fdp);
clib_error_t *clib_mem_vm_ext_alloc (clib_mem_vm_alloc_t * a);
void clib_mem_vm_ext_free (clib_mem_vm_alloc_t * a);
u64 clib_mem_get_fd_page_size (int fd);
uword clib_mem_get_default_hugepage_size (void);
int clib_mem_get_fd_log2_page_size (int fd);
uword clib_mem_vm_reserve (uword start, uword size,
			   clib_mem_page_sz_t log2_page_sz);
u64 *clib_mem_vm_get_paddr (void *mem, int log2_page_size, int n_pages);
void clib_mem_destroy_mspace (void *mspace);
void clib_mem_destroy (void);

typedef struct
{
  uword size;		/**< Map size */
  int fd;		/**< File descriptor to be mapped */
  uword requested_va;	/**< Request fixed position mapping */
  void *addr;		/**< Pointer to mapped memory, if successful */
  u8 numa_node;
} clib_mem_vm_map_t;

clib_error_t *clib_mem_vm_ext_map (clib_mem_vm_map_t * a);
void clib_mem_vm_randomize_va (uword * requested_va,
			       clib_mem_page_sz_t log2_page_size);
void mheap_trace (void *v, int enable);
uword clib_mem_trace_enable_disable (uword enable);
void clib_mem_trace (int enable);

#include <vppinfra/error.h>	/* clib_panic */

#endif /* _included_clib_mem_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
