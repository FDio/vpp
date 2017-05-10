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

#include <vppinfra/clib.h>	/* uword, etc */
#include <vppinfra/mheap_bootstrap.h>
#include <vppinfra/os.h>
#include <vppinfra/string.h>	/* memcpy, memset */
#include <vppinfra/valgrind.h>

#define CLIB_MAX_MHEAPS 256

/* Per CPU heaps. */
extern void *clib_per_cpu_mheaps[CLIB_MAX_MHEAPS];

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

/* Memory allocator which may call os_out_of_memory() if it fails */
always_inline void *
clib_mem_alloc_aligned_at_offset (uword size, uword align, uword align_offset,
				  int os_out_of_memory_on_failure)
{
  void *heap, *p;
  uword offset, cpu;

  if (align_offset > align)
    {
      if (align > 0)
	align_offset %= align;
      else
	align_offset = align;
    }

  cpu = os_get_thread_index ();
  heap = clib_per_cpu_mheaps[cpu];
  heap = mheap_get_aligned (heap, size, align, align_offset, &offset);
  clib_per_cpu_mheaps[cpu] = heap;

  if (offset != ~0)
    {
      p = heap + offset;
#if CLIB_DEBUG > 0
      VALGRIND_MALLOCLIKE_BLOCK (p, mheap_data_bytes (heap, offset), 0, 0);
#endif
      return p;
    }
  else
    {
      if (os_out_of_memory_on_failure)
	os_out_of_memory ();
      return 0;
    }
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
clib_mem_is_heap_object (void *p)
{
  void *heap = clib_mem_get_per_cpu_heap ();
  uword offset = (uword) p - (uword) heap;
  mheap_elt_t *e, *n;

  if (offset >= vec_len (heap))
    return 0;

  e = mheap_elt_at_uoffset (heap, offset);
  n = mheap_next_elt (e);

  /* Check that heap forward and reverse pointers agree. */
  return e->n_user_data == n->prev_n_user_data;
}

always_inline void
clib_mem_free (void *p)
{
  u8 *heap = clib_mem_get_per_cpu_heap ();

  /* Make sure object is in the correct heap. */
  ASSERT (clib_mem_is_heap_object (p));

  mheap_put (heap, (u8 *) p - heap);

#if CLIB_DEBUG > 0
  VALGRIND_FREELIKE_BLOCK (p, 0);
#endif
}

always_inline void *
clib_mem_realloc (void *p, uword new_size, uword old_size)
{
  /* By default use alloc, copy and free to emulate realloc. */
  void *q = clib_mem_alloc (new_size);
  if (q)
    {
      uword copy_size;
      if (old_size < new_size)
	copy_size = old_size;
      else
	copy_size = new_size;
      clib_memcpy (q, p, copy_size);
      clib_mem_free (p);
    }
  return q;
}

always_inline uword
clib_mem_size (void *p)
{
  ASSERT (clib_mem_is_heap_object (p));
  mheap_elt_t *e = mheap_user_pointer_to_elt (p);
  return mheap_elt_data_bytes (e);
}

always_inline void *
clib_mem_get_heap (void)
{
  return clib_mem_get_per_cpu_heap ();
}

always_inline void *
clib_mem_set_heap (void *heap)
{
  return clib_mem_set_per_cpu_heap (heap);
}

void *clib_mem_init (void *heap, uword size);

void clib_mem_exit (void);

uword clib_mem_get_page_size (void);

void clib_mem_validate (void);

void clib_mem_trace (int enable);

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

/* Include appropriate VM functions depending on whether
   we are compiling for linux kernel, for Unix or standalone. */
#ifdef CLIB_LINUX_KERNEL
#include <vppinfra/vm_linux_kernel.h>
#endif

#ifdef CLIB_UNIX
#include <vppinfra/vm_unix.h>
#endif

#ifdef CLIB_STANDALONE
#include <vppinfra/vm_standalone.h>
#endif

#include <vppinfra/error.h>	/* clib_panic */

#endif /* _included_clib_mem_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
