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

void *clib_per_cpu_mheaps[CLIB_MAX_MHEAPS];

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

  return heap;
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

u8 *
format_mheap (u8 * s, va_list * va)
{
  void *heap = va_arg (*va, u8 *);
  int verbose = va_arg (*va, int);
  struct mallinfo mi;

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
clib_mem_trace (int enable)
{
  clib_warning ("unimp");
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
