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

#include <vppinfra/format.h>
#include <vppinfra/mheap.h>
#include <vppinfra/os.h>

/* Valgrind stuff. */
#include <vppinfra/memcheck.h>
#include <vppinfra/valgrind.h>

void *clib_per_cpu_mheaps[CLIB_MAX_MHEAPS];

void
clib_mem_exit (void)
{
  u8 *heap = clib_mem_get_per_cpu_heap ();
  if (heap)
    mheap_free (heap);
  clib_mem_set_per_cpu_heap (0);
}

/* Initialize CLIB heap based on memory/size given by user.
   Set memory to 0 and CLIB will try to allocate its own heap. */
void *
clib_mem_init (void *memory, uword memory_size)
{
  u8 *heap;

  if (memory || memory_size)
    heap = mheap_alloc (memory, memory_size);
  else
    {
      /* Allocate lots of address space since this will limit
         the amount of memory the program can allocate.
         In the kernel we're more conservative since some architectures
         (e.g. mips) have pretty small kernel virtual address spaces. */
#ifdef __KERNEL__
#define MAX_VM_MEG 64
#else
#define MAX_VM_MEG 1024
#endif

      uword alloc_size = MAX_VM_MEG << 20;
      uword tries = 16;

      while (1)
	{
	  heap = mheap_alloc (0, alloc_size);
	  if (heap)
	    break;
	  alloc_size = (alloc_size * 3) / 4;
	  tries--;
	  if (tries == 0)
	    break;
	}
    }

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
  return format (s, "%U", format_mheap, clib_mem_get_heap (), verbose);
}

void
clib_mem_usage (clib_mem_usage_t * u)
{
  mheap_usage (clib_mem_get_heap (), u);
}

/* Call serial number for debugger breakpoints. */
uword clib_mem_validate_serial = 0;

void
clib_mem_validate (void)
{
  if (MHEAP_HAVE_SMALL_OBJECT_CACHE)
    clib_warning ("clib_mem_validate disabled (small object cache is ON)");
  else
    {
      mheap_validate (clib_mem_get_heap ());
      clib_mem_validate_serial++;
    }
}

void
clib_mem_trace (int enable)
{
  mheap_trace (clib_mem_get_heap (), enable);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
