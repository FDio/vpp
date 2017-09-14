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

#ifndef included_vm_unix_h
#define included_vm_unix_h

#include <vppinfra/clib_error.h>
#include <unistd.h>
#include <sys/mman.h>

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

  return mmap_addr;
}

always_inline void *
clib_mem_vm_map (void *addr, uword size)
{
  void *mmap_addr;
  uword flags = MAP_PRIVATE | MAP_FIXED;

  mmap_addr = mmap (addr, size, (PROT_READ | PROT_WRITE), flags, -1, 0);
  if (mmap_addr == (void *) -1)
    mmap_addr = 0;

  return mmap_addr;
}

typedef struct
{
#define CLIB_MEM_VM_F_SHARED (1 << 0)
#define CLIB_MEM_VM_F_HUGETLB (1 << 1)
#define CLIB_MEM_VM_F_NUMA_PREFER (1 << 2)
#define CLIB_MEM_VM_F_NUMA_FORCE (1 << 3)
#define CLIB_MEM_VM_F_HUGETLB_PREALLOC (1 << 4)
  u32 flags; /**< vm allocation flags:
                <br> CLIB_MEM_VM_F_SHARED: request shared memory, file
		destiptor will be provided on successful allocation.
                <br> CLIB_MEM_VM_F_HUGETLB: request hugepages.
		<br> CLIB_MEM_VM_F_NUMA_PREFER: numa_node field contains valid
		numa node preference.
		<br> CLIB_MEM_VM_F_NUMA_FORCE: fail if setting numa policy fails.
		<br> CLIB_MEM_VM_F_HUGETLB_PREALLOC: pre-allocate hugepages if
		number of available pages is not sufficient.
             */
  char *name; /**< Name for memory allocation, set by caller. */
  uword size; /**< Allocation size, set by caller. */
  int numa_node; /**< numa node preference. Valid if CLIB_MEM_VM_F_NUMA_PREFER set. */
  void *addr; /**< Pointer to allocated memory, set on successful allocation. */
  int fd; /**< File desriptor, set on successful allocation if CLIB_MEM_VM_F_SHARED is set. */
  int log2_page_size;		/* Page size in log2 format, set on successful allocation. */
  int n_pages;			/* Number of pages. */
} clib_mem_vm_alloc_t;

clib_error_t *clib_mem_vm_ext_alloc (clib_mem_vm_alloc_t * a);
int clib_mem_vm_get_log2_page_size (int fd);
u64 *clib_mem_vm_get_paddr (void *mem, int log2_page_size, int n_pages);

#endif /* included_vm_unix_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
