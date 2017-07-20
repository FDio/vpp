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
 * physmem.h: virtual <-> physical memory mapping for VLIB buffers
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vlib_physmem_h
#define included_vlib_physmem_h

typedef struct
{
  u8 index;
  void *mem;
  uword va_start;
  uword va_end;
  uword va_size;
  int fd;
  u8 log2_page_size;
  u16 n_pages;
  u32 page_mask;

  void *heap;
  u32 flags;
#define VLIB_PHYSMEM_F_INIT_MHEAP (1<<0)

  u8 numa_node;
  u64 *page_table;
  u8 *name;
} vlib_physmem_region_t;

clib_error_t *unix_physmem_region_alloc (struct vlib_main_t *vm, char *name,
					 u32 size, u8 numa_node, u32 flags,
					 vlib_physmem_region_t ** region);

typedef struct
{
#if 0
  uword va_start, va_end, va_size;

  uword log2_n_bytes_per_page;

  /* 1 << log2_n_bytes_per_page - 1. */
  uword page_mask;

  u64 *page_table;
#endif

  /* NEW */
  vlib_physmem_region_t *regions;
  u8 default_region;

  /* is fake physmem */
  u8 is_fake;
} vlib_physmem_main_t;


#if 0
always_inline vlib_physmem_region_t *
vlib_physmem_get_region (vlib_main_t * vm, u8 index)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  return pool_elt_at_index (vpm->regions, index);
}
#endif

always_inline u64
vlib_physmem_offset_to_physical (vlib_physmem_region_t * pr, uword o)
{
  uword page_index = o >> pr->log2_page_size;
  ASSERT (o < pr->va_size);
  ASSERT (pr->page_table[page_index] != 0);
  return (vec_elt (pr->page_table, page_index) + (o & pr->page_mask));
}

always_inline int
vlib_physmem_is_virtual (vlib_physmem_region_t * pr, uword p)
{
  return p >= pr->va_start && p < pr->va_end;
}

always_inline uword
vlib_physmem_offset_of (vlib_physmem_region_t * pr, void *p)
{
  uword a = pointer_to_uword (p);
  uword o;

  ASSERT (vlib_physmem_is_virtual (pr, a));
  o = a - pr->va_start;

  /* Offset must fit in 32 bits. */
  ASSERT ((uword) o == a - pr->va_start);

  return o;
}

always_inline void *
vlib_physmem_at_offset (vlib_physmem_region_t * pr, uword offset)
{
  ASSERT (offset < pr->va_size);
  return uword_to_pointer (pr->va_start + offset, void *);
}

#endif /* included_vlib_physmem_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
