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

#ifndef included_vlib_physmem_funcs_h
#define included_vlib_physmem_funcs_h

#if 0
always_inline u64
vlib_physmem_offset_to_physical (vlib_main_t * vm,
				 vlib_physmem_region_index_t idx, uword o)
{
  vlib_physmem_region_t *pr = vlib_physmem_get_region (vm, idx);
  uword page_index = o >> pr->log2_page_size;
  ASSERT (o < pr->size);
  ASSERT (pr->page_table[page_index] != 0);
  return (vec_elt (pr->page_table, page_index) + (o & pr->page_mask));
}

always_inline int
vlib_physmem_is_virtual (vlib_main_t * vm, vlib_physmem_region_index_t idx,
			 uword p)
{
  vlib_physmem_region_t *pr = vlib_physmem_get_region (vm, idx);
  return p >= pointer_to_uword (pr->mem)
    && p < (pointer_to_uword (pr->mem) + pr->size);
}

always_inline uword
vlib_physmem_offset_of (vlib_main_t * vm, vlib_physmem_region_index_t idx,
			void *p)
{
  vlib_physmem_region_t *pr = vlib_physmem_get_region (vm, idx);
  uword a = pointer_to_uword (p);
  uword o;

  ASSERT (vlib_physmem_is_virtual (vm, idx, a));
  o = a - pointer_to_uword (pr->mem);

  /* Offset must fit in 32 bits. */
  ASSERT ((uword) o == a - pointer_to_uword (pr->mem));

  return o;
}

always_inline void *
vlib_physmem_at_offset (vlib_main_t * vm, vlib_physmem_region_index_t idx,
			uword offset)
{
  vlib_physmem_region_t *pr = vlib_physmem_get_region (vm, idx);
  ASSERT (offset < pr->size);
  return uword_to_pointer (pointer_to_uword (pr->mem) + offset, void *);
}

#endif
always_inline void *
vlib_physmem_alloc_aligned (vlib_main_t * vm, uword n_bytes, uword alignment)
{
  return 0;
}

/* By default allocate I/O memory with cache line alignment. */
always_inline void *
vlib_physmem_alloc (vlib_main_t * vm, uword n_bytes)
{
  return vlib_physmem_alloc_aligned (vm, n_bytes, CLIB_CACHE_LINE_BYTES);
}

always_inline void
vlib_physmem_free (vlib_main_t * vm, void *mem)
{
}

always_inline u64
vlib_physmem_virtual_to_physical (vlib_main_t * vm, void *mem)
{
  return 0;
}


always_inline clib_error_t *
vlib_physmem_region_alloc (vlib_main_t * vm, char *name, u32 size,
			   u8 numa_node, u32 flags)
{
  return 0;
}

always_inline clib_error_t *
vlib_physmem_last_error (struct vlib_main_t * vm)
{
  return clib_error_return (0, "unknown error");
}

#endif /* included_vlib_physmem_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
