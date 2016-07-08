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
  uword start, end, size;
} vlib_physmem_region_t;

typedef struct
{
  vlib_physmem_region_t virtual;

  uword log2_n_bytes_per_page;

  /* 1 << log2_n_bytes_per_page - 1. */
  uword page_mask;

  u64 *page_table;

  /* is fake physmem */
  u8 is_fake;
} vlib_physmem_main_t;

always_inline u64
vlib_physmem_offset_to_physical (vlib_physmem_main_t * pm, uword o)
{
  uword page_index = o >> pm->log2_n_bytes_per_page;
  ASSERT (o < pm->virtual.size);
  ASSERT (pm->page_table[page_index] != 0);
  return (vec_elt (pm->page_table, page_index) + (o & pm->page_mask));
}

always_inline int
vlib_physmem_is_virtual (vlib_physmem_main_t * pm, uword p)
{
  return p >= pm->virtual.start && p < pm->virtual.end;
}

always_inline uword
vlib_physmem_offset_of (vlib_physmem_main_t * pm, void *p)
{
  uword a = pointer_to_uword (p);
  uword o;

  ASSERT (vlib_physmem_is_virtual (pm, a));
  o = a - pm->virtual.start;

  /* Offset must fit in 32 bits. */
  ASSERT ((uword) o == a - pm->virtual.start);

  return o;
}

always_inline void *
vlib_physmem_at_offset (vlib_physmem_main_t * pm, uword offset)
{
  ASSERT (offset < pm->virtual.size);
  return uword_to_pointer (pm->virtual.start + offset, void *);
}

#endif /* included_vlib_physmem_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
