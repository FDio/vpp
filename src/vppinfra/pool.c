/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
  Copyright (c) 2001, 2002, 2003, 2004 Eliot Dresselhaus

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

#include <vppinfra/pool.h>

__clib_export void
_pool_init_fixed (void **pool_ptr, uword elt_size, uword max_elts, uword align)
{
  uword *b;
  pool_header_t *ph;
  u8 *v;
  u32 i;
  vec_attr_t va = { .elt_sz = elt_size,
		    .align = align,
		    .hdr_sz = sizeof (pool_header_t) };

  ASSERT (elt_size);
  ASSERT (max_elts);

  v = _vec_alloc_internal (max_elts, &va);

  ph = pool_header (v);
  ph->max_elts = max_elts;

  /* Build the free-index vector */
  vec_validate_aligned (ph->free_indices, max_elts - 1, CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < max_elts; i++)
    ph->free_indices[i] = (max_elts - 1) - i;

  /* Set the entire free bitmap */
  clib_bitmap_alloc (ph->free_bitmap, max_elts);

  for (b = ph->free_bitmap, i = max_elts; i >= uword_bits;
       i -= uword_bits, b++)
    b[0] = ~0ULL;

  if (i)
    b[0] = pow2_mask (i);

  *pool_ptr = v;
}

