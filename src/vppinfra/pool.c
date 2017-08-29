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

void
_pool_init_fixed (void **pool_ptr, u32 elt_size, u32 max_elts)
{
  u8 *mmap_base;
  u64 vector_size;
  u64 free_index_size;
  u64 total_size;
  u64 page_size;
  pool_header_t *fh;
  vec_header_t *vh;
  u8 *v;
  u32 *fi;
  u32 i;
  u32 set_bits;

  ASSERT (elt_size);
  ASSERT (max_elts);

  vector_size = pool_aligned_header_bytes + vec_header_bytes (0)
    + (u64) elt_size *max_elts;

  free_index_size = vec_header_bytes (0) + sizeof (u32) * max_elts;

  /* Round up to a cache line boundary */
  vector_size = (vector_size + CLIB_CACHE_LINE_BYTES - 1)
    & ~(CLIB_CACHE_LINE_BYTES - 1);

  free_index_size = (free_index_size + CLIB_CACHE_LINE_BYTES - 1)
    & ~(CLIB_CACHE_LINE_BYTES - 1);

  total_size = vector_size + free_index_size;

  /* Round up to an even number of pages */
  page_size = clib_mem_get_page_size ();
  total_size = (total_size + page_size - 1) & ~(page_size - 1);

  /* mmap demand zero memory */

  mmap_base = mmap (0, total_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (mmap_base == MAP_FAILED)
    {
      clib_unix_warning ("mmap");
      *pool_ptr = 0;
    }

  /* First comes the pool header */
  fh = (pool_header_t *) mmap_base;
  /* Find the user vector pointer */
  v = (u8 *) (mmap_base + pool_aligned_header_bytes);
  /* Finally, the vector header */
  vh = _vec_find (v);

  fh->free_bitmap = 0;		/* No free elts (yet) */
  fh->max_elts = max_elts;
  fh->mmap_base = mmap_base;
  fh->mmap_size = total_size;

  vh->len = max_elts;

  /* Build the free-index vector */
  vh = (vec_header_t *) (v + vector_size);
  vh->len = max_elts;
  fi = (u32 *) (vh + 1);

  fh->free_indices = fi;

  /* Set the entire free bitmap */
  clib_bitmap_alloc (fh->free_bitmap, max_elts);
  memset (fh->free_bitmap, 0xff, vec_len (fh->free_bitmap) * sizeof (uword));

  /* Clear any extraneous set bits */
  set_bits = vec_len (fh->free_bitmap) * BITS (uword);

  for (i = max_elts; i < set_bits; i++)
    fh->free_bitmap = clib_bitmap_set (fh->free_bitmap, i, 0);

  /* Create the initial free vector */
  for (i = 0; i < max_elts; i++)
    fi[i] = (max_elts - 1) - i;

  *pool_ptr = v;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
