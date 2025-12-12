/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003, 2004 Eliot Dresselhaus
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

