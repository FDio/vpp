/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#include <vppinfra/interrupt.h>

__clib_export void
clib_interrupt_init (void **data, u32 n_int)
{
  clib_interrupt_header_t *h;
  const u32 bits_in_cl = 8 << CLIB_LOG2_CACHE_LINE_BYTES;
  u32 sz = sizeof (clib_interrupt_header_t);
  u32 n_cl = round_pow2 (n_int, bits_in_cl) / bits_in_cl;

  sz += 2 * n_cl * CLIB_CACHE_LINE_BYTES;
  h = data[0] = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (data[0], 0, sz);
  h->n_int = n_int;
  h->uwords_allocated = n_cl * bits_in_cl / uword_bits;
  h->uwords_used = round_pow2 (n_int, uword_bits) / uword_bits;
  h->local = (uword *) (h + 1);
  h->remote = h->local + h->uwords_allocated;
}

__clib_export void
clib_interrupt_resize (void **data, u32 n_int)
{
  clib_interrupt_header_t *h = data[0];
  u32 new_n_uwords, i;

  if (data[0] == 0)
    {
      clib_interrupt_init (data, n_int);
      return;
    }

  if (n_int == h->n_int)
    return;

  new_n_uwords = round_pow2 (n_int, uword_bits) / uword_bits;

  if (new_n_uwords > h->uwords_allocated)
    {
      clib_interrupt_header_t *nh;
      clib_interrupt_init ((void **) &nh, n_int);
      for (int i = 0; i < h->uwords_used; i++)
	nh->local[i] = h->local[i] | h->remote[i];
      clib_mem_free (data[0]);
      data[0] = nh;
      return;
    }

  h->n_int = n_int;
  h->uwords_used = new_n_uwords;

  for (i = 0; i < new_n_uwords; i++)
    h->local[i] |= h->remote[i];

  for (i = 0; i < h->uwords_allocated; i++)
    h->remote[i] = 0;

  for (i = new_n_uwords; i < h->uwords_allocated; i++)
    h->local[i] = 0;

  n_int &= pow2_mask (log2_uword_bits);

  if (n_int)
    h->local[n_int >> log2_uword_bits] &= pow2_mask (n_int);
}

