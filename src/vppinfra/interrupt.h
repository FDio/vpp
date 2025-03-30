/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef included_clib_interrupt_h
#define included_clib_interrupt_h

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 n_int;
  u32 uwords_allocated;
  u32 uwords_used;
  uword *local;
  uword *remote;
} clib_interrupt_header_t;

void clib_interrupt_init (void **data, u32 n_interrupts);
void clib_interrupt_resize (void **data, u32 n_interrupts);

static_always_inline void
clib_interrupt_free (void **data)
{
  if (data[0])
    {
      clib_mem_free (data[0]);
      data[0] = 0;
    }
}

static_always_inline int
clib_interrupt_get_n_int (void *d)
{
  clib_interrupt_header_t *h = (clib_interrupt_header_t *) d;
  if (h)
    return h->n_int;
  return 0;
}

static_always_inline void
clib_interrupt_set (void *in, int int_num)
{
  clib_interrupt_header_t *h = (clib_interrupt_header_t *) in;
  u32 off = int_num >> log2_uword_bits;
  uword bit = 1ULL << (int_num & pow2_mask (log2_uword_bits));

  ASSERT (int_num < h->n_int);

  h->local[off] |= bit;
}

static_always_inline void
clib_interrupt_set_atomic (void *in, int int_num)
{
  clib_interrupt_header_t *h = (clib_interrupt_header_t *) in;
  u32 off = int_num >> log2_uword_bits;
  uword bit = 1ULL << (int_num & pow2_mask (log2_uword_bits));

  ASSERT (int_num < h->n_int);

  __atomic_fetch_or (h->remote + off, bit, __ATOMIC_RELAXED);
}

static_always_inline void
clib_interrupt_clear (void *in, int int_num)
{
  clib_interrupt_header_t *h = (clib_interrupt_header_t *) in;
  u32 off = int_num >> log2_uword_bits;
  uword bit = 1ULL << (int_num & pow2_mask (log2_uword_bits));
  uword *loc = h->local;
  uword *rem = h->remote;
  uword v;

  ASSERT (int_num < h->n_int);

  v = loc[off] | __atomic_exchange_n (rem + off, 0, __ATOMIC_SEQ_CST);
  loc[off] = v & ~bit;
}

static_always_inline int
clib_interrupt_get_next_and_clear (void *in, int last)
{
  clib_interrupt_header_t *h = (clib_interrupt_header_t *) in;
  uword bit, v;
  uword *loc = h->local;
  uword *rem = h->remote;
  u32 off, n_uwords = h->uwords_used;

  ASSERT (last >= -1 && last < (int) h->n_int);

  off = (last + 1) >> log2_uword_bits;

  if (off >= n_uwords)
    return -1;

  v = loc[off] | __atomic_exchange_n (rem + off, 0, __ATOMIC_SEQ_CST);
  loc[off] = v;

  v &= ~pow2_mask ((last + 1) & pow2_mask (log2_uword_bits));

  while (v == 0)
    {
      if (++off == n_uwords)
	return -1;

      v = loc[off] | __atomic_exchange_n (rem + off, 0, __ATOMIC_SEQ_CST);
      loc[off] = v;
    }

  bit = get_lowest_set_bit (v);
  loc[off] &= ~bit;
  return get_lowest_set_bit_index (bit) + (int) (off << log2_uword_bits);
}

static_always_inline int
clib_interrupt_is_any_pending (void *in)
{
  clib_interrupt_header_t *h = (clib_interrupt_header_t *) in;
  u32 n_uwords = h->uwords_used;
  uword *loc = h->local;
  uword *rem = h->remote;

  for (u32 i = 0; i < n_uwords; i++)
    if (loc[i])
      return 1;

  for (u32 i = 0; i < n_uwords; i++)
    if (rem[i])
      return 1;

  return 0;
}

#endif /* included_clib_interrupt_h */
