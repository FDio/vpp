/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef included_clib_interrupt_h
#define included_clib_interrupt_h

#include <vppinfra/clib.h>
#include <vppinfra/bitops.h>	/* for count_set_bits */
#include <vppinfra/vec.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  int n_int;
  uword n_uword_alloc;
} clib_interrupt_header_t;

void clib_interrupt_init (void **data, uword n_interrupts);
void clib_interrupt_resize (void **data, uword n_interrupts);

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
  clib_interrupt_header_t *h = d;
  if (h)
    return h->n_int;
  return 0;
}

static_always_inline uword *
clib_interrupt_get_bitmap (void *d)
{
  return d + sizeof (clib_interrupt_header_t);
}

static_always_inline uword *
clib_interrupt_get_atomic_bitmap (void *d)
{
  clib_interrupt_header_t *h = d;
  return clib_interrupt_get_bitmap (d) + h->n_uword_alloc;
}

static_always_inline void
clib_interrupt_set (void *in, int int_num)
{
  uword *bmp = clib_interrupt_get_bitmap (in);
  uword mask = 1ULL << (int_num & (uword_bits - 1));
  bmp += int_num >> log2_uword_bits;

  ASSERT (int_num < ((clib_interrupt_header_t *) in)->n_int);

  *bmp |= mask;
}

static_always_inline void
clib_interrupt_set_atomic (void *in, int int_num)
{
  uword *bmp = clib_interrupt_get_atomic_bitmap (in);
  uword mask = 1ULL << (int_num & (uword_bits - 1));
  bmp += int_num >> log2_uword_bits;

  ASSERT (int_num < ((clib_interrupt_header_t *) in)->n_int);

  __atomic_fetch_or (bmp, mask, __ATOMIC_RELAXED);
}

static_always_inline void
clib_interrupt_clear (void *in, int int_num)
{
  uword *bmp = clib_interrupt_get_bitmap (in);
  uword *abm = clib_interrupt_get_atomic_bitmap (in);
  uword mask = 1ULL << (int_num & (uword_bits - 1));
  uword off = int_num >> log2_uword_bits;

  ASSERT (int_num < ((clib_interrupt_header_t *) in)->n_int);

  bmp[off] |= __atomic_exchange_n (abm + off, 0, __ATOMIC_SEQ_CST);
  bmp[off] &= ~mask;
}

static_always_inline int
clib_interrupt_get_next (void *in, int last)
{
  uword *bmp = clib_interrupt_get_bitmap (in);
  uword *abm = clib_interrupt_get_atomic_bitmap (in);
  clib_interrupt_header_t *h = in;
  uword bmp_uword, off;

  ASSERT (last >= -1 && last < h->n_int);

  off = (last + 1) >> log2_uword_bits;

  last -= off << log2_uword_bits;
  bmp[off] |= __atomic_exchange_n (abm + off, 0, __ATOMIC_SEQ_CST);
  bmp_uword = bmp[off] & ~pow2_mask (last + 1);

next:
  if (bmp_uword)
    return (off << log2_uword_bits) + count_trailing_zeros (bmp_uword);

  off++;

  if (off > h->n_int >> log2_uword_bits)
    return -1;

  bmp[off] |= __atomic_exchange_n (abm + off, 0, __ATOMIC_SEQ_CST);
  bmp_uword = bmp[off];

  goto next;
}

#endif /* included_clib_interrupt_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
