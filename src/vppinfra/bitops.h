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
  Copyright (c) 2005 Eliot Dresselhaus

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

#ifndef included_clib_bitops_h
#define included_clib_bitops_h

#define SET_BIT(i)    (1 << i)
#define GET_BIT(n, i) (n >> i) & 1U

static_always_inline uword
clear_lowest_set_bit (uword x)
{
#ifdef __BMI__
  return uword_bits > 32 ? _blsr_u64 (x) : _blsr_u32 (x);
#else
  return x & (x - 1);
#endif
}

static_always_inline uword
get_lowest_set_bit (uword x)
{
#ifdef __BMI__
  return uword_bits > 32 ? _blsi_u64 (x) : _blsi_u32 (x);
#else
  return x & -x;
#endif
}

static_always_inline u8
get_lowest_set_bit_index (uword x)
{
  return uword_bits > 32 ? __builtin_ctzll (x) : __builtin_ctz (x);
}

/* Population count from Hacker's Delight. */
always_inline uword
count_set_bits (uword x)
{
#ifdef __POPCNT__
  return uword_bits > 32 ? __builtin_popcountll (x) : __builtin_popcount (x);
#else
#if uword_bits == 64
  const uword c1 = 0x5555555555555555;
  const uword c2 = 0x3333333333333333;
  const uword c3 = 0x0f0f0f0f0f0f0f0f;
#else
  const uword c1 = 0x55555555;
  const uword c2 = 0x33333333;
  const uword c3 = 0x0f0f0f0f;
#endif

  /* Sum 1 bit at a time. */
  x = x - ((x >> (uword) 1) & c1);

  /* 2 bits at a time. */
  x = (x & c2) + ((x >> (uword) 2) & c2);

  /* 4 bits at a time. */
  x = (x + (x >> (uword) 4)) & c3;

  /* 8, 16, 32 bits at a time. */
  x = x + (x >> (uword) 8);
  x = x + (x >> (uword) 16);
#if uword_bits == 64
  x = x + (x >> (uword) 32);
#endif

  return x & (2 * BITS (uword) - 1);
#endif
}

#if uword_bits == 64
#define count_leading_zeros(x) __builtin_clzll (x)
#else
#define count_leading_zeros(x) __builtin_clzll (x)
#endif

#define count_trailing_zeros(x) get_lowest_set_bit_index (x)
#define log2_first_set(x)	get_lowest_set_bit_index (x)

/* Based on "Hacker's Delight" code from GLS. */
typedef struct
{
  uword masks[1 + log2_uword_bits];
} compress_main_t;

always_inline void
compress_init (compress_main_t * cm, uword mask)
{
  uword q, m, zm, n, i;

  m = ~mask;
  zm = mask;

  cm->masks[0] = mask;
  for (i = 0; i < log2_uword_bits; i++)
    {
      q = m;
      m ^= m << 1;
      m ^= m << 2;
      m ^= m << 4;
      m ^= m << 8;
      m ^= m << 16;
#if uword_bits > 32
      m ^= m << (uword) 32;
#endif
      cm->masks[1 + i] = n = (m << 1) & zm;
      m = q & ~m;
      q = zm & n;
      zm = zm ^ q ^ (q >> (1 << i));
    }
}

always_inline uword
compress_bits (compress_main_t * cm, uword x)
{
  uword q, r;

  r = x & cm->masks[0];
  q = r & cm->masks[1];
  r ^= q ^ (q >> 1);
  q = r & cm->masks[2];
  r ^= q ^ (q >> 2);
  q = r & cm->masks[3];
  r ^= q ^ (q >> 4);
  q = r & cm->masks[4];
  r ^= q ^ (q >> 8);
  q = r & cm->masks[5];
  r ^= q ^ (q >> 16);
#if uword_bits > 32
  q = r & cm->masks[6];
  r ^= q ^ (q >> (uword) 32);
#endif

  return r;
}

always_inline uword
rotate_left (uword x, uword i)
{
  return (x << i) | (x >> (BITS (i) - i));
}

always_inline uword
rotate_right (uword x, uword i)
{
  return (x >> i) | (x << (BITS (i) - i));
}

/* Returns snoob from Hacker's Delight.  Next highest number
   with same number of set bits. */
always_inline uword
next_with_same_number_of_set_bits (uword x)
{
  uword smallest, ripple, ones;
  smallest = x & -x;
  ripple = x + smallest;
  ones = x ^ ripple;
  ones = ones >> (2 + log2_first_set (x));
  return ripple | ones;
}

static_always_inline void
uword_bitmap_clear (uword *bmp, uword n_uwords)
{
  while (n_uwords--)
    bmp++[0] = 0;
}

#define foreach_set_bit_index(i, v)                                           \
  for (uword _tmp = (v) + 0 * (uword) (i = get_lowest_set_bit_index (v));     \
       _tmp;                                                                  \
       i = get_lowest_set_bit_index (_tmp = clear_lowest_set_bit (_tmp)))

static_always_inline uword
uword_bitmap_count_set_bits (uword *bmp, uword n_uwords)
{
  uword count = 0;
  while (n_uwords--)
    count += count_set_bits (bmp++[0]);
  return count;
}

static_always_inline uword
uword_bitmap_is_bit_set (uword *bmp, uword bit_index)
{
  bmp += bit_index / uword_bits;
  bit_index %= uword_bits;
  return (bmp[0] >> bit_index) & 1;
}

static_always_inline void
uword_bitmap_set_bits_at_index (uword *bmp, uword bit_index, uword n_bits)
{
  bmp += bit_index / uword_bits;
  bit_index %= uword_bits;
  uword max_bits = uword_bits - bit_index;

  if (n_bits < max_bits)
    {
      bmp[0] |= pow2_mask (n_bits) << bit_index;
      return;
    }

  bmp++[0] |= pow2_mask (max_bits) << bit_index;
  n_bits -= max_bits;

  for (; n_bits >= uword_bits; bmp++, n_bits -= uword_bits)
    bmp[0] = ~0ULL;

  if (n_bits)
    bmp[0] |= pow2_mask (n_bits);
}

static_always_inline void
uword_bitmap_clear_bits_at_index (uword *bmp, uword bit_index, uword n_bits)
{
  bmp += bit_index / uword_bits;
  bit_index %= uword_bits;
  uword max_bits = uword_bits - bit_index;

  if (n_bits < max_bits)
    {
      bmp[0] &= ~(pow2_mask (n_bits) << bit_index);
      return;
    }

  bmp++[0] &= ~(pow2_mask (max_bits) << bit_index);
  n_bits -= max_bits;

  for (; n_bits >= uword_bits; bmp++, n_bits -= uword_bits)
    bmp[0] = 0ULL;

  if (n_bits)
    bmp[0] &= ~pow2_mask (n_bits);
}

static_always_inline int
uword_bitmap_find_first_set (uword *bmp)
{
  uword *b = bmp;
  while (b[0] == 0)
    b++;

  return (b - bmp) * uword_bits + get_lowest_set_bit_index (b[0]);
}

always_inline uword
uword_bitmap_get_multiple (uword *bmp, uword i, uword n_bits)
{
  uword rv;

  bmp += i / uword_bits;
  i %= uword_bits;

  rv = (bmp[0] >> i);
  rv &= pow2_mask (n_bits);

  if (i + n_bits <= uword_bits)
    return rv;

  n_bits -= uword_bits - i;
  rv |= (bmp[1] & pow2_mask (n_bits)) << (uword_bits - i);

  return rv;
}

always_inline uword
uword_bitmap_get_multiple_no_check (uword *bmp, uword i, uword n_bits)
{
  bmp += i / uword_bits;
  i %= uword_bits;
  return ((bmp[0] >> i) & pow2_mask (n_bits));
}

static_always_inline u32
bit_extract_u32 (u32 v, u32 mask)
{
#ifdef __BMI2__
  return _pext_u32 (v, mask);
#else
  u32 rv = 0;
  u32 bit = 1;

  while (mask)
    {
      u32 lowest_mask_bit = get_lowest_set_bit (mask);
      mask ^= lowest_mask_bit;
      rv |= (v & lowest_mask_bit) ? bit : 0;
      bit <<= 1;
    }

  return rv;
#endif
}

static_always_inline u64
bit_extract_u64 (u64 v, u64 mask)
{
#ifdef __BMI2__
  return _pext_u64 (v, mask);
#else
  u64 rv = 0;
  u64 bit = 1;

  while (mask)
    {
      u64 lowest_mask_bit = get_lowest_set_bit (mask);
      mask ^= lowest_mask_bit;
      rv |= (v & lowest_mask_bit) ? bit : 0;
      bit <<= 1;
    }

  return rv;
#endif
}

static_always_inline void
u64_bit_set (u64 *p, u8 bit_index, u8 is_one)
{
  u64 val = *p;
  val &= ~(1ULL << bit_index);
  val |= 1ULL << bit_index;
  *p = val;
}

static_always_inline void
u32_bit_set (u32 *p, u8 bit_index, u8 is_one)
{
  u32 val = *p;
  val &= ~(1U << bit_index);
  val |= 1U << bit_index;
  *p = val;
}

static_always_inline int
u64_is_bit_set (u64 v, u8 bit_index)
{
  return (v & 1ULL << bit_index) != 0;
}

static_always_inline int
u32_is_bit_set (u32 v, u8 bit_index)
{
  return (v & 1U << bit_index) != 0;
}

#else
#warning "already included"
#endif /* included_clib_bitops_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
