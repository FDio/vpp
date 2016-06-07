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
  Copyright (c) 2001, 2002, 2003, 2005 Eliot Dresselhaus

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

#ifndef included_clib_bitmap_h
#define included_clib_bitmap_h

/* Bitmaps built as vectors of machine words. */

#include <vppinfra/vec.h>
#include <vppinfra/random.h>
#include <vppinfra/error.h>
#include <vppinfra/bitops.h>	/* for count_set_bits */

/* Returns 1 if the entire bitmap is zero, 0 otherwise */
always_inline uword
clib_bitmap_is_zero (uword * ai)
{
  uword i;
  for (i = 0; i < vec_len (ai); i++)
    if (ai[i] != 0)
      return 0;
  return 1;
}

/* Returns 1 if two bitmaps are equal, 0 otherwise */
always_inline uword
clib_bitmap_is_equal (uword * a, uword * b)
{
  uword i;
  if (vec_len (a) != vec_len (b))
    return 0;
  for (i = 0; i < vec_len (a); i++)
    if (a[i] != b[i])
      return 0;
  return 1;
}

/* Duplicate a bitmap */
#define clib_bitmap_dup(v) vec_dup(v)

/* Free a bitmap */
#define clib_bitmap_free(v) vec_free(v)

/* Returns the number of bytes in a bitmap */
#define clib_bitmap_bytes(v) vec_bytes(v)

/* Clear a bitmap */
#define clib_bitmap_zero(v) vec_zero(v)

/* Allocate bitmap with given number of bits. */
#define clib_bitmap_alloc(v,n_bits) \
  v = vec_new (uword, ((n_bits) + BITS (uword) - 1) / BITS (uword))

#define clib_bitmap_vec_validate(v,i) vec_validate_aligned((v),(i),sizeof(uword))

/* Make sure that a bitmap is at least n_bits in size */
#define clib_bitmap_validate(v,n_bits) \
  clib_bitmap_vec_validate ((v), ((n_bits) - 1) / BITS (uword))

/* low-level routine to remove trailing zeros from a bitmap */
always_inline uword *
_clib_bitmap_remove_trailing_zeros (uword * a)
{
  word i;
  if (a)
    {
      for (i = _vec_len (a) - 1; i >= 0; i--)
	if (a[i] != 0)
	  break;
      _vec_len (a) = i + 1;
    }
  return a;
}

/* Sets the ith bit of a bitmap to new_value.  Returns old value. 
   No sanity checking. Be careful. */
always_inline uword
clib_bitmap_set_no_check (uword * a, uword i, uword new_value)
{
  uword i0 = i / BITS (a[0]);
  uword i1 = i % BITS (a[0]);
  uword bit = (uword) 1 << i1;
  uword ai, old_value;

  /* Removed ASSERT since uword * a may not be a vector. */
  /* ASSERT (i0 < vec_len (a)); */

  ai = a[i0];
  old_value = (ai & bit) != 0;
  ai &= ~ bit;
  ai |= ((uword) (new_value != 0)) << i1;
  a[i0] = ai;
  return old_value;
}

/* Set bit I to value (either non-zero or zero). */
always_inline uword *
clib_bitmap_set (uword * ai, uword i, uword value)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  uword a;

  /* Check for writing a zero to beyond end of bitmap. */
  if (value == 0 && i0 >= vec_len (ai))
    return ai;			/* Implied trailing zeros. */

  clib_bitmap_vec_validate (ai, i0);

  a = ai[i0];
  a &= ~((uword) 1 << i1);
  a |= ((uword) (value != 0)) << i1;
  ai[i0] = a;

  /* If bits have been cleared, test for zero. */
  if (a == 0)
    ai = _clib_bitmap_remove_trailing_zeros (ai);

  return ai;
}

/* Fetch bit I. */
always_inline uword
clib_bitmap_get (uword * ai, uword i)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  return i0 < vec_len (ai) && 0 != ((ai[i0] >> i1) & 1);
}

/* Fetch bit I. 

    No sanity checking. Be careful.
*/
always_inline uword
clib_bitmap_get_no_check (uword * ai, uword i)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  return 0 != ((ai[i0] >> i1) & 1);
}

/* I through I + N_BITS. 

    No sanity checking. Be careful.
*/
always_inline uword
clib_bitmap_get_multiple_no_check (uword * ai, uword i, uword n_bits)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  ASSERT (i1 + n_bits <= BITS (uword));
  return 0 != ((ai[i0] >> i1) & pow2_mask (n_bits));
}

/* Fetch bits I through I + N_BITS. */
always_inline uword
clib_bitmap_get_multiple (uword * bitmap, uword i, uword n_bits)
{
  uword i0, i1, result;
  uword l = vec_len (bitmap);

  ASSERT (n_bits >= 0 && n_bits <= BITS (result));

  i0 = i / BITS (bitmap[0]);
  i1 = i % BITS (bitmap[0]);

  /* Check first word. */
  result = 0;
  if (i0 < l)
    {
      result |= (bitmap[i0] >> i1);
      if (n_bits < BITS (bitmap[0]))
	result &= (((uword) 1 << n_bits) - 1);
    }

  /* Check for overlap into next word. */
  i0++;
  if (i1 + n_bits > BITS (bitmap[0]) && i0 < l)
    {
      n_bits -= BITS (bitmap[0]) - i1;
      result |= (bitmap[i0] & (((uword) 1 << n_bits) - 1)) << (BITS (bitmap[0]) - i1);
    }

  return result;
}

/* Set bits I through I + N_BITS to given value.

    New bitmap will be returned. */
always_inline uword *
clib_bitmap_set_multiple (uword * bitmap, uword i, uword value, uword n_bits)
{
  uword i0, i1, l, t, m;

  ASSERT (n_bits >= 0 && n_bits <= BITS (value));

  i0 = i / BITS (bitmap[0]);
  i1 = i % BITS (bitmap[0]);

  /* Allocate bitmap. */
  clib_bitmap_vec_validate (bitmap, (i + n_bits) / BITS (bitmap[0]));
  l = vec_len (bitmap);

  m = ~0;
  if (n_bits < BITS (value))
    m = (((uword) 1 << n_bits) - 1);
  value &= m;

  /* Insert into first word. */
  t = bitmap[i0];
  t &= ~(m << i1);
  t |= value << i1;
  bitmap[i0] = t;

  /* Insert into second word. */
  i0++;
  if (i1 + n_bits > BITS (bitmap[0]) && i0 < l)
    {
      t = BITS (bitmap[0]) - i1;
      value >>= t;
      n_bits -= t;
      t = bitmap[i0];
      m = ((uword) 1 << n_bits) - 1;
      t &= ~m;
      t |= value;
      bitmap[i0] = t;
    }

  return bitmap;
}

/* For a multi-word region set all bits to given value. */
always_inline uword *
clib_bitmap_set_region (uword * bitmap, uword i, uword value, uword n_bits)
{
  uword a0, a1, b0;
  uword i_end, mask;

  a0 = i / BITS (bitmap[0]);
  a1 = i % BITS (bitmap[0]);

  i_end = i + n_bits;
  b0 = i_end / BITS (bitmap[0]);

  clib_bitmap_vec_validate (bitmap, b0);

  /* First word. */
  mask = n_bits < BITS (bitmap[0]) ? pow2_mask (n_bits) : ~0;
  mask <<= a1;

  if (value)
    bitmap[a0] |= mask;
  else
    bitmap[a0] &= ~mask;

  for (a0++; a0 < b0; a0++)
    bitmap[a0] = value ? ~0 : 0;

  if (a0 == b0)
    {
      word n_bits_left = n_bits - (BITS (bitmap[0]) - a1);
      mask = pow2_mask (n_bits_left);
      if (value)
	bitmap[a0] |= mask;
      else
	bitmap[a0] &= ~mask;
    }

  return bitmap;
}

/* Iterate through set bits. */
#define clib_bitmap_foreach(i,ai,body)					\
do {									\
  uword __bitmap_i, __bitmap_ai, __bitmap_len, __bitmap_first_set;	\
  __bitmap_len = vec_len ((ai));					\
  for (__bitmap_i = 0; __bitmap_i < __bitmap_len; __bitmap_i++)		\
    {									\
      __bitmap_ai = (ai)[__bitmap_i];					\
      while (__bitmap_ai != 0)						\
	{								\
	  __bitmap_first_set = first_set (__bitmap_ai);			\
	  (i) = (__bitmap_i * BITS ((ai)[0])				\
		 + min_log2 (__bitmap_first_set));			\
	  do { body; } while (0);					\
	  __bitmap_ai ^= __bitmap_first_set;				\
	}								\
    }									\
} while (0)

/* Return lowest numbered set bit in bitmap.

    Return infinity (~0) if bitmap is zero. */
always_inline uword clib_bitmap_first_set (uword * ai)
{
  uword i;
  for (i = 0; i < vec_len (ai); i++)
    {
      uword x = ai[i];
      if (x != 0)
	return i * BITS (ai[0]) + log2_first_set (x);
    }
  return ~0;
}

/* Return highest numbered set bit in bitmap.

    Return infinity (~0) if bitmap is zero. */
always_inline uword clib_bitmap_last_set (uword * ai)
{
  uword i;

  for (i = vec_len (ai) - 1; i >= 0 ; i--)
    {
      uword x = ai[i];
      if (x != 0)
	{
	  uword first_bit;
	  count_leading_zeros (first_bit, x);
	  return (i + 1) * BITS (ai[0]) - first_bit - 1;
	}
    }
  return ~0;
}

/* Return lowest numbered clear bit in bitmap. */
always_inline uword
clib_bitmap_first_clear (uword * ai)
{
  uword i;
  for (i = 0; i < vec_len (ai); i++)
    {
      uword x = ~ai[i];
      if (x != 0)
	return i * BITS (ai[0]) + log2_first_set (x);
    }
  return i * BITS (ai[0]);
}

/* Count number of set bits in bitmap. */
always_inline uword
clib_bitmap_count_set_bits (uword * ai)
{
  uword i;
  uword n_set = 0;
  for (i = 0; i < vec_len (ai); i++)
    n_set += count_set_bits (ai[i]);
  return n_set;
}

/* ALU function definition macro for functions taking two bitmaps. */
#define _(name, body, check_zero)				\
always_inline uword *						\
clib_bitmap_##name (uword * ai, uword * bi)			\
{								\
  uword i, a, b, bi_len, n_trailing_zeros;			\
								\
  n_trailing_zeros = 0;						\
  bi_len = vec_len (bi);					\
  if (bi_len > 0)						\
    clib_bitmap_vec_validate (ai, bi_len - 1);			\
  for (i = 0; i < vec_len (ai); i++)				\
    {								\
      a = ai[i];						\
      b = i < bi_len ? bi[i] : 0;				\
      do { body; } while (0);					\
      ai[i] = a;						\
      if (check_zero)						\
	n_trailing_zeros = a ? 0 : (n_trailing_zeros + 1);	\
    }								\
  if (check_zero)						\
    _vec_len (ai) -= n_trailing_zeros;				\
  return ai;							\
}

/* ALU functions: */
_ (and, a = a & b, 1)
_ (andnot, a = a &~ b, 1)
_ (or,  a = a | b, 0)
_ (xor, a = a ^ b, 1)
#undef _

/* Define functions which duplicate first argument.
   (Normal functions over-write first argument.) */
#define _(name)						\
  always_inline uword *					\
  clib_bitmap_dup_##name (uword * ai, uword * bi)	\
{ return clib_bitmap_##name (clib_bitmap_dup (ai), bi); }

_ (and);
_ (andnot);
_ (or);
_ (xor);

#undef _

/* ALU function definition macro for functions taking one bitmap and an immediate. */
#define _(name, body, check_zero)			\
always_inline uword *					\
clib_bitmap_##name (uword * ai, uword i)		\
{							\
  uword i0 = i / BITS (ai[0]);				\
  uword i1 = i % BITS (ai[0]);				\
  uword a, b;						\
  clib_bitmap_vec_validate (ai, i0);			\
  a = ai[i0];						\
  b = (uword) 1 << i1;					\
  do { body; } while (0);				\
  ai[i0] = a;						\
  if (check_zero && a == 0)				\
    ai = _clib_bitmap_remove_trailing_zeros (ai);	\
  return ai;						\
}

/* ALU functions immediate: */
_ (andi, a = a & b, 1)
_ (andnoti, a = a &~ b, 1)
_ (ori, a = a | b, 0)
_ (xori, a = a ^ b, 1)

#undef _

/* Returns random bitmap of given length. */
always_inline uword *
clib_bitmap_random (uword * ai, uword n_bits, u32 * seed)
{
  vec_reset_length (ai);

  if (n_bits > 0)
    {
      uword i = n_bits - 1;
      uword i0, i1;
      uword log2_rand_max;

      log2_rand_max = min_log2 (random_u32_max ());

      i0 = i / BITS (ai[0]);
      i1 = i % BITS (ai[0]);

      clib_bitmap_vec_validate (ai, i0);
      for (i = 0; i <= i0; i++)
	{
	  uword n;
	  for (n = 0; n < BITS (ai[i]); n += log2_rand_max)
	    ai[i] |= random_u32 (seed) << n;
	}
      if (i1 + 1 < BITS (ai[0]))
	ai[i0] &= (((uword) 1 << (i1 + 1)) - 1);
    }
  return ai;
}

/* Returns next set bit starting at bit i (~0 if not found). */
always_inline uword
clib_bitmap_next_set (uword * ai, uword i)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  uword t;
  
  if (i0 < vec_len (ai))
    {
      t = (ai[i0] >> i1) << i1;
      if (t)
	return log2_first_set (t) + i0 * BITS (ai[0]);

      for (i0++; i0 < vec_len (ai); i0++)
	{
	  t = ai[i0];
	  if (t)
	    return log2_first_set (t) + i0 * BITS (ai[0]);
	}
    }

  return ~0;
}

/* Returns next clear bit at position >= i */
always_inline uword
clib_bitmap_next_clear (uword * ai, uword i)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  uword t;
  
  if (i0 < vec_len (ai))
    {
      t = (~ai[i0] >> i1) << i1;
      if (t)
	return log2_first_set (t) + i0 * BITS (ai[0]);

      for (i0++; i0 < vec_len (ai); i0++)
	{
          t = ~ai[i0];
	  if (t)
	    return log2_first_set (t) + i0 * BITS (ai[0]);
	}
    }
  return i;
}

/* unformat list of bits into bitmap (eg "0-3,5-7,11" ) */
static inline uword
unformat_bitmap_list(unformat_input_t * input, va_list * va)
{
  uword ** bitmap_return = va_arg (* va, uword **);
  uword * bitmap = 0;

  u32 a,b;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int i;
      if (unformat (input, "%u-%u,", &a, &b))
        ;
      else if (unformat (input, "%u,", &a))
        b = a;
      else if (unformat (input, "%u-%u", &a, &b))
        ;
      else if (unformat (input, "%u", &a))
        b = a;
      else if (bitmap)
        {
	  unformat_put_input(input);
	  break;
	}
      else
        goto error;

      if (b < a)
        goto error;

      for (i = a; i <= b; i++)
        bitmap = clib_bitmap_set(bitmap, i, 1);
    }
  *bitmap_return = bitmap;
  return 1;
error:
  clib_bitmap_free(bitmap);
  return 0;
}

static inline u8 *
format_bitmap_hex(u8 * s, va_list * args)
{
  uword * bitmap = va_arg (*args, uword *);
  int i, is_trailing_zero = 1;

  if (!bitmap)
    return format(s, "0");

  i = vec_bytes (bitmap) * 2;

  while (i > 0)
    {
      u8 x = clib_bitmap_get_multiple(bitmap, --i * 4, 4);

      if (x && is_trailing_zero)
        is_trailing_zero = 0;

      if (x || !is_trailing_zero)
          s = format(s, "%x", x);
    }
  return s;
}
#endif /* included_clib_bitmap_h */
