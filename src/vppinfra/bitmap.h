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

/** \file
    Bitmaps built as vectors of machine words
*/

#include <vppinfra/vec.h>
#include <vppinfra/random.h>
#include <vppinfra/error.h>
#include <vppinfra/bitops.h>	/* for count_set_bits */

typedef uword clib_bitmap_t;

/** predicate function; is an entire bitmap empty?
    @param ai - pointer to a bitmap
    @returns 1 if the entire bitmap is zero, 0 otherwise
*/
always_inline uword
clib_bitmap_is_zero (uword * ai)
{
  uword i;
  for (i = 0; i < vec_len (ai); i++)
    if (ai[i] != 0)
      return 0;
  return 1;
}

/** predicate function; are two bitmaps equal?
    @param a - pointer to a bitmap
    @param b - pointer to a bitmap
    @returns 1 if the bitmaps are equal, 0 otherwise
*/
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

/** Duplicate a bitmap
    @param v - pointer to a bitmap
    @returns a duplicate of the bitmap
*/
#define clib_bitmap_dup(v) vec_dup(v)

/** Free a bitmap
    @param v - pointer to the bitmap to free
*/
#define clib_bitmap_free(v) vec_free(v)

/** Number of bytes in a bitmap
    @param v - pointer to the bitmap
*/
#define clib_bitmap_bytes(v) vec_bytes(v)

/** Clear a bitmap
    @param v - pointer to the bitmap to clear
*/
#define clib_bitmap_zero(v) vec_zero(v)

/** Allocate a bitmap with the supplied number of bits
    @param [out] v - the resulting bitmap
    @param n_bits - the required number of bits
*/

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

/** Sets the ith bit of a bitmap to new_value.
    No sanity checking. Be careful.
    @param a - pointer to the bitmap
    @param i - the bit position to interrogate
    @param new_value - new value for the bit
    @returns the old value of the bit
*/
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
  ai &= ~bit;
  ai |= ((uword) (new_value != 0)) << i1;
  a[i0] = ai;
  return old_value;
}

/** Sets the ith bit of a bitmap to new_value
    Removes trailing zeros from the bitmap
    @param ai - pointer to the bitmap
    @param i - the bit position to interrogate
    @param value - new value for the bit
    @returns the old value of the bit
*/
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

/** Gets the ith bit value from a bitmap
    @param ai - pointer to the bitmap
    @param i - the bit position to interrogate
    @returns the indicated bit value
*/
always_inline uword
clib_bitmap_get (uword * ai, uword i)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  return i0 < vec_len (ai) && 0 != ((ai[i0] >> i1) & 1);
}

/** Gets the ith bit value from a bitmap
    Does not sanity-check the bit position. Be careful.
    @param ai - pointer to the bitmap
    @param i - the bit position to interrogate
    @returns the indicated bit value, or garbage if the bit position is
    out of range.
*/
always_inline uword
clib_bitmap_get_no_check (uword * ai, uword i)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  return 0 != ((ai[i0] >> i1) & 1);
}

always_inline uword
clib_bitmap_get_multiple_no_check (uword * ai, uword i, uword n_bits)
{
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  ASSERT (i1 + n_bits <= BITS (uword));
  return 0 != ((ai[i0] >> i1) & pow2_mask (n_bits));
}

/** Gets the ith through ith + n_bits bit values from a bitmap
    @param bitmap - pointer to the bitmap
    @param i - the first bit position to retrieve
    @param n_bits - the number of bit positions to retrieve
    @returns the indicated range of bits
*/
always_inline uword
clib_bitmap_get_multiple (uword * bitmap, uword i, uword n_bits)
{
  uword i0, i1, result;
  uword l = vec_len (bitmap);

  ASSERT (n_bits <= BITS (result));

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
      result |=
	(bitmap[i0] & (((uword) 1 << n_bits) - 1)) << (BITS (bitmap[0]) - i1);
    }

  return result;
}

/** sets the ith through ith + n_bits bits in a bitmap
    @param bitmap - pointer to the bitmap
    @param i - the first bit position to retrieve
    @param value - the values to set
    @param n_bits - the number of bit positions to set
    @returns a pointer to the updated bitmap, which may expand and move
*/

always_inline uword *
clib_bitmap_set_multiple (uword * bitmap, uword i, uword value, uword n_bits)
{
  uword i0, i1, l, t, m;

  ASSERT (n_bits <= BITS (value));

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

always_inline uword *
clfib_bitmap_set_region (uword * bitmap, uword i, uword value, uword n_bits)
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

/** Macro to iterate across set bits in a bitmap

    @param i - the current set bit
    @param ai - the bitmap
    @param body - the expression to evaluate for each set bit
*/
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


/** Return the lowest numbered set bit in a bitmap
    @param ai - pointer to the bitmap
    @returns lowest numbered set bit, or ~0 if the entire bitmap is zero
*/
always_inline uword
clib_bitmap_first_set (uword * ai)
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

/** Return the higest numbered set bit in a bitmap
    @param ai - pointer to the bitmap
    @returns lowest numbered set bit, or ~0 if the entire bitmap is zero
*/
always_inline uword
clib_bitmap_last_set (uword * ai)
{
  uword i;

  for (i = vec_len (ai); i > 0; i--)
    {
      uword x = ai[i - 1];
      if (x != 0)
	{
	  uword first_bit;
	  count_leading_zeros (first_bit, x);
	  return (i) * BITS (ai[0]) - first_bit - 1;
	}
    }
  return ~0;
}

/** Return the lowest numbered clear bit in a bitmap
    @param ai - pointer to the bitmap
    @returns lowest numbered clear bit
*/
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

/** Return the number of set bits in a bitmap
    @param ai - pointer to the bitmap
    @returns the number of set bits in the bitmap
*/
always_inline uword
clib_bitmap_count_set_bits (uword * ai)
{
  uword i;
  uword n_set = 0;
  for (i = 0; i < vec_len (ai); i++)
    n_set += count_set_bits (ai[i]);
  return n_set;
}

/** Logical operator across two bitmaps

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns ai = ai and bi. ai is modified, bi is not modified
*/
always_inline uword *clib_bitmap_and (uword * ai, uword * bi);

/** Logical operator across two bitmaps

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns ai = ai & ~bi. ai is modified, bi is not modified
*/
always_inline uword *clib_bitmap_andnot (uword * ai, uword * bi);

/** Logical operator across two bitmaps

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns ai = ai & ~bi. ai is modified, bi is not modified
*/
always_inline uword *clib_bitmap_or (uword * ai, uword * bi);
/** Logical operator across two bitmaps

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns ai = ai or bi. ai is modified, bi is not modified
*/
always_inline uword *clib_bitmap_or (uword * ai, uword * bi);

/** Logical operator across two bitmaps

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns ai = ai xor bi. ai is modified, bi is not modified
*/
always_inline uword *clib_bitmap_xor (uword * ai, uword * bi);

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
_(and, a = a & b, 1)
_(andnot, a = a & ~b, 1) _(or, a = a | b, 0) _(xor, a = a ^ b, 1)
#undef _
/** Logical operator across two bitmaps which duplicates the first bitmap

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns aiDup = ai and bi. Neither ai nor bi are modified
*/
     always_inline uword *
     clib_bitmap_dup_and (uword * ai, uword * bi);

/** Logical operator across two bitmaps which duplicates the first bitmap

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns aiDup = ai & ~bi. Neither ai nor bi are modified
*/
     always_inline uword *
     clib_bitmap_dup_andnot (uword * ai, uword * bi);

/** Logical operator across two bitmaps which duplicates the first bitmap

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns aiDup = ai or bi. Neither ai nor bi are modified
*/
     always_inline uword *
     clib_bitmap_dup_or (uword * ai, uword * bi);

/** Logical operator across two bitmaps which duplicates the first bitmap

    @param ai - pointer to the destination bitmap
    @param bi - pointer to the source bitmap
    @returns aiDup = ai xor bi. Neither ai nor bi are modified
*/
     always_inline uword *
     clib_bitmap_dup_xor (uword * ai, uword * bi);

#define _(name)						\
  always_inline uword *					\
  clib_bitmap_dup_##name (uword * ai, uword * bi)	\
{ return clib_bitmap_##name (clib_bitmap_dup (ai), bi); }

_(and);
_(andnot);
_(or);
_(xor);

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
_(andi, a = a & b, 1)
_(andnoti, a = a & ~b, 1) _(ori, a = a | b, 0) _(xori, a = a ^ b, 1)
#undef _
/** Return a random bitmap of the requested length
    @param ai - pointer to the destination bitmap
    @param n_bits - number of bits to allocate
    @param [in,out] seed - pointer to the random number seed
    @returns a reasonably random bitmap based. See random.h.
*/
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

/** Return the next set bit in a bitmap starting at bit i
    @param ai - pointer to the bitmap
    @param i - first bit position to test
    @returns first set bit position at or after i,
    ~0 if no further set bits are found
*/
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

/** Return the next clear bit in a bitmap starting at bit i
    @param ai - pointer to the bitmap
    @param i - first bit position to test
    @returns first clear bit position at or after i
*/
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

/** unformat a list of bit ranges into a bitmap (eg "0-3,5-7,11" )

    uword * bitmap;
    rv = unformat ("%U", unformat_bitmap_list, &bitmap);

    Standard unformat_function_t arguments

    @param input - pointer an unformat_input_t
    @param va - varargs list comprising a single uword **
    @returns 1 on success, 0 on failure
*/
static inline uword
unformat_bitmap_list (unformat_input_t * input, va_list * va)
{
  uword **bitmap_return = va_arg (*va, uword **);
  uword *bitmap = 0;

  u32 a, b;

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
	  unformat_put_input (input);
	  break;
	}
      else
	goto error;

      if (b < a)
	goto error;

      for (i = a; i <= b; i++)
	bitmap = clib_bitmap_set (bitmap, i, 1);
    }
  *bitmap_return = bitmap;
  return 1;
error:
  clib_bitmap_free (bitmap);
  return 0;
}

/** Format a bitmap as a string of hex bytes

    uword * bitmap;
    s = format ("%U", format_bitmap_hex, bitmap);

    Standard format_function_t arguments

    @param s - string under construction
    @param args - varargs list comprising a single uword *
    @returns string under construction
*/
static inline u8 *
format_bitmap_hex (u8 * s, va_list * args)
{
  uword *bitmap = va_arg (*args, uword *);
  int i, is_trailing_zero = 1;

  if (!bitmap)
    return format (s, "0");

  i = vec_bytes (bitmap) * 2;

  while (i > 0)
    {
      u8 x = clib_bitmap_get_multiple (bitmap, --i * 4, 4);

      if (x && is_trailing_zero)
	is_trailing_zero = 0;

      if (x || !is_trailing_zero)
	s = format (s, "%x", x);
    }
  return s;
}
#endif /* included_clib_bitmap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
