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
 * Modifications to this file
 * Copyright (c) 2006-2009 by cisco Systems, Inc.
 * All rights reserved.
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

#ifndef __CGN_BITMAP_H__
#define __CGN_BITMAP_H__

/* Bitmaps built as vectors of machine words. */

#include <string.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/random.h>

#define clib_bitmap_dup(v) vec_dup(v)
#define clib_bitmap_free(v) vec_free(v)
#define clib_bitmap_bytes(v) vec_bytes(v)
#define clib_bitmap_zero(v) vec_zero(v)

/* Allocate bitmap with given number of bits. */
#define clib_bitmap_alloc(v,n_bits) \
  v = vec_new (uword, ((n_bits) + BITS (uword) - 1) / BITS (uword))

/* Sets given bit.  Returns old value. */
static inline uword
cgn_clib_bitmap_set_no_check (uword * a, uword i)
{
  uword i0 = i / BITS (a[0]);
  uword bit = (uword) 1 << (i % BITS (a[0]));
  uword ai;

/*  ASSERT (i0 < vec_len (a)); */
  ai = a[i0];
  a[i0] = ai | bit;

  return (ai & bit) != 0;
}

/* Clears given bit.  Returns old value. */
static inline 
uword cgn_clib_bitmap_clear_no_check (uword * a, uword i)
{
  uword i0 = i / BITS (a[0]);
  uword bit = (uword) 1 << (i % BITS (a[0]));
  uword ai;

/*  ASSERT (i0 < vec_len (a)); */
  ai = a[i0];
  a[i0] = ai & ~bit;

  return (ai & bit) != 0;
}

/* Gets num_bits from ai start at start. assume that all bits are
 * in the same uword.
 */
static inline uword cgn_clib_bitmap_get_bits (uword *ai, u16 start,
            unsigned char num_bits)
{
  uword i0 = start / BITS (ai[0]);
  uword i1 = start % BITS (ai[0]);
  uword result = ai[i0] >> i1;
  if(num_bits >=  BITS(ai[0])) return result;
  /* Else, we have to trim the bits */
  result = result & (((uword)1 << num_bits) - 1);
  return result;
}

/* Check if all of the bits from start to numb_bits are avaiable */
static inline uword cgn_clib_bitmap_check_if_all (uword *ai, u16 start,
            i16 num_bits)
{
  /* Now check if any bits are zero.. if yes, return false */
  uword bitmask;
  if(num_bits >= BITS(ai[0])) {
    /* assume that its going to be multiples of BUTS(ai[0]) */
    uword i0 = start / BITS (ai[0]);
    bitmask = ~0; /* set all bits to 1 */
    do {
      if(ai[i0] ^ bitmask) return 0;
      num_bits = num_bits - BITS (ai[0]);
      i0++;
    } while (num_bits > 0);
    return 1;
  }
  else {
    uword result = cgn_clib_bitmap_get_bits (ai, start, num_bits);
    bitmask = ((uword)1 << num_bits) -1; /* set only num_bits */
    return (!(result ^ bitmask));
  }
}

#endif
