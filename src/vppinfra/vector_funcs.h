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
  Copyright (c) 2008 Eliot Dresselhaus

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

#ifndef included_vector_funcs_h
#define included_vector_funcs_h

#include <vppinfra/byte_order.h>

/* Addition/subtraction. */
#if CLIB_VECTOR_WORD_BITS == 128
#define u8x_add u8x16_add
#define u16x_add u16x8_add
#define u32x_add u32x4_add
#define u64x_add u64x2_add
#define i8x_add i8x16_add
#define i16x_add i16x8_add
#define i32x_add i32x4_add
#define i64x_add i64x2_add
#define u8x_sub u8x16_sub
#define u16x_sub u16x8_sub
#define u32x_sub u32x4_sub
#define u64x_sub u64x2_sub
#define i8x_sub i8x16_sub
#define i16x_sub i16x8_sub
#define i32x_sub i32x4_sub
#define i64x_sub i64x2_sub
#endif

#if CLIB_VECTOR_WORD_BITS == 64
#define u8x_add u8x8_add
#define u16x_add u16x4_add
#define u32x_add u32x2_add
#define i8x_add i8x8_add
#define i16x_add i16x4_add
#define i32x_add i32x2_add
#define u8x_sub u8x8_sub
#define u16x_sub u16x4_sub
#define u32x_sub u32x2_sub
#define i8x_sub i8x8_sub
#define i16x_sub i16x4_sub
#define i32x_sub i32x2_sub
#endif

/* Saturating addition/subtraction. */
#if CLIB_VECTOR_WORD_BITS == 128
#define u8x_add_saturate u8x16_add_saturate
#define u16x_add_saturate u16x8_add_saturate
#define i8x_add_saturate i8x16_add_saturate
#define i16x_add_saturate i16x8_add_saturate
#define u8x_sub_saturate u8x16_sub_saturate
#define u16x_sub_saturate u16x8_sub_saturate
#define i8x_sub_saturate i8x16_sub_saturate
#define i16x_sub_saturate i16x8_sub_saturate
#endif

#if CLIB_VECTOR_WORD_BITS == 64
#define u8x_add_saturate u8x8_add_saturate
#define u16x_add_saturate u16x4_add_saturate
#define i8x_add_saturate i8x8_add_saturate
#define i16x_add_saturate i16x4_add_saturate
#define u8x_sub_saturate u8x8_sub_saturate
#define u16x_sub_saturate u16x4_sub_saturate
#define i8x_sub_saturate i8x8_sub_saturate
#define i16x_sub_saturate i16x4_sub_saturate
#endif

#define _vector_interleave(a,b,t)		\
do {						\
  t _tmp_lo = t##_interleave_lo (a, b);		\
  t _tmp_hi = t##_interleave_hi (a, b);		\
  if (CLIB_ARCH_IS_LITTLE_ENDIAN)		\
    (a) = _tmp_lo, (b) = _tmp_hi;		\
  else						\
    (a) = _tmp_hi, (b) = _tmp_lo;		\
} while (0)

/* 128 bit interleaves. */
#define u8x16_interleave(a,b) _vector_interleave(a,b,u8x16)
#define i8x16_interleave(a,b) _vector_interleave(a,b,i8x16)
#define u16x8_interleave(a,b) _vector_interleave(a,b,u16x8)
#define i16x8_interleave(a,b) _vector_interleave(a,b,i16x8)
#define u32x4_interleave(a,b) _vector_interleave(a,b,u32x4)
#define i32x4_interleave(a,b) _vector_interleave(a,b,i32x4)
#define u64x2_interleave(a,b) _vector_interleave(a,b,u64x2)
#define i64x2_interleave(a,b) _vector_interleave(a,b,i64x2)

/* 64 bit interleaves. */
#define u8x8_interleave(a,b) _vector_interleave(a,b,u8x8)
#define i8x8_interleave(a,b) _vector_interleave(a,b,i8x8)
#define u16x4_interleave(a,b) _vector_interleave(a,b,u16x4)
#define i16x4_interleave(a,b) _vector_interleave(a,b,i16x4)
#define u32x2_interleave(a,b) _vector_interleave(a,b,u32x2)
#define i32x2_interleave(a,b) _vector_interleave(a,b,i32x2)

/* Word sized interleaves. */
#if CLIB_VECTOR_WORD_BITS == 128
#define u8x_interleave u8x16_interleave
#define u16x_interleave u16x8_interleave
#define u32x_interleave u32x4_interleave
#define u64x_interleave u64x2_interleave
#endif

#if CLIB_VECTOR_WORD_BITS == 64
#define u8x_interleave u8x8_interleave
#define u16x_interleave u16x4_interleave
#define u32x_interleave u32x2_interleave
#define u64x_interleave(a,b)	/* do nothing */
#endif

/* Vector word sized shifts. */
#if CLIB_VECTOR_WORD_BITS == 128
#define u8x_shift_left u8x16_shift_left
#define i8x_shift_left i8x16_shift_left
#define u16x_shift_left u16x8_shift_left
#define i16x_shift_left i16x8_shift_left
#define u32x_shift_left u32x4_shift_left
#define i32x_shift_left i32x4_shift_left
#define u64x_shift_left u64x2_shift_left
#define i64x_shift_left i64x2_shift_left
#define u8x_shift_right u8x16_shift_right
#define i8x_shift_right i8x16_shift_right
#define u16x_shift_right u16x8_shift_right
#define i16x_shift_right i16x8_shift_right
#define u32x_shift_right u32x4_shift_right
#define i32x_shift_right i32x4_shift_right
#define u64x_shift_right u64x2_shift_right
#define i64x_shift_right i64x2_shift_right
#define u8x_rotate_left u8x16_rotate_left
#define i8x_rotate_left i8x16_rotate_left
#define u16x_rotate_left u16x8_rotate_left
#define i16x_rotate_left i16x8_rotate_left
#define u32x_rotate_left u32x4_rotate_left
#define i32x_rotate_left i32x4_rotate_left
#define u64x_rotate_left u64x2_rotate_left
#define i64x_rotate_left i64x2_rotate_left
#define u8x_rotate_right u8x16_rotate_right
#define i8x_rotate_right i8x16_rotate_right
#define u16x_rotate_right u16x8_rotate_right
#define i16x_rotate_right i16x8_rotate_right
#define u32x_rotate_right u32x4_rotate_right
#define i32x_rotate_right i32x4_rotate_right
#define u64x_rotate_right u64x2_rotate_right
#define i64x_rotate_right i64x2_rotate_right
#define u8x_ishift_left u8x16_ishift_left
#define i8x_ishift_left i8x16_ishift_left
#define u16x_ishift_left u16x8_ishift_left
#define i16x_ishift_left i16x8_ishift_left
#define u32x_ishift_left u32x4_ishift_left
#define i32x_ishift_left i32x4_ishift_left
#define u64x_ishift_left u64x2_ishift_left
#define i64x_ishift_left i64x2_ishift_left
#define u8x_ishift_right u8x16_ishift_right
#define i8x_ishift_right i8x16_ishift_right
#define u16x_ishift_right u16x8_ishift_right
#define i16x_ishift_right i16x8_ishift_right
#define u32x_ishift_right u32x4_ishift_right
#define i32x_ishift_right i32x4_ishift_right
#define u64x_ishift_right u64x2_ishift_right
#define i64x_ishift_right i64x2_ishift_right
#define u8x_irotate_left u8x16_irotate_left
#define i8x_irotate_left i8x16_irotate_left
#define u16x_irotate_left u16x8_irotate_left
#define i16x_irotate_left i16x8_irotate_left
#define u32x_irotate_left u32x4_irotate_left
#define i32x_irotate_left i32x4_irotate_left
#define u64x_irotate_left u64x2_irotate_left
#define i64x_irotate_left i64x2_irotate_left
#define u8x_irotate_right u8x16_irotate_right
#define i8x_irotate_right i8x16_irotate_right
#define u16x_irotate_right u16x8_irotate_right
#define i16x_irotate_right i16x8_irotate_right
#define u32x_irotate_right u32x4_irotate_right
#define i32x_irotate_right i32x4_irotate_right
#define u64x_irotate_right u64x2_irotate_right
#define i64x_irotate_right i64x2_irotate_right
#endif

#if CLIB_VECTOR_WORD_BITS == 64
#define u8x_shift_left u8x8_shift_left
#define i8x_shift_left i8x8_shift_left
#define u16x_shift_left u16x4_shift_left
#define i16x_shift_left i16x4_shift_left
#define u32x_shift_left u32x2_shift_left
#define i32x_shift_left i32x2_shift_left
#define u8x_shift_right u8x8_shift_right
#define i8x_shift_right i8x8_shift_right
#define u16x_shift_right u16x4_shift_right
#define i16x_shift_right i16x4_shift_right
#define u32x_shift_right u32x2_shift_right
#define i32x_shift_right i32x2_shift_right
#define u8x_rotate_left u8x8_rotate_left
#define i8x_rotate_left i8x8_rotate_left
#define u16x_rotate_left u16x4_rotate_left
#define i16x_rotate_left i16x4_rotate_left
#define u32x_rotate_left u32x2_rotate_left
#define i32x_rotate_left i32x2_rotate_left
#define u8x_rotate_right u8x8_rotate_right
#define i8x_rotate_right i8x8_rotate_right
#define u16x_rotate_right u16x4_rotate_right
#define i16x_rotate_right i16x4_rotate_right
#define u32x_rotate_right u32x2_rotate_right
#define i32x_rotate_right i32x2_rotate_right
#define u8x_ishift_left u8x8_ishift_left
#define i8x_ishift_left i8x8_ishift_left
#define u16x_ishift_left u16x4_ishift_left
#define i16x_ishift_left i16x4_ishift_left
#define u32x_ishift_left u32x2_ishift_left
#define i32x_ishift_left i32x2_ishift_left
#define u8x_ishift_right u8x8_ishift_right
#define i8x_ishift_right i8x8_ishift_right
#define u16x_ishift_right u16x4_ishift_right
#define i16x_ishift_right i16x4_ishift_right
#define u32x_ishift_right u32x2_ishift_right
#define i32x_ishift_right i32x2_ishift_right
#define u8x_irotate_left u8x8_irotate_left
#define i8x_irotate_left i8x8_irotate_left
#define u16x_irotate_left u16x4_irotate_left
#define i16x_irotate_left i16x4_irotate_left
#define u32x_irotate_left u32x2_irotate_left
#define i32x_irotate_left i32x2_irotate_left
#define u8x_irotate_right u8x8_irotate_right
#define i8x_irotate_right i8x8_irotate_right
#define u16x_irotate_right u16x4_irotate_right
#define i16x_irotate_right i16x4_irotate_right
#define u32x_irotate_right u32x2_irotate_right
#define i32x_irotate_right i32x2_irotate_right
#endif

#if CLIB_VECTOR_WORD_BITS == 128
#define u8x_splat u8x16_splat
#define i8x_splat i8x16_splat
#define u16x_splat u16x8_splat
#define i16x_splat i16x8_splat
#define u32x_splat u32x4_splat
#define i32x_splat i32x4_splat
#define u64x_splat u64x2_splat
#define i64x_splat i64x2_splat
#endif

#if CLIB_VECTOR_WORD_BITS == 64
#define u8x_splat u8x8_splat
#define i8x_splat i8x8_splat
#define u16x_splat u16x4_splat
#define i16x_splat i16x4_splat
#define u32x_splat u32x2_splat
#define i32x_splat i32x2_splat
#endif

#define u32x4_transpose_step(x,y)		\
do {						\
  u32x4 _x = (x);				\
  u32x4 _y = (y);				\
  (x) = u32x4_interleave_lo (_x, _y);		\
  (y) = u32x4_interleave_hi (_x, _y);		\
} while (0)

/* 4x4 transpose: x_ij -> x_ji */
#define u32x4_transpose(x0,x1,x2,x3)		\
do {						\
  u32x4 _x0 = (u32x4) (x0);			\
  u32x4 _x1 = (u32x4) (x1);			\
  u32x4 _x2 = (u32x4) (x2);			\
  u32x4 _x3 = (u32x4) (x3);			\
  u32x4_transpose_step (_x0, _x2);		\
  u32x4_transpose_step (_x1, _x3);		\
  u32x4_transpose_step (_x0, _x1);		\
  u32x4_transpose_step (_x2, _x3);		\
  (x0) = (u32x4) _x0;				\
  (x1) = (u32x4) _x1;				\
  (x2) = (u32x4) _x2;				\
  (x3) = (u32x4) _x3;				\
} while (0)

#define i32x4_transpose(x0,x1,x2,x3)		\
do {						\
  u32x4 _x0 = (u32x4) (x0);			\
  u32x4 _x1 = (u32x4) (x1);			\
  u32x4 _x2 = (u32x4) (x2);			\
  u32x4 _x3 = (u32x4) (x3);			\
  u32x4_transpose_step (_x0, _x2);		\
  u32x4_transpose_step (_x1, _x3);		\
  u32x4_transpose_step (_x0, _x1);		\
  u32x4_transpose_step (_x2, _x3);		\
  (x0) = (i32x4) _x0;				\
  (x1) = (i32x4) _x1;				\
  (x2) = (i32x4) _x2;				\
  (x3) = (i32x4) _x3;				\
} while (0)

#undef _

#endif /* included_vector_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
