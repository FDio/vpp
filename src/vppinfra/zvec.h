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
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

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

#ifndef included_zvec_h
#define included_zvec_h

#include <vppinfra/clib.h>
#include <vppinfra/error.h>	/* for ASSERT */
#include <vppinfra/format.h>

/* zvec: compressed vectors.

   Data is entropy coded with 32 bit "codings".

   Consider coding as bitmap, coding = 2^c_0 + 2^c_1 + ... + 2^c_n
   With c_0 < c_1 < ... < c_n.  coding == 0 represents c_n = BITS (uword).

   Unsigned integers i = 0 ... are represented as follows:

       0 <= i < 2^c_0       	(i << 1) | (1 << 0) binary:   i 1
   2^c_0 <= i < 2^c_0 + 2^c_1   (i << 2) | (1 << 1) binary: i 1 0
   ...                                              binary: i 0 ... 0

   Smaller numbers use less bits.  Coding is chosen so that encoding
   of given histogram of typical values gives smallest number of bits.
   The number and position of coding bits c_i are used to best fit the
   histogram of typical values.
*/

typedef struct
{
  /* Smallest coding for given histogram of typical data. */
  u32 coding;

  /* Number of data in histogram. */
  u32 n_data;

  /* Number of codes (unique values) in histogram. */
  u32 n_codes;

  /* Number of bits in smallest coding of data. */
  u32 min_coding_bits;

  /* Average number of bits per code. */
  f64 ave_coding_bits;
} zvec_coding_info_t;

/* Encode/decode data. */
uword zvec_encode (uword coding, uword data, uword * n_result_bits);
uword zvec_decode (uword coding, uword zdata, uword * n_zdata_bits);

format_function_t format_zvec_coding;

typedef u32 zvec_histogram_count_t;

#define zvec_coding_from_histogram(h,count_field,len,max_value_to_encode,zc) \
  _zvec_coding_from_histogram ((h), (len),				\
			       STRUCT_OFFSET_OF_VAR (h, count_field),	\
			       sizeof (h[0]),				\
			       max_value_to_encode,			\
			       (zc))

uword
_zvec_coding_from_histogram (void *_histogram,
			     uword histogram_len,
			     uword histogram_elt_count_offset,
			     uword histogram_elt_bytes,
			     uword max_value_to_encode,
			     zvec_coding_info_t * coding_info_return);

#define _(TYPE,IS_SIGNED)						\
  uword * zvec_encode_##TYPE (uword * zvec, uword * zvec_n_bits, uword coding, \
			   void * data, uword data_stride, uword n_data);

_(u8, /* is_signed */ 0);
_(u16, /* is_signed */ 0);
_(u32, /* is_signed */ 0);
_(u64, /* is_signed */ 0);
_(i8, /* is_signed */ 1);
_(i16, /* is_signed */ 1);
_(i32, /* is_signed */ 1);
_(i64, /* is_signed */ 1);

#undef _

#define _(TYPE,IS_SIGNED)			\
  void zvec_decode_##TYPE (uword * zvec,	\
			   uword * zvec_n_bits,	\
			   uword coding,	\
			   void * data,		\
			   uword data_stride,	\
			   uword n_data)

_(u8, /* is_signed */ 0);
_(u16, /* is_signed */ 0);
_(u32, /* is_signed */ 0);
_(u64, /* is_signed */ 0);
_(i8, /* is_signed */ 1);
_(i16, /* is_signed */ 1);
_(i32, /* is_signed */ 1);
_(i64, /* is_signed */ 1);

#undef _

/* Signed <=> unsigned conversion.
      -1, -2, -3, ... =>    1, 3, 5, ... odds
   0, +1, +2, +3, ... => 0, 2, 4, 6, ... evens */
always_inline uword
zvec_signed_to_unsigned (word s)
{
  uword a = s < 0;
  s = 2 * s + a;
  return a ? -s : s;
}

always_inline word
zvec_unsigned_to_signed (uword u)
{
  uword a = u & 1;
  u >>= 1;
  return a ? -u : u;
}

#endif /* included_zvec_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
