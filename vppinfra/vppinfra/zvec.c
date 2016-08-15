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

#include <vppinfra/bitmap.h>
#include <vppinfra/bitops.h>	/* for next_with_same_number_of_set_bits */
#include <vppinfra/error.h>	/* for ASSERT */
#include <vppinfra/mem.h>
#include <vppinfra/os.h>	/* for os_panic */
#include <vppinfra/vec.h>
#include <vppinfra/zvec.h>

/* Consider coding as bitmap, coding = 2^c_0 + 2^c_1 + ... + 2^c_n
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

/* Decode given compressed data.  Return number of compressed data
   bits used. */
uword
zvec_decode (uword coding, uword zdata, uword * n_zdata_bits)
{
  uword c, d, result, n_bits;
  uword explicit_end, implicit_end;

  result = 0;
  n_bits = 0;
  while (1)
    {
      c = first_set (coding);
      implicit_end = c == coding;
      explicit_end = (zdata & 1) & ~implicit_end;
      d = (zdata >> explicit_end) & (c - 1);
      if (explicit_end | implicit_end)
	{
	  result += d;
	  n_bits += min_log2 (c) + explicit_end;
	  break;
	}
      n_bits += 1;
      result += c;
      coding ^= c;
      zdata >>= 1;
    }

  if (coding == 0)
    n_bits = BITS (uword);

  *n_zdata_bits = n_bits;
  return result;
}

uword
zvec_encode (uword coding, uword data, uword * n_result_bits)
{
  uword c, shift, result;
  uword explicit_end, implicit_end;

  /* Data must be in range.  Note special coding == 0
     would break for data - 1 <= coding. */
  ASSERT (data <= coding - 1);

  shift = 0;
  while (1)
    {
      c = first_set (coding);
      implicit_end = c == coding;
      explicit_end = ((data & (c - 1)) == data);
      if (explicit_end | implicit_end)
	{
	  uword t = explicit_end & ~implicit_end;
	  result = ((data << t) | t) << shift;
	  *n_result_bits =
	    /* data bits */ (c == 0 ? BITS (uword) : min_log2 (c))
	    /* shift bits */  + shift + t;
	  return result;
	}
      data -= c;
      coding ^= c;
      shift++;
    }

  /* Never reached. */
  ASSERT (0);
  return ~0;
}

always_inline uword
get_data (void *data, uword data_bytes, uword is_signed)
{
  if (data_bytes == 1)
    return is_signed ? zvec_signed_to_unsigned (*(i8 *) data) : *(u8 *) data;
  else if (data_bytes == 2)
    return is_signed ? zvec_signed_to_unsigned (*(i16 *) data) : *(u16 *)
      data;
  else if (data_bytes == 4)
    return is_signed ? zvec_signed_to_unsigned (*(i32 *) data) : *(u32 *)
      data;
  else if (data_bytes == 8)
    return is_signed ? zvec_signed_to_unsigned (*(i64 *) data) : *(u64 *)
      data;
  else
    {
      os_panic ();
      return ~0;
    }
}

always_inline void
put_data (void *data, uword data_bytes, uword is_signed, uword x)
{
  if (data_bytes == 1)
    {
      if (is_signed)
	*(i8 *) data = zvec_unsigned_to_signed (x);
      else
	*(u8 *) data = x;
    }
  else if (data_bytes == 2)
    {
      if (is_signed)
	*(i16 *) data = zvec_unsigned_to_signed (x);
      else
	*(u16 *) data = x;
    }
  else if (data_bytes == 4)
    {
      if (is_signed)
	*(i32 *) data = zvec_unsigned_to_signed (x);
      else
	*(u32 *) data = x;
    }
  else if (data_bytes == 8)
    {
      if (is_signed)
	*(i64 *) data = zvec_unsigned_to_signed (x);
      else
	*(u64 *) data = x;
    }
  else
    {
      os_panic ();
    }
}

always_inline uword *
zvec_encode_inline (uword * zvec,
		    uword * zvec_n_bits,
		    uword coding,
		    void *data,
		    uword data_stride,
		    uword n_data, uword data_bytes, uword is_signed)
{
  uword i;

  i = *zvec_n_bits;
  while (n_data >= 1)
    {
      uword d0, z0, l0;

      d0 = get_data (data + 0 * data_stride, data_bytes, is_signed);
      data += 1 * data_stride;
      n_data -= 1;

      z0 = zvec_encode (coding, d0, &l0);
      zvec = clib_bitmap_set_multiple (zvec, i, z0, l0);
      i += l0;
    }

  *zvec_n_bits = i;
  return zvec;
}

#define _(TYPE,IS_SIGNED)					\
  uword * zvec_encode_##TYPE (uword * zvec,			\
			      uword * zvec_n_bits,		\
			      uword coding,			\
			      void * data,			\
			      uword data_stride,		\
			      uword n_data)			\
  {								\
    return zvec_encode_inline (zvec, zvec_n_bits,		\
			    coding,				\
			    data, data_stride, n_data,		\
			    /* data_bytes */ sizeof (TYPE),	\
			    /* is_signed */ IS_SIGNED);		\
  }

_(u8, /* is_signed */ 0);
_(u16, /* is_signed */ 0);
_(u32, /* is_signed */ 0);
_(u64, /* is_signed */ 0);
_(i8, /* is_signed */ 1);
_(i16, /* is_signed */ 1);
_(i32, /* is_signed */ 1);
_(i64, /* is_signed */ 1);

#undef _

always_inline uword
coding_max_n_bits (uword coding)
{
  uword n_bits;
  (void) zvec_decode (coding, 0, &n_bits);
  return n_bits;
}

always_inline void
zvec_decode_inline (uword * zvec,
		    uword * zvec_n_bits,
		    uword coding,
		    void *data,
		    uword data_stride,
		    uword n_data, uword data_bytes, uword is_signed)
{
  uword i, n_max;

  i = *zvec_n_bits;
  n_max = coding_max_n_bits (coding);
  while (n_data >= 1)
    {
      uword d0, z0, l0;

      z0 = clib_bitmap_get_multiple (zvec, i, n_max);
      d0 = zvec_decode (coding, z0, &l0);
      i += l0;
      put_data (data + 0 * data_stride, data_bytes, is_signed, d0);
      data += 1 * data_stride;
      n_data -= 1;
    }
  *zvec_n_bits = i;
}

#define _(TYPE,IS_SIGNED)					\
  void zvec_decode_##TYPE (uword * zvec,			\
			   uword * zvec_n_bits,			\
			   uword coding,			\
			   void * data,				\
			   uword data_stride,			\
			   uword n_data)			\
  {								\
    return zvec_decode_inline (zvec, zvec_n_bits,		\
			       coding,				\
			       data, data_stride, n_data,	\
			       /* data_bytes */ sizeof (TYPE),	\
			       /* is_signed */ IS_SIGNED);	\
  }

_(u8, /* is_signed */ 0);
_(u16, /* is_signed */ 0);
_(u32, /* is_signed */ 0);
_(u64, /* is_signed */ 0);
_(i8, /* is_signed */ 1);
_(i16, /* is_signed */ 1);
_(i32, /* is_signed */ 1);
_(i64, /* is_signed */ 1);

#undef _

/* Compute number of bits needed to encode given histogram. */
static uword
zvec_coding_bits (uword coding, uword * histogram_counts, uword min_bits)
{
  uword n_type_bits, n_bits;
  uword this_count, last_count, max_count_index;
  uword i, b, l;

  n_bits = 0;
  n_type_bits = 1;
  last_count = 0;
  max_count_index = vec_len (histogram_counts) - 1;

  /* Coding is not large enough to encode given data. */
  if (coding <= max_count_index)
    return ~0;

  i = 0;
  while (coding != 0)
    {
      b = first_set (coding);
      l = min_log2 (b);
      i += b;

      this_count =
	histogram_counts[i > max_count_index ? max_count_index : i - 1];

      /* No more data to encode? */
      if (this_count == last_count)
	break;

      /* Last coding is i 0 ... 0 so we don't need an extra type bit. */
      if (coding == b)
	n_type_bits--;

      n_bits += (this_count - last_count) * (n_type_bits + l);

      /* This coding cannot be minimal: so return. */
      if (n_bits >= min_bits)
	return ~0;

      last_count = this_count;
      coding ^= b;
      n_type_bits++;
    }

  return n_bits;
}

uword
_zvec_coding_from_histogram (void *histogram,
			     uword histogram_len,
			     uword histogram_elt_count_offset,
			     uword histogram_elt_bytes,
			     uword max_value_to_encode,
			     zvec_coding_info_t * coding_return)
{
  uword coding, min_coding;
  uword min_coding_bits, coding_bits;
  uword i, n_bits_set, total_count;
  uword *counts;
  zvec_histogram_count_t *h_count = histogram + histogram_elt_count_offset;

  if (histogram_len < 1)
    {
      coding_return->coding = 0;
      coding_return->min_coding_bits = 0;
      coding_return->n_data = 0;
      coding_return->n_codes = 0;
      coding_return->ave_coding_bits = 0;
      return 0;
    }

  total_count = 0;
  counts = vec_new (uword, histogram_len);
  for (i = 0; i < histogram_len; i++)
    {
      zvec_histogram_count_t this_count = h_count[0];
      total_count += this_count;
      counts[i] = total_count;
      h_count =
	(zvec_histogram_count_t *) ((void *) h_count + histogram_elt_bytes);
    }

  min_coding = 0;
  min_coding_bits = ~0;

  {
    uword base_coding =
      max_value_to_encode !=
      ~0 ? (1 + max_value_to_encode) : vec_len (counts);
    uword max_coding = max_pow2 (2 * base_coding);

    for (n_bits_set = 1; n_bits_set <= 8; n_bits_set++)
      {
	for (coding = pow2_mask (n_bits_set);
	     coding < max_coding;
	     coding = next_with_same_number_of_set_bits (coding))
	  {
	    coding_bits = zvec_coding_bits (coding, counts, min_coding_bits);
	    if (coding_bits >= min_coding_bits)
	      continue;
	    min_coding_bits = coding_bits;
	    min_coding = coding;
	  }
      }
  }

  if (coding_return)
    {
      coding_return->coding = min_coding;
      coding_return->min_coding_bits = min_coding_bits;
      coding_return->n_data = total_count;
      coding_return->n_codes = vec_len (counts);
      coding_return->ave_coding_bits =
	(f64) min_coding_bits / (f64) total_count;
    }

  vec_free (counts);

  return min_coding;
}

u8 *
format_zvec_coding (u8 * s, va_list * args)
{
  zvec_coding_info_t *c = va_arg (*args, zvec_coding_info_t *);
  return format (s,
		 "zvec coding 0x%x, %d elts, %d codes, %d bits total, %.4f ave bits/code",
		 c->coding, c->n_data, c->n_codes, c->min_coding_bits,
		 c->ave_coding_bits);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
