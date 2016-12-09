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
 * ip4/ip_checksum.c: ip/tcp/udp checksums
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/ip/ip.h>

ip_csum_t
ip_incremental_checksum (ip_csum_t sum, void *_data, uword n_bytes)
{
  uword data = pointer_to_uword (_data);
  ip_csum_t sum0, sum1;

  sum0 = 0;
  sum1 = sum;

  /* Align data pointer to 64 bits. */
#define _(t)					\
do {						\
  if (n_bytes >= sizeof (t)			\
      && sizeof (t) < sizeof (ip_csum_t)	\
      && (data % (2 * sizeof (t))) != 0)	\
    {						\
      sum0 += * uword_to_pointer (data, t *);	\
      data += sizeof (t);			\
      n_bytes -= sizeof (t);			\
    }						\
} while (0)

  _(u8);
  _(u16);
  if (BITS (ip_csum_t) > 32)
    _(u32);

#undef _

  {
    ip_csum_t *d = uword_to_pointer (data, ip_csum_t *);

    while (n_bytes >= 2 * sizeof (d[0]))
      {
	sum0 = ip_csum_with_carry (sum0, d[0]);
	sum1 = ip_csum_with_carry (sum1, d[1]);
	d += 2;
	n_bytes -= 2 * sizeof (d[0]);
      }

    data = pointer_to_uword (d);
  }

#define _(t)								\
do {									\
  if (n_bytes >= sizeof (t) && sizeof (t) <= sizeof (ip_csum_t))	\
    {									\
      sum0 = ip_csum_with_carry (sum0, * uword_to_pointer (data, t *));	\
      data += sizeof (t);						\
      n_bytes -= sizeof (t);						\
    }									\
} while (0)

  if (BITS (ip_csum_t) > 32)
    _(u64);
  _(u32);
  _(u16);
  _(u8);

#undef _

  /* Combine even and odd sums. */
  sum0 = ip_csum_with_carry (sum0, sum1);

  return sum0;
}

ip_csum_t
ip_csum_and_memcpy (ip_csum_t sum, void *dst, void *src, uword n_bytes)
{
  uword n_left;
  ip_csum_t sum0 = sum, sum1;
  n_left = n_bytes;

  if (n_left && (pointer_to_uword (dst) & sizeof (u8)))
    {
      u8 *d8, val;

      d8 = dst;
      val = ((u8 *) src)[0];
      d8[0] = val;
      dst += 1;
      src += 1;
      n_left -= 1;
      sum0 =
	ip_csum_with_carry (sum0, val << (8 * CLIB_ARCH_IS_LITTLE_ENDIAN));
    }

  while ((n_left >= sizeof (u16))
	 && (pointer_to_uword (dst) & (sizeof (sum) - sizeof (u16))))
    {
      u16 *d16, *s16;

      d16 = dst;
      s16 = src;

      d16[0] = clib_mem_unaligned (&s16[0], u16);

      sum0 = ip_csum_with_carry (sum0, d16[0]);
      dst += sizeof (u16);
      src += sizeof (u16);
      n_left -= sizeof (u16);
    }

  sum1 = 0;
  while (n_left >= 2 * sizeof (sum))
    {
      ip_csum_t dst0, dst1;
      ip_csum_t *dst_even, *src_even;

      dst_even = dst;
      src_even = src;
      dst0 = clib_mem_unaligned (&src_even[0], ip_csum_t);
      dst1 = clib_mem_unaligned (&src_even[1], ip_csum_t);

      dst_even[0] = dst0;
      dst_even[1] = dst1;

      dst += 2 * sizeof (dst_even[0]);
      src += 2 * sizeof (dst_even[0]);
      n_left -= 2 * sizeof (dst_even[0]);

      sum0 = ip_csum_with_carry (sum0, dst0);
      sum1 = ip_csum_with_carry (sum1, dst1);
    }

  sum0 = ip_csum_with_carry (sum0, sum1);
  while (n_left >= 1 * sizeof (sum))
    {
      ip_csum_t dst0, *dst_even, *src_even;

      dst_even = dst;
      src_even = src;

      dst0 = clib_mem_unaligned (&src_even[0], ip_csum_t);

      dst_even[0] = dst0;

      dst += 1 * sizeof (sum);
      src += 1 * sizeof (sum);
      n_left -= 1 * sizeof (sum);

      sum0 = ip_csum_with_carry (sum0, dst0);
    }

  while (n_left >= sizeof (u16))
    {
      u16 dst0, *dst_short, *src_short;

      dst_short = dst;
      src_short = src;

      dst0 = clib_mem_unaligned (&src_short[0], u16);

      dst_short[0] = dst0;

      sum0 = ip_csum_with_carry (sum0, dst_short[0]);
      dst += 1 * sizeof (dst0);
      src += 1 * sizeof (dst0);
      n_left -= 1 * sizeof (dst0);

    }

  if (n_left == 1)
    {
      u8 *d8, *s8, val;

      d8 = dst;
      s8 = src;

      d8[0] = val = s8[0];
      d8 += 1;
      s8 += 1;
      n_left -= 1;
      sum0 = ip_csum_with_carry (sum0, val << (8 * CLIB_ARCH_IS_BIG_ENDIAN));
    }

  return sum0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
