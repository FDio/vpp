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
  Copyright (c) 2006 Eliot Dresselhaus

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

#include <vppinfra/string.h>
#include <vppinfra/error.h>

/* Exchanges source and destination. */
void
clib_memswap (void *_a, void *_b, uword bytes)
{
  uword pa = pointer_to_uword (_a);
  uword pb = pointer_to_uword (_b);

#define _(TYPE)					\
  if (0 == ((pa | pb) & (sizeof (TYPE) - 1)))	\
    {						\
      TYPE * a = uword_to_pointer (pa, TYPE *);	\
      TYPE * b = uword_to_pointer (pb, TYPE *);	\
						\
      while (bytes >= 2*sizeof (TYPE))		\
	{					\
	  TYPE a0, a1, b0, b1;			\
	  bytes -= 2*sizeof (TYPE);		\
	  a += 2;				\
	  b += 2;				\
	  a0 = a[-2]; a1 = a[-1];		\
	  b0 = b[-2]; b1 = b[-1];		\
	  a[-2] = b0; a[-1] = b1;		\
	  b[-2] = a0; b[-1] = a1;		\
	}					\
      pa = pointer_to_uword (a);		\
      pb = pointer_to_uword (b);		\
    }

  if (BITS (uword) == BITS (u64))
    _(u64);
  _(u32);
  _(u16);
  _(u8);

#undef _

  ASSERT (bytes < 2);
  if (bytes)
    {
      u8 *a = uword_to_pointer (pa, u8 *);
      u8 *b = uword_to_pointer (pb, u8 *);
      u8 a0 = a[0], b0 = b[0];
      a[0] = b0;
      b[0] = a0;
    }
}

void
clib_c11_violation (const char *s)
{
  _clib_error (CLIB_ERROR_WARNING, (char *) __FUNCTION__, 0, (char *) s);
}

errno_t
memcpy_s (void *__restrict__ dest, rsize_t dmax,
	  const void *__restrict__ src, rsize_t n)
{
  return memcpy_s_inline (dest, dmax, src, n);
}

errno_t
memset_s (void *s, rsize_t smax, int c, rsize_t n)
{
  return memset_s_inline (s, smax, c, n);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
