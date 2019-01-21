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

#ifndef included_error_bootstrap_h
#define included_error_bootstrap_h

/* Bootstrap include so that #include <vppinfra/mem.h> can include e.g.
   <vppinfra/mheap.h> which depends on <vppinfra/vec.h>. */

#include <vppinfra/clib.h>	/* for uword */

enum
{
  CLIB_ERROR_FATAL = 1 << 0,
  CLIB_ERROR_ABORT = 1 << 1,
  CLIB_ERROR_WARNING = 1 << 2,
  CLIB_ERROR_ERRNO_VALID = 1 << 16,
  CLIB_ERROR_NO_RATE_LIMIT = 1 << 17,
};

/* Current function name.  Need (char *) cast to silence gcc4 pointer signedness warning. */
#define clib_error_function ((char *) __FUNCTION__)

#ifndef CLIB_ASSERT_ENABLE
#define CLIB_ASSERT_ENABLE (CLIB_DEBUG > 0)
#endif

/* Low level error reporting function.
   Code specifies whether to call exit, abort or nothing at
   all (for non-fatal warnings). */
extern void _clib_error (int code,
			 char *function_name,
			 uword line_number, char *format, ...);

#define ASSERT(truth)					\
do {							\
  if (CLIB_ASSERT_ENABLE && ! (truth))			\
    {							\
      _clib_error (CLIB_ERROR_ABORT, 0, 0,		\
		   "%s:%d (%s) assertion `%s' fails",	\
		   __FILE__,				\
		   (uword) __LINE__,			\
		   clib_error_function,			\
		   # truth);				\
    }							\
} while (0)

#if defined(__clang__)
#define STATIC_ASSERT(truth,...)
#else
#define STATIC_ASSERT(truth,...) _Static_assert(truth, __VA_ARGS__)
#endif

#define STATIC_ASSERT_SIZEOF(d, s) \
  STATIC_ASSERT (sizeof (d) == s, "Size of " #d " must be " # s " bytes")

#define STATIC_ASSERT_OFFSET_OF(s, e, o) \
  STATIC_ASSERT (STRUCT_OFFSET_OF(s,e) == o, "Offset of " #s "." #e " must be " # o)

#define STATIC_ASSERT_FITS_IN(s, e, o) \
  STATIC_ASSERT (STRUCT_OFFSET_OF(s,e) <= (o - sizeof(((s *)0)->e)), \
  #s "." #e " does not fit into " # o " bytes")

/* Assert without allocating memory. */
#define ASSERT_AND_PANIC(truth)			\
do {						\
  if (CLIB_ASSERT_ENABLE && ! (truth))		\
    os_panic ();				\
} while (0)

#endif /* included_error_bootstrap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
