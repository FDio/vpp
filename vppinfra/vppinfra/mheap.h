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

#ifndef included_mheap_h
#define included_mheap_h

#include <vppinfra/vec.h>
#include <vppinfra/error.h>	/* clib_error_t */
#include <vppinfra/mem.h>	/* clib_mem_usage_t */
#include <vppinfra/format.h>	/* for unformat_input_t */

/* Allocate size bytes.  New heap and offset are returned.
   offset == ~0 means allocation failed. */
always_inline void *
mheap_get (void *v, uword size, uword * offset_return)
{
  return mheap_get_aligned (v, size, 0, 0, offset_return);
}

/* Create allocation heap of given size.
 * The actual usable size is smaller than the requested size.
 * memory_bytes must be greater than mheap_page_size + sizeof (mheap_t) + 16.
 * Otherwise, allocation may fail and return 0.
 */
void *mheap_alloc (void *memory, uword memory_bytes);
void *mheap_alloc_with_flags (void *memory, uword memory_bytes, uword flags);

#define mheap_free(v) (v) = _mheap_free(v)
void *_mheap_free (void *v);

void mheap_foreach (void *v,
		    uword (*func) (void *arg, void *v, void *elt_data,
				   uword elt_size), void *arg);

/* Format mheap data structures as string. */
u8 *format_mheap (u8 * s, va_list * va);

/* Validate internal consistency. */
void mheap_validate (void *h);

/* Query bytes used. */
uword mheap_bytes (void *v);

void mheap_usage (void *v, clib_mem_usage_t * usage);

/* Enable disable traceing. */
void mheap_trace (void *v, int enable);

/* Test routine. */
int test_mheap_main (unformat_input_t * input);

#endif /* included_mheap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
