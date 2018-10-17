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

#include <vppinfra/cache.h>
#include <vppinfra/fifo.h>
#include <vppinfra/error.h>
#include <vppinfra/string.h>

/*
  General first in/first out queues.
  FIFOs can have arbitrary size and type.
  Let T be any type (i.e. char, int, struct foo, etc.).

  A null fifo is initialized:

    T * f = 0;

  For example, typedef struct { int a, b; } T;

  Elements can be added in 3 ways.

    #1 1 element is added:
       T x;
       x.a = 10; x.b = 20;
       fifo_add1 (f, x);

    #2 n elements are added
       T buf[10];
       initialize buf[0] .. buf[9];
       fifo_add (f, buf, 10);

    #3 1 element is added, pointer is returned
       T * x;
       fifo_add2 (f, x);
       x->a = 10;
       x->b = 20;

   Elements are removed 1 at a time:
       T x;
       fifo_sub1 (f, x);

   fifo_free (f) frees fifo.
*/

void *
_clib_fifo_resize (void *v_old, uword n_new_elts, uword elt_bytes)
{
  void *v_new, *end, *head;
  uword n_old_elts, header_bytes;
  uword n_copy_bytes, n_zero_bytes;
  clib_fifo_header_t *f_new, *f_old;

  n_old_elts = clib_fifo_elts (v_old);
  n_new_elts += n_old_elts;
  if (n_new_elts < 32)
    n_new_elts = 32;
  else
    n_new_elts = max_pow2 (n_new_elts);

  header_bytes = vec_header_bytes (sizeof (clib_fifo_header_t));

  v_new = clib_mem_alloc_no_fail (n_new_elts * elt_bytes + header_bytes);
  v_new += header_bytes;

  f_new = clib_fifo_header (v_new);
  f_new->head_index = 0;
  f_new->tail_index = n_old_elts;
  _vec_len (v_new) = n_new_elts;

  /* Copy old -> new. */
  n_copy_bytes = n_old_elts * elt_bytes;
  if (n_copy_bytes > 0)
    {
      f_old = clib_fifo_header (v_old);
      end = v_old + _vec_len (v_old) * elt_bytes;
      head = v_old + f_old->head_index * elt_bytes;

      if (head + n_copy_bytes >= end)
	{
	  uword n = end - head;
	  clib_memcpy (v_new, head, n);
	  clib_memcpy (v_new + n, v_old, n_copy_bytes - n);
	}
      else
	clib_memcpy (v_new, head, n_copy_bytes);
    }

  /* Zero empty space. */
  n_zero_bytes = (n_new_elts - n_old_elts) * elt_bytes;
  clib_memset (v_new + n_copy_bytes, 0, n_zero_bytes);

  clib_fifo_free (v_old);

  return v_new;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
