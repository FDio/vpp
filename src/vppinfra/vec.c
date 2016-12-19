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

#include <vppinfra/vec.h>
#include <vppinfra/mem.h>

/* Vector resize operator.  Called as needed by various macros such as
   vec_add1() when we need to allocate memory. */
void *
vec_resize_allocate_memory (void *v,
			    word length_increment,
			    uword data_bytes,
			    uword header_bytes, uword data_align)
{
  vec_header_t *vh = _vec_find (v);
  uword old_alloc_bytes, new_alloc_bytes;
  void *old, *new;

  header_bytes = vec_header_bytes (header_bytes);

  data_bytes += header_bytes;

  if (!v)
    {
      new = clib_mem_alloc_aligned_at_offset (data_bytes, data_align, header_bytes, 1	/* yes, call os_out_of_memory */
	);
      data_bytes = clib_mem_size (new);
      memset (new, 0, data_bytes);
      v = new + header_bytes;
      _vec_len (v) = length_increment;
      return v;
    }

  vh->len += length_increment;
  old = v - header_bytes;

  /* Vector header must start heap object. */
  ASSERT (clib_mem_is_heap_object (old));

  old_alloc_bytes = clib_mem_size (old);

  /* Need to resize? */
  if (data_bytes <= old_alloc_bytes)
    return v;

  new_alloc_bytes = (old_alloc_bytes * 3) / 2;
  if (new_alloc_bytes < data_bytes)
    new_alloc_bytes = data_bytes;

  new =
    clib_mem_alloc_aligned_at_offset (new_alloc_bytes, data_align,
				      header_bytes,
				      1 /* yes, call os_out_of_memory */ );

  /* FIXME fail gracefully. */
  if (!new)
    clib_panic
      ("vec_resize fails, length increment %d, data bytes %d, alignment %d",
       length_increment, data_bytes, data_align);

  clib_memcpy (new, old, old_alloc_bytes);
  clib_mem_free (old);
  v = new;

  /* Allocator may give a bit of extra room. */
  new_alloc_bytes = clib_mem_size (v);

  /* Zero new memory. */
  memset (v + old_alloc_bytes, 0, new_alloc_bytes - old_alloc_bytes);

  return v + header_bytes;
}

uword
clib_mem_is_vec_h (void *v, uword header_bytes)
{
  return clib_mem_is_heap_object (vec_header (v, header_bytes));
}

/** \cond */

#ifdef TEST

#include <stdio.h>

void
main (int argc, char *argv[])
{
  word n = atoi (argv[1]);
  word i, *x = 0;

  typedef struct
  {
    word x, y, z;
  } FOO;

  FOO *foos = vec_init (FOO, 10), *f;

  vec_validate (foos, 100);
  foos[100].x = 99;

  _vec_len (foos) = 0;
  for (i = 0; i < n; i++)
    {
      vec_add1 (x, i);
      vec_add2 (foos, f, 1);
      f->x = 2 * i;
      f->y = 3 * i;
      f->z = 4 * i;
    }

  {
    word n = 2;
    word m = 42;
    vec_delete (foos, n, m);
  }

  {
    word n = 2;
    word m = 42;
    vec_insert (foos, n, m);
  }

  vec_free (x);
  vec_free (foos);
  exit (0);
}
#endif
/** \endcond */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
