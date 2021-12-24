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
  Copyright (c) 2005 Eliot Dresselhaus

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

#ifndef included_fifo_h
#define included_fifo_h

#include <vppinfra/cache.h>
#include <vppinfra/error.h>	/* for ASSERT */
#include <vppinfra/vec.h>

typedef struct
{
  /* First index of valid data in fifo. */
  u32 head_index;

  /* One beyond last index in fifo. */
  u32 tail_index;
} clib_fifo_header_t;

always_inline clib_fifo_header_t *
clib_fifo_header (void *f)
{
  return vec_header (f, sizeof (clib_fifo_header_t));
}

/* Aliases. */
#define clib_fifo_len(v) vec_len(v)
#define _clib_fifo_len(v) _vec_len(v)
#define clib_fifo_end(v) vec_end(v)

always_inline uword
clib_fifo_elts (void *v)
{
  word l, r;
  clib_fifo_header_t *f;

  if (!v)
    return 0;

  f = clib_fifo_header (v);
  l = _clib_fifo_len (v);
  r = (word) f->tail_index - (word) f->head_index;
  r = r < 0 ? r + l : r;
  ASSERT (r >= 0 && r <= l);
  return r;
}

always_inline uword
clib_fifo_free_elts (void *v)
{
  return clib_fifo_len (v) - clib_fifo_elts (v);
}

always_inline void
clib_fifo_reset (void *v)
{
  clib_fifo_header_t *f = clib_fifo_header (v);
  if (v)
    {
      f->head_index = f->tail_index = 0;
      _vec_len (v) = 0;
    }
}

/* External resize function. */
void *_clib_fifo_resize (void *v, uword n_elts, uword elt_bytes);

#define clib_fifo_resize(f,n_elts) \
  f = _clib_fifo_resize ((f), (n_elts), sizeof ((f)[0]))

always_inline void *
_clib_fifo_validate (void *v, uword n_elts, uword elt_bytes)
{
  if (clib_fifo_free_elts (v) < n_elts)
    v = _clib_fifo_resize (v, n_elts, elt_bytes);
  return v;
}

#define clib_fifo_validate(f,n_elts) \
  f = _clib_fifo_validate ((f), (n_elts), sizeof (f[0]))

/* Advance tail pointer by N_ELTS which can be either positive or negative. */
always_inline void *
_clib_fifo_advance_tail (void *v, word n_elts, uword elt_bytes,
			 uword * tail_return)
{
  word i, l, n_free;
  clib_fifo_header_t *f;

  n_free = clib_fifo_free_elts (v);
  if (n_free < n_elts)
    {
      v = _clib_fifo_resize (v, n_elts, elt_bytes);
      n_free = clib_fifo_free_elts (v);
    }

  ASSERT (n_free >= n_elts);
  n_free -= n_elts;

  f = clib_fifo_header (v);
  l = _clib_fifo_len (v);
  i = f->tail_index;

  if (n_free == 0)
    {
      /* Mark fifo full. */
      f->tail_index = f->head_index + l;
    }
  else
    {
      word n = f->tail_index + n_elts;
      if (n >= l)
	n -= l;
      else if (n < 0)
	n += l;
      ASSERT (n >= 0 && n < l);
      f->tail_index = n;
    }

  ASSERT (clib_fifo_free_elts (v) == n_free);

  if (tail_return)
    *tail_return = n_elts > 0 ? i : f->tail_index;

  return v;
}

#define clib_fifo_advance_tail(f,n_elts)				\
({									\
  uword _i;								\
  (f) = _clib_fifo_advance_tail ((f), (n_elts), sizeof ((f)[0]), &_i);	\
  (f) + _i;								\
})

always_inline uword
clib_fifo_advance_head (void *v, uword n_elts)
{
  clib_fifo_header_t *f;
  uword l, i, n;

  ASSERT (clib_fifo_elts (v) >= n_elts);
  f = clib_fifo_header (v);
  l = _clib_fifo_len (v);

  /* If fifo was full, restore tail pointer. */
  if (f->tail_index == f->head_index + l)
    f->tail_index = f->head_index;

  n = i = f->head_index;
  n += n_elts;
  n = n >= l ? n - l : n;
  ASSERT (n < l);
  f->head_index = n;

  return i;
}

/* Add given element to fifo. */
#define clib_fifo_add1(f,e)					\
do {								\
  uword _i;							\
  (f) = _clib_fifo_advance_tail ((f), 1, sizeof ((f)[0]), &_i);	\
  (f)[_i] = (e);						\
} while (0)

/* Add element to fifo; return pointer to new element. */
#define clib_fifo_add2(f,p)					\
do {								\
  uword _i;							\
  (f) = _clib_fifo_advance_tail ((f), 1, sizeof ((f)[0]), &_i);	\
  (p) = (f) + _i;						\
} while (0)

/* Add several elements to fifo. */
#define clib_fifo_add(f,e,n)						\
do {									\
  uword _i, _l; word _n0, _n1;						\
									\
  _n0 = (n);								\
  (f) = _clib_fifo_advance_tail ((f), _n0, sizeof ((f)[0]), &_i);	\
  _l = clib_fifo_len (f);						\
  _n1 = _i + _n0 - _l;							\
  _n1 = _n1 < 0 ? 0 : _n1;						\
  _n0 -= _n1;								\
  clib_memcpy_fast ((f) + _i, (e), _n0 * sizeof ((f)[0]));		\
  if (_n1)								\
    clib_memcpy_fast ((f) + 0, (e) + _n0, _n1 * sizeof ((f)[0]));	\
} while (0)

/* Subtract element from fifo. */
#define clib_fifo_sub1(f,e)			\
do {						\
  uword _i;					\
  ASSERT (clib_fifo_elts (f) >= 1);		\
  _i = clib_fifo_advance_head ((f), 1);		\
  (e) = (f)[_i];				\
} while (0)

#define clib_fifo_sub2(f,p)			\
do {						\
  uword _i;					\
  ASSERT (clib_fifo_elts (f) >= 1);		\
  _i = clib_fifo_advance_head ((f), 1);		\
  (p) = (f) + _i;				\
} while (0)

always_inline uword
clib_fifo_head_index (void *v)
{
  clib_fifo_header_t *f = clib_fifo_header (v);
  return v ? f->head_index : 0;
}

always_inline uword
clib_fifo_tail_index (void *v)
{
  clib_fifo_header_t *f = clib_fifo_header (v);
  return v ? f->tail_index : 0;
}

#define clib_fifo_head(v) ((v) + clib_fifo_head_index (v))
#define clib_fifo_tail(v) ((v) + clib_fifo_tail_index (v))

#define clib_fifo_free(f) vec_free_h((f),sizeof(clib_fifo_header_t))

always_inline uword
clib_fifo_elt_index (void *v, uword i)
{
  clib_fifo_header_t *f = clib_fifo_header (v);
  uword result = 0;

  ASSERT (i < clib_fifo_elts (v));

  if (v)
    {
      result = f->head_index + i;
      if (result >= _vec_len (v))
	result -= _vec_len (v);
    }

  return result;
}

#define clib_fifo_elt_at_index(v, i) ((v) + (i))

#define clib_fifo_foreach(v,f,body)		\
do {						\
  uword _i, _l, _n;				\
						\
  _i = clib_fifo_head_index (f);		\
  _l = clib_fifo_len (f);			\
  _n = clib_fifo_elts (f);			\
  while (_n > 0)				\
    {						\
      (v) = (f) + _i;				\
      do { body; } while (0);			\
      _n--;					\
      _i++;					\
      _i = _i >= _l ? 0 : _i;			\
    }						\
} while (0)

#endif /* included_fifo_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
