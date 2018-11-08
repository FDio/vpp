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

/* Turn data structures into byte streams for saving or transport. */

#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/serialize.h>

void
serialize_64 (serialize_main_t * m, va_list * va)
{
  u64 x = va_arg (*va, u64);
  u32 lo, hi;
  lo = x;
  hi = x >> 32;
  serialize_integer (m, lo, sizeof (lo));
  serialize_integer (m, hi, sizeof (hi));
}

void
serialize_32 (serialize_main_t * m, va_list * va)
{
  u32 x = va_arg (*va, u32);
  serialize_integer (m, x, sizeof (x));
}

void
serialize_16 (serialize_main_t * m, va_list * va)
{
  u32 x = va_arg (*va, u32);
  serialize_integer (m, x, sizeof (u16));
}

void
serialize_8 (serialize_main_t * m, va_list * va)
{
  u32 x = va_arg (*va, u32);
  serialize_integer (m, x, sizeof (u8));
}

void
unserialize_64 (serialize_main_t * m, va_list * va)
{
  u64 *x = va_arg (*va, u64 *);
  u32 lo, hi;
  unserialize_integer (m, &lo, sizeof (lo));
  unserialize_integer (m, &hi, sizeof (hi));
  *x = ((u64) hi << 32) | (u64) lo;
}

void
unserialize_32 (serialize_main_t * m, va_list * va)
{
  u32 *x = va_arg (*va, u32 *);
  unserialize_integer (m, x, sizeof (x[0]));
}

void
unserialize_16 (serialize_main_t * m, va_list * va)
{
  u16 *x = va_arg (*va, u16 *);
  u32 t;
  unserialize_integer (m, &t, sizeof (x[0]));
  x[0] = t;
}

void
unserialize_8 (serialize_main_t * m, va_list * va)
{
  u8 *x = va_arg (*va, u8 *);
  u32 t;
  unserialize_integer (m, &t, sizeof (x[0]));
  x[0] = t;
}

void
serialize_f64 (serialize_main_t * m, va_list * va)
{
  f64 x = va_arg (*va, f64);
  union
  {
    f64 f;
    u64 i;
  } y;
  y.f = x;
  serialize (m, serialize_64, y.i);
}

void
serialize_f32 (serialize_main_t * m, va_list * va)
{
  f32 x = va_arg (*va, f64);
  union
  {
    f32 f;
    u32 i;
  } y;
  y.f = x;
  serialize_integer (m, y.i, sizeof (y.i));
}

void
unserialize_f64 (serialize_main_t * m, va_list * va)
{
  f64 *x = va_arg (*va, f64 *);
  union
  {
    f64 f;
    u64 i;
  } y;
  unserialize (m, unserialize_64, &y.i);
  *x = y.f;
}

void
unserialize_f32 (serialize_main_t * m, va_list * va)
{
  f32 *x = va_arg (*va, f32 *);
  union
  {
    f32 f;
    u32 i;
  } y;
  unserialize_integer (m, &y.i, sizeof (y.i));
  *x = y.f;
}

void
serialize_cstring (serialize_main_t * m, char *s)
{
  u32 len = s ? strlen (s) : 0;
  void *p;

  serialize_likely_small_unsigned_integer (m, len);
  if (len > 0)
    {
      p = serialize_get (m, len);
      clib_memcpy (p, s, len);
    }
}

void
unserialize_cstring (serialize_main_t * m, char **s)
{
  char *p, *r = 0;
  u32 len;

  len = unserialize_likely_small_unsigned_integer (m);

  /*
   * Given broken enough data, we could get len = 0xFFFFFFFF.
   * Add one, it overflows, we call vec_new (char, 0), then
   * memcpy until we bus error.
   */
  if (len > 0 && len != 0xFFFFFFFF)
    {
      r = vec_new (char, len + 1);
      p = unserialize_get (m, len);
      clib_memcpy (r, p, len);

      /* Null terminate. */
      r[len] = 0;
    }
  *s = r;
}

/* vec_serialize/vec_unserialize helper functions for basic vector types. */
void
serialize_vec_8 (serialize_main_t * m, va_list * va)
{
  u8 *s = va_arg (*va, u8 *);
  u32 n = va_arg (*va, u32);
  u8 *p = serialize_get (m, n * sizeof (u8));
  clib_memcpy (p, s, n * sizeof (u8));
}

void
unserialize_vec_8 (serialize_main_t * m, va_list * va)
{
  u8 *s = va_arg (*va, u8 *);
  u32 n = va_arg (*va, u32);
  u8 *p = unserialize_get (m, n);
  clib_memcpy (s, p, n);
}

#define _(n_bits)							\
  void serialize_vec_##n_bits (serialize_main_t * m, va_list * va)	\
  {									\
    u##n_bits * s = va_arg (*va, u##n_bits *);				\
    u32 n = va_arg (*va, u32);						\
    u##n_bits * p = serialize_get (m, n * sizeof (s[0]));		\
									\
    while (n >= 4)							\
      {									\
	p[0] = clib_host_to_net_u##n_bits (s[0]);			\
	p[1] = clib_host_to_net_u##n_bits (s[1]);			\
	p[2] = clib_host_to_net_u##n_bits (s[2]);			\
	p[3] = clib_host_to_net_u##n_bits (s[3]);			\
	s += 4;								\
	p += 4;								\
	n -= 4;								\
      }									\
									\
    while (n >= 1)							\
      {									\
	p[0] = clib_host_to_net_u##n_bits (s[0]);			\
	s += 1;								\
	p += 1;								\
	n -= 1;								\
      }									\
  }									\
									\
  void unserialize_vec_##n_bits (serialize_main_t * m, va_list * va)	\
  {									\
    u##n_bits * s = va_arg (*va, u##n_bits *);				\
    u32 n = va_arg (*va, u32);						\
    u##n_bits * p = unserialize_get (m, n * sizeof (s[0]));		\
									\
    while (n >= 4)							\
      {									\
	s[0] = clib_net_to_host_mem_u##n_bits (&p[0]);			\
	s[1] = clib_net_to_host_mem_u##n_bits (&p[1]);			\
	s[2] = clib_net_to_host_mem_u##n_bits (&p[2]);			\
	s[3] = clib_net_to_host_mem_u##n_bits (&p[3]);			\
	s += 4;								\
	p += 4;								\
	n -= 4;								\
      }									\
									\
    while (n >= 1)							\
      {									\
	s[0] = clib_net_to_host_mem_u##n_bits (&p[0]);			\
	s += 1;								\
	p += 1;								\
	n -= 1;								\
      }									\
  }

_(16);
_(32);
_(64);

#undef _

#define SERIALIZE_VECTOR_CHUNK_SIZE 64

void
serialize_vector (serialize_main_t * m, va_list * va)
{
  void *vec = va_arg (*va, void *);
  u32 elt_bytes = va_arg (*va, u32);
  serialize_function_t *f = va_arg (*va, serialize_function_t *);
  u32 l = vec_len (vec);
  void *p = vec;

  serialize_integer (m, l, sizeof (l));

  /* Serialize vector in chunks for cache locality. */
  while (l != 0)
    {
      u32 n = clib_min (SERIALIZE_VECTOR_CHUNK_SIZE, l);
      serialize (m, f, p, n);
      l -= n;
      p += SERIALIZE_VECTOR_CHUNK_SIZE * elt_bytes;
    }
}

void *
unserialize_vector_ha (serialize_main_t * m,
		       u32 elt_bytes,
		       u32 header_bytes,
		       u32 align, u32 max_length, serialize_function_t * f)
{
  void *v, *p;
  u32 l;

  unserialize_integer (m, &l, sizeof (l));
  if (l > max_length)
    serialize_error (&m->header,
		     clib_error_create ("bad vector length %d", l));
  p = v = _vec_resize ((void *) 0, l, (uword) l * elt_bytes, header_bytes,
		       /* align */ align);

  while (l != 0)
    {
      u32 n = clib_min (SERIALIZE_VECTOR_CHUNK_SIZE, l);
      unserialize (m, f, p, n);
      l -= n;
      p += SERIALIZE_VECTOR_CHUNK_SIZE * elt_bytes;
    }
  return v;
}

void
unserialize_aligned_vector (serialize_main_t * m, va_list * va)
{
  void **vec = va_arg (*va, void **);
  u32 elt_bytes = va_arg (*va, u32);
  serialize_function_t *f = va_arg (*va, serialize_function_t *);
  u32 align = va_arg (*va, u32);

  *vec = unserialize_vector_ha (m, elt_bytes,
				/* header_bytes */ 0,
				/* align */ align,
				/* max_length */ ~0,
				f);
}

void
unserialize_vector (serialize_main_t * m, va_list * va)
{
  void **vec = va_arg (*va, void **);
  u32 elt_bytes = va_arg (*va, u32);
  serialize_function_t *f = va_arg (*va, serialize_function_t *);

  *vec = unserialize_vector_ha (m, elt_bytes,
				/* header_bytes */ 0,
				/* align */ 0,
				/* max_length */ ~0,
				f);
}

void
serialize_bitmap (serialize_main_t * m, uword * b)
{
  u32 l, i, n_u32s;

  l = vec_len (b);
  n_u32s = l * sizeof (b[0]) / sizeof (u32);
  serialize_integer (m, n_u32s, sizeof (n_u32s));

  /* Send 32 bit words, low-order word first on 64 bit. */
  for (i = 0; i < l; i++)
    {
      serialize_integer (m, b[i], sizeof (u32));
      if (BITS (uword) == 64)
	serialize_integer (m, (u64) b[i] >> (u64) 32, sizeof (u32));
    }
}

uword *
unserialize_bitmap (serialize_main_t * m)
{
  uword *b = 0;
  u32 i, n_u32s;

  unserialize_integer (m, &n_u32s, sizeof (n_u32s));
  if (n_u32s == 0)
    return b;

  i = (n_u32s * sizeof (u32) + sizeof (b[0]) - 1) / sizeof (b[0]);
  vec_resize (b, i);
  for (i = 0; i < n_u32s; i++)
    {
      u32 data;
      unserialize_integer (m, &data, sizeof (u32));

      /* Low-word is first on 64 bit. */
      if (BITS (uword) == 64)
	{
	  if ((i % 2) == 0)
	    b[i / 2] |= (u64) data << (u64) 0;
	  else
	    b[i / 2] |= (u64) data << (u64) 32;
	}
      else
	{
	  b[i] = data;
	}
    }

  return b;
}

void
serialize_pool (serialize_main_t * m, va_list * va)
{
  void *pool = va_arg (*va, void *);
  u32 elt_bytes = va_arg (*va, u32);
  serialize_function_t *f = va_arg (*va, serialize_function_t *);
  u32 l, lo, hi;
  pool_header_t *p;

  l = vec_len (pool);
  serialize_integer (m, l, sizeof (u32));
  if (l == 0)
    return;
  p = pool_header (pool);

  /* No need to send free bitmap.  Need to send index vector
     to guarantee that unserialized pool will be identical. */
  vec_serialize (m, p->free_indices, serialize_vec_32);

  pool_foreach_region (lo, hi, pool,
		       serialize (m, f, pool + lo * elt_bytes, hi - lo));
}

static void *
unserialize_pool_helper (serialize_main_t * m,
			 u32 elt_bytes, u32 align, serialize_function_t * f)
{
  void *v;
  u32 i, l, lo, hi;
  pool_header_t *p;

  unserialize_integer (m, &l, sizeof (l));
  if (l == 0)
    {
      return 0;
    }

  v = _vec_resize ((void *) 0, l, (uword) l * elt_bytes, sizeof (p[0]),
		   align);
  p = pool_header (v);

  vec_unserialize (m, &p->free_indices, unserialize_vec_32);

  /* Construct free bitmap. */
  p->free_bitmap = 0;
  for (i = 0; i < vec_len (p->free_indices); i++)
    p->free_bitmap = clib_bitmap_ori (p->free_bitmap, p->free_indices[i]);

  pool_foreach_region (lo, hi, v,
		       unserialize (m, f, v + lo * elt_bytes, hi - lo));

  return v;
}

void
unserialize_pool (serialize_main_t * m, va_list * va)
{
  void **result = va_arg (*va, void **);
  u32 elt_bytes = va_arg (*va, u32);
  serialize_function_t *f = va_arg (*va, serialize_function_t *);
  *result = unserialize_pool_helper (m, elt_bytes, /* align */ 0, f);
}

void
unserialize_aligned_pool (serialize_main_t * m, va_list * va)
{
  void **result = va_arg (*va, void **);
  u32 elt_bytes = va_arg (*va, u32);
  u32 align = va_arg (*va, u32);
  serialize_function_t *f = va_arg (*va, serialize_function_t *);
  *result = unserialize_pool_helper (m, elt_bytes, align, f);
}

static void
serialize_vec_heap_elt (serialize_main_t * m, va_list * va)
{
  heap_elt_t *e = va_arg (*va, heap_elt_t *);
  u32 i, n = va_arg (*va, u32);
  for (i = 0; i < n; i++)
    {
      serialize_integer (m, e[i].offset, sizeof (e[i].offset));
      serialize_integer (m, e[i].next, sizeof (e[i].next));
      serialize_integer (m, e[i].prev, sizeof (e[i].prev));
    }
}

static void
unserialize_vec_heap_elt (serialize_main_t * m, va_list * va)
{
  heap_elt_t *e = va_arg (*va, heap_elt_t *);
  u32 i, n = va_arg (*va, u32);
  for (i = 0; i < n; i++)
    {
      unserialize_integer (m, &e[i].offset, sizeof (e[i].offset));
      unserialize_integer (m, &e[i].next, sizeof (e[i].next));
      unserialize_integer (m, &e[i].prev, sizeof (e[i].prev));
    }
}

void
serialize_heap (serialize_main_t * m, va_list * va)
{
  void *heap = va_arg (*va, void *);
  serialize_function_t *f = va_arg (*va, serialize_function_t *);
  u32 i, l;
  heap_header_t *h;

  l = vec_len (heap);
  serialize_integer (m, l, sizeof (u32));
  if (l == 0)
    return;

  h = heap_header (heap);

#define foreach_serialize_heap_header_integer \
  _ (head) _ (tail) _ (used_count) _ (max_len) _ (flags) _ (elt_bytes)

#define _(f) serialize_integer (m, h->f, sizeof (h->f));
  foreach_serialize_heap_header_integer;
#undef _

  serialize_integer (m, vec_len (h->free_lists), sizeof (u32));
  for (i = 0; i < vec_len (h->free_lists); i++)
    vec_serialize (m, h->free_lists[i], serialize_vec_32);

  vec_serialize (m, h->elts, serialize_vec_heap_elt);
  vec_serialize (m, h->small_free_elt_free_index, serialize_vec_32);
  vec_serialize (m, h->free_elts, serialize_vec_32);

  /* Serialize data in heap. */
  {
    heap_elt_t *e, *end;
    e = h->elts + h->head;
    end = h->elts + h->tail;
    while (1)
      {
	if (!heap_is_free (e))
	  {
	    void *v = heap + heap_offset (e) * h->elt_bytes;
	    u32 n = heap_elt_size (heap, e);
	    serialize (m, f, v, n);
	  }
	if (e == end)
	  break;
	e = heap_next (e);
      }
  }
}

void
unserialize_heap (serialize_main_t * m, va_list * va)
{
  void **result = va_arg (*va, void **);
  serialize_function_t *f = va_arg (*va, serialize_function_t *);
  u32 i, vl, fl;
  heap_header_t h;
  void *heap;

  unserialize_integer (m, &vl, sizeof (u32));
  if (vl == 0)
    {
      *result = 0;
      return;
    }

  memset (&h, 0, sizeof (h));
#define _(f) unserialize_integer (m, &h.f, sizeof (h.f));
  foreach_serialize_heap_header_integer;
#undef _

  unserialize_integer (m, &fl, sizeof (u32));
  vec_resize (h.free_lists, fl);

  for (i = 0; i < vec_len (h.free_lists); i++)
    vec_unserialize (m, &h.free_lists[i], unserialize_vec_32);

  vec_unserialize (m, &h.elts, unserialize_vec_heap_elt);
  vec_unserialize (m, &h.small_free_elt_free_index, unserialize_vec_32);
  vec_unserialize (m, &h.free_elts, unserialize_vec_32);

  /* Re-construct used elt bitmap. */
  if (CLIB_DEBUG > 0)
    {
      heap_elt_t *e;
      vec_foreach (e, h.elts)
      {
	if (!heap_is_free (e))
	  h.used_elt_bitmap = clib_bitmap_ori (h.used_elt_bitmap, e - h.elts);
      }
    }

  heap = *result = _heap_new (vl, h.elt_bytes);
  heap_header (heap)[0] = h;

  /* Unserialize data in heap. */
  {
    heap_elt_t *e, *end;
    e = h.elts + h.head;
    end = h.elts + h.tail;
    while (1)
      {
	if (!heap_is_free (e))
	  {
	    void *v = heap + heap_offset (e) * h.elt_bytes;
	    u32 n = heap_elt_size (heap, e);
	    unserialize (m, f, v, n);
	  }
	if (e == end)
	  break;
	e = heap_next (e);
      }
  }
}

void
serialize_magic (serialize_main_t * m, void *magic, u32 magic_bytes)
{
  void *p;
  serialize_integer (m, magic_bytes, sizeof (magic_bytes));
  p = serialize_get (m, magic_bytes);
  clib_memcpy (p, magic, magic_bytes);
}

void
unserialize_check_magic (serialize_main_t * m, void *magic, u32 magic_bytes)
{
  u32 l;
  void *d;

  unserialize_integer (m, &l, sizeof (l));
  if (l != magic_bytes)
    {
    bad:
      serialize_error_return (m, "bad magic number");
    }
  d = serialize_get (m, magic_bytes);
  if (memcmp (magic, d, magic_bytes))
    goto bad;
}

clib_error_t *
va_serialize (serialize_main_t * sm, va_list * va)
{
  serialize_main_header_t *m = &sm->header;
  serialize_function_t *f = va_arg (*va, serialize_function_t *);
  clib_error_t *error = 0;

  m->recursion_level += 1;
  if (m->recursion_level == 1)
    {
      uword r = clib_setjmp (&m->error_longjmp, 0);
      error = uword_to_pointer (r, clib_error_t *);
    }

  if (!error)
    f (sm, va);

  m->recursion_level -= 1;
  return error;
}

clib_error_t *
serialize (serialize_main_t * m, ...)
{
  clib_error_t *error;
  va_list va;

  va_start (va, m);
  error = va_serialize (m, &va);
  va_end (va);
  return error;
}

clib_error_t *
unserialize (serialize_main_t * m, ...)
{
  clib_error_t *error;
  va_list va;

  va_start (va, m);
  error = va_serialize (m, &va);
  va_end (va);
  return error;
}

static void *
serialize_write_not_inline (serialize_main_header_t * m,
			    serialize_stream_t * s,
			    uword n_bytes_to_write, uword flags)
{
  uword cur_bi, n_left_b, n_left_o;

  ASSERT (s->current_buffer_index <= s->n_buffer_bytes);
  cur_bi = s->current_buffer_index;
  n_left_b = s->n_buffer_bytes - cur_bi;
  n_left_o = vec_len (s->overflow_buffer);

  /* Prepend overflow buffer if present. */
  do
    {
      if (n_left_o > 0 && n_left_b > 0)
	{
	  uword n = clib_min (n_left_b, n_left_o);
	  clib_memcpy (s->buffer + cur_bi, s->overflow_buffer, n);
	  cur_bi += n;
	  n_left_b -= n;
	  n_left_o -= n;
	  if (n_left_o == 0)
	    _vec_len (s->overflow_buffer) = 0;
	  else
	    vec_delete (s->overflow_buffer, n, 0);
	}

      /* Call data function when buffer is complete.  Data function should
         dispatch with current buffer and give us a new one to write more
         data into. */
      if (n_left_b == 0)
	{
	  s->current_buffer_index = cur_bi;
	  m->data_function (m, s);
	  cur_bi = s->current_buffer_index;
	  n_left_b = s->n_buffer_bytes - cur_bi;
	}
    }
  while (n_left_o > 0);

  if (n_left_o > 0 || n_left_b < n_bytes_to_write)
    {
      u8 *r;
      vec_add2 (s->overflow_buffer, r, n_bytes_to_write);
      return r;
    }
  else
    {
      s->current_buffer_index = cur_bi + n_bytes_to_write;
      return s->buffer + cur_bi;
    }
}

static void *
serialize_read_not_inline (serialize_main_header_t * m,
			   serialize_stream_t * s,
			   uword n_bytes_to_read, uword flags)
{
  uword cur_bi, cur_oi, n_left_b, n_left_o, n_left_to_read;

  ASSERT (s->current_buffer_index <= s->n_buffer_bytes);

  cur_bi = s->current_buffer_index;
  cur_oi = s->current_overflow_index;

  n_left_b = s->n_buffer_bytes - cur_bi;
  n_left_o = vec_len (s->overflow_buffer) - cur_oi;

  /* Read from overflow? */
  if (n_left_o >= n_bytes_to_read)
    {
      s->current_overflow_index = cur_oi + n_bytes_to_read;
      return vec_elt_at_index (s->overflow_buffer, cur_oi);
    }

  /* Reset overflow buffer. */
  if (n_left_o == 0 && s->overflow_buffer)
    {
      s->current_overflow_index = 0;
      _vec_len (s->overflow_buffer) = 0;
    }

  n_left_to_read = n_bytes_to_read;
  while (n_left_to_read > 0)
    {
      uword n;

      /* If we don't have enough data between overflow and normal buffer
         call read function. */
      if (n_left_o + n_left_b < n_bytes_to_read)
	{
	  /* Save any left over buffer in overflow vector. */
	  if (n_left_b > 0)
	    {
	      vec_add (s->overflow_buffer, s->buffer + cur_bi, n_left_b);
	      n_left_o += n_left_b;
	      n_left_to_read -= n_left_b;
	      /* Advance buffer to end --- even if
	         SERIALIZE_FLAG_NO_ADVANCE_CURRENT_BUFFER_INDEX is set. */
	      cur_bi = s->n_buffer_bytes;
	      n_left_b = 0;
	    }

	  if (m->data_function)
	    {
	      m->data_function (m, s);
	      cur_bi = s->current_buffer_index;
	      n_left_b = s->n_buffer_bytes - cur_bi;
	    }
	}

      /* For first time through loop return if we have enough data
         in normal buffer and overflow vector is empty. */
      if (n_left_o == 0
	  && n_left_to_read == n_bytes_to_read && n_left_b >= n_left_to_read)
	{
	  s->current_buffer_index = cur_bi + n_bytes_to_read;
	  return s->buffer + cur_bi;
	}

      if (!m->data_function || serialize_stream_is_end_of_stream (s))
	{
	  /* This can happen for a peek at end of file.
	     Pad overflow buffer with 0s. */
	  vec_resize (s->overflow_buffer, n_left_to_read);
	  n_left_o += n_left_to_read;
	  n_left_to_read = 0;
	}
      else
	{
	  /* Copy from buffer to overflow vector. */
	  n = clib_min (n_left_to_read, n_left_b);
	  vec_add (s->overflow_buffer, s->buffer + cur_bi, n);
	  cur_bi += n;
	  n_left_b -= n;
	  n_left_o += n;
	  n_left_to_read -= n;
	}
    }

  s->current_buffer_index = cur_bi;
  s->current_overflow_index = cur_oi + n_bytes_to_read;
  return vec_elt_at_index (s->overflow_buffer, cur_oi);
}

void *
serialize_read_write_not_inline (serialize_main_header_t * m,
				 serialize_stream_t * s,
				 uword n_bytes, uword flags)
{
  return (((flags & SERIALIZE_FLAG_IS_READ) ? serialize_read_not_inline :
	   serialize_write_not_inline) (m, s, n_bytes, flags));
}

static void
serialize_read_write_close (serialize_main_header_t * m,
			    serialize_stream_t * s, uword flags)
{
  if (serialize_stream_is_end_of_stream (s))
    return;

  if (flags & SERIALIZE_FLAG_IS_WRITE)
    /* "Write" 0 bytes to flush overflow vector. */
    serialize_write_not_inline (m, s, /* n bytes */ 0, flags);

  serialize_stream_set_end_of_stream (s);

  /* Call it one last time to flush buffer and close. */
  m->data_function (m, s);

  vec_free (s->overflow_buffer);
}

void
serialize_close (serialize_main_t * m)
{
  serialize_read_write_close (&m->header, &m->stream,
			      SERIALIZE_FLAG_IS_WRITE);
}

void
unserialize_close (serialize_main_t * m)
{
  serialize_read_write_close (&m->header, &m->stream, SERIALIZE_FLAG_IS_READ);
}

void
serialize_open_data (serialize_main_t * m, u8 * data, uword n_data_bytes)
{
  memset (m, 0, sizeof (m[0]));
  m->stream.buffer = data;
  m->stream.n_buffer_bytes = n_data_bytes;
}

void
unserialize_open_data (serialize_main_t * m, u8 * data, uword n_data_bytes)
{
  serialize_open_data (m, data, n_data_bytes);
}

static void
serialize_vector_write (serialize_main_header_t * m, serialize_stream_t * s)
{
  if (!serialize_stream_is_end_of_stream (s))
    {
      /* Double buffer size. */
      uword l = vec_len (s->buffer);
      vec_resize (s->buffer, l > 0 ? l : 64);
      s->n_buffer_bytes = vec_len (s->buffer);
    }
}

void
serialize_open_vector (serialize_main_t * m, u8 * vector)
{
  memset (m, 0, sizeof (m[0]));
  m->header.data_function = serialize_vector_write;
  m->stream.buffer = vector;
  m->stream.current_buffer_index = 0;
  m->stream.n_buffer_bytes = vec_len (vector);
}

void *
serialize_close_vector (serialize_main_t * m)
{
  serialize_stream_t *s = &m->stream;
  void *result;

  serialize_close (m);		/* frees overflow buffer */

  if (s->buffer)
    _vec_len (s->buffer) = s->current_buffer_index;
  result = s->buffer;
  memset (m, 0, sizeof (m[0]));
  return result;
}

void
serialize_multiple_1 (serialize_main_t * m,
		      void *data, uword data_stride, uword n_data)
{
  u8 *d = data;
  u8 *p;
  uword n_left = n_data;

  while (n_left >= 4)
    {
      p = serialize_get (m, 4 * sizeof (d[0]));
      p[0] = d[0 * data_stride];
      p[1] = d[1 * data_stride];
      p[2] = d[2 * data_stride];
      p[3] = d[3 * data_stride];
      n_left -= 4;
      d += 4 * data_stride;
    }

  if (n_left > 0)
    {
      p = serialize_get (m, n_left * sizeof (p[0]));
      while (n_left > 0)
	{
	  p[0] = d[0];
	  p += 1;
	  d += 1 * data_stride;
	  n_left -= 1;
	}
    }
}

void
serialize_multiple_2 (serialize_main_t * m,
		      void *data, uword data_stride, uword n_data)
{
  void *d = data;
  u16 *p;
  uword n_left = n_data;

  while (n_left >= 4)
    {
      p = serialize_get (m, 4 * sizeof (p[0]));
      clib_mem_unaligned (p + 0, u16) =
	clib_host_to_net_mem_u16 (d + 0 * data_stride);
      clib_mem_unaligned (p + 1, u16) =
	clib_host_to_net_mem_u16 (d + 1 * data_stride);
      clib_mem_unaligned (p + 2, u16) =
	clib_host_to_net_mem_u16 (d + 2 * data_stride);
      clib_mem_unaligned (p + 3, u16) =
	clib_host_to_net_mem_u16 (d + 3 * data_stride);
      n_left -= 4;
      d += 4 * data_stride;
    }

  if (n_left > 0)
    {
      p = serialize_get (m, n_left * sizeof (p[0]));
      while (n_left > 0)
	{
	  clib_mem_unaligned (p + 0, u16) =
	    clib_host_to_net_mem_u16 (d + 0 * data_stride);
	  p += 1;
	  d += 1 * data_stride;
	  n_left -= 1;
	}
    }
}

void
serialize_multiple_4 (serialize_main_t * m,
		      void *data, uword data_stride, uword n_data)
{
  void *d = data;
  u32 *p;
  uword n_left = n_data;

  while (n_left >= 4)
    {
      p = serialize_get (m, 4 * sizeof (p[0]));
      clib_mem_unaligned (p + 0, u32) =
	clib_host_to_net_mem_u32 (d + 0 * data_stride);
      clib_mem_unaligned (p + 1, u32) =
	clib_host_to_net_mem_u32 (d + 1 * data_stride);
      clib_mem_unaligned (p + 2, u32) =
	clib_host_to_net_mem_u32 (d + 2 * data_stride);
      clib_mem_unaligned (p + 3, u32) =
	clib_host_to_net_mem_u32 (d + 3 * data_stride);
      n_left -= 4;
      d += 4 * data_stride;
    }

  if (n_left > 0)
    {
      p = serialize_get (m, n_left * sizeof (p[0]));
      while (n_left > 0)
	{
	  clib_mem_unaligned (p + 0, u32) =
	    clib_host_to_net_mem_u32 (d + 0 * data_stride);
	  p += 1;
	  d += 1 * data_stride;
	  n_left -= 1;
	}
    }
}

void
unserialize_multiple_1 (serialize_main_t * m,
			void *data, uword data_stride, uword n_data)
{
  u8 *d = data;
  u8 *p;
  uword n_left = n_data;

  while (n_left >= 4)
    {
      p = unserialize_get (m, 4 * sizeof (d[0]));
      d[0 * data_stride] = p[0];
      d[1 * data_stride] = p[1];
      d[2 * data_stride] = p[2];
      d[3 * data_stride] = p[3];
      n_left -= 4;
      d += 4 * data_stride;
    }

  if (n_left > 0)
    {
      p = unserialize_get (m, n_left * sizeof (p[0]));
      while (n_left > 0)
	{
	  d[0] = p[0];
	  p += 1;
	  d += 1 * data_stride;
	  n_left -= 1;
	}
    }
}

void
unserialize_multiple_2 (serialize_main_t * m,
			void *data, uword data_stride, uword n_data)
{
  void *d = data;
  u16 *p;
  uword n_left = n_data;

  while (n_left >= 4)
    {
      p = unserialize_get (m, 4 * sizeof (p[0]));
      clib_mem_unaligned (d + 0 * data_stride, u16) =
	clib_net_to_host_mem_u16 (p + 0);
      clib_mem_unaligned (d + 1 * data_stride, u16) =
	clib_net_to_host_mem_u16 (p + 1);
      clib_mem_unaligned (d + 2 * data_stride, u16) =
	clib_net_to_host_mem_u16 (p + 2);
      clib_mem_unaligned (d + 3 * data_stride, u16) =
	clib_net_to_host_mem_u16 (p + 3);
      n_left -= 4;
      d += 4 * data_stride;
    }

  if (n_left > 0)
    {
      p = unserialize_get (m, n_left * sizeof (p[0]));
      while (n_left > 0)
	{
	  clib_mem_unaligned (d + 0 * data_stride, u16) =
	    clib_net_to_host_mem_u16 (p + 0);
	  p += 1;
	  d += 1 * data_stride;
	  n_left -= 1;
	}
    }
}

void
unserialize_multiple_4 (serialize_main_t * m,
			void *data, uword data_stride, uword n_data)
{
  void *d = data;
  u32 *p;
  uword n_left = n_data;

  while (n_left >= 4)
    {
      p = unserialize_get (m, 4 * sizeof (p[0]));
      clib_mem_unaligned (d + 0 * data_stride, u32) =
	clib_net_to_host_mem_u32 (p + 0);
      clib_mem_unaligned (d + 1 * data_stride, u32) =
	clib_net_to_host_mem_u32 (p + 1);
      clib_mem_unaligned (d + 2 * data_stride, u32) =
	clib_net_to_host_mem_u32 (p + 2);
      clib_mem_unaligned (d + 3 * data_stride, u32) =
	clib_net_to_host_mem_u32 (p + 3);
      n_left -= 4;
      d += 4 * data_stride;
    }

  if (n_left > 0)
    {
      p = unserialize_get (m, n_left * sizeof (p[0]));
      while (n_left > 0)
	{
	  clib_mem_unaligned (d + 0 * data_stride, u32) =
	    clib_net_to_host_mem_u32 (p + 0);
	  p += 1;
	  d += 1 * data_stride;
	  n_left -= 1;
	}
    }
}

#ifdef CLIB_UNIX

#include <unistd.h>
#include <fcntl.h>

static void
clib_file_write (serialize_main_header_t * m, serialize_stream_t * s)
{
  int fd, n;

  fd = s->data_function_opaque;
  n = write (fd, s->buffer, s->current_buffer_index);
  if (n < 0)
    {
      if (!unix_error_is_fatal (errno))
	n = 0;
      else
	serialize_error (m, clib_error_return_unix (0, "write"));
    }
  if (n == s->current_buffer_index)
    _vec_len (s->buffer) = 0;
  else
    vec_delete (s->buffer, n, 0);
  s->current_buffer_index = vec_len (s->buffer);
}

static void
clib_file_read (serialize_main_header_t * m, serialize_stream_t * s)
{
  int fd, n;

  fd = s->data_function_opaque;
  n = read (fd, s->buffer, vec_len (s->buffer));
  if (n < 0)
    {
      if (!unix_error_is_fatal (errno))
	n = 0;
      else
	serialize_error (m, clib_error_return_unix (0, "read"));
    }
  else if (n == 0)
    serialize_stream_set_end_of_stream (s);
  s->current_buffer_index = 0;
  s->n_buffer_bytes = n;
}

static void
serialize_open_clib_file_descriptor_helper (serialize_main_t * m, int fd,
					    uword is_read)
{
  memset (m, 0, sizeof (m[0]));
  vec_resize (m->stream.buffer, 4096);

  if (!is_read)
    {
      m->stream.n_buffer_bytes = vec_len (m->stream.buffer);
      _vec_len (m->stream.buffer) = 0;
    }

  m->header.data_function = is_read ? clib_file_read : clib_file_write;
  m->stream.data_function_opaque = fd;
}

void
serialize_open_clib_file_descriptor (serialize_main_t * m, int fd)
{
  serialize_open_clib_file_descriptor_helper (m, fd, /* is_read */ 0);
}

void
unserialize_open_clib_file_descriptor (serialize_main_t * m, int fd)
{
  serialize_open_clib_file_descriptor_helper (m, fd, /* is_read */ 1);
}

static clib_error_t *
serialize_open_clib_file_helper (serialize_main_t * m, char *file,
				 uword is_read)
{
  int fd, mode;

  mode = is_read ? O_RDONLY : O_RDWR | O_CREAT | O_TRUNC;
  fd = open (file, mode, 0666);
  if (fd < 0)
    return clib_error_return_unix (0, "open `%s'", file);

  serialize_open_clib_file_descriptor_helper (m, fd, is_read);
  return 0;
}

clib_error_t *
serialize_open_clib_file (serialize_main_t * m, char *file)
{
  return serialize_open_clib_file_helper (m, file, /* is_read */ 0);
}

clib_error_t *
unserialize_open_clib_file (serialize_main_t * m, char *file)
{
  return serialize_open_clib_file_helper (m, file, /* is_read */ 1);
}

#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
