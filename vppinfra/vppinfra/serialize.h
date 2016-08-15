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

#ifndef included_clib_serialize_h
#define included_clib_serialize_h

#include <stdarg.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/longjmp.h>

struct serialize_main_header_t;
struct serialize_stream_t;

typedef void (serialize_data_function_t) (struct serialize_main_header_t * h,
					  struct serialize_stream_t * s);

typedef struct serialize_stream_t
{
  /* Current data buffer being serialized/unserialized. */
  u8 *buffer;

  /* Size of buffer in bytes. */
  u32 n_buffer_bytes;

  /* Current index into buffer. */
  u32 current_buffer_index;

  /* Overflow buffer for when there is not enough room at the end of
     buffer to hold serialized/unserialized data. */
  u8 *overflow_buffer;

  /* Current index in overflow buffer for reads. */
  u32 current_overflow_index;

  u32 flags;
#define SERIALIZE_END_OF_STREAM (1 << 0)

  uword data_function_opaque;

  u32 opaque[64 - 4 * sizeof (u32) - 1 * sizeof (uword) -
	     2 * sizeof (void *)];
} serialize_stream_t;

always_inline void
serialize_stream_set_end_of_stream (serialize_stream_t * s)
{
  s->flags |= SERIALIZE_END_OF_STREAM;
}

always_inline uword
serialize_stream_is_end_of_stream (serialize_stream_t * s)
{
  return (s->flags & SERIALIZE_END_OF_STREAM) != 0;
}

typedef struct serialize_main_header_t
{
  u32 recursion_level;

  /* Data callback function and opaque data. */
  serialize_data_function_t *data_function;

  /* Error if signaled by data function. */
  clib_error_t *error;

  /* Exit unwind point if error occurs. */
  clib_longjmp_t error_longjmp;
} serialize_main_header_t;

always_inline void
serialize_error (serialize_main_header_t * m, clib_error_t * error)
{
  clib_longjmp (&m->error_longjmp, pointer_to_uword (error));
}

#define serialize_error_return(m,args...)			\
  serialize_error (&(m)->header, clib_error_return (0, args))

void *serialize_read_write_not_inline (serialize_main_header_t * m,
				       serialize_stream_t * s,
				       uword n_bytes, uword flags);

#define SERIALIZE_FLAG_IS_READ  (1 << 0)
#define SERIALIZE_FLAG_IS_WRITE (1 << 1)

always_inline void *
serialize_stream_read_write (serialize_main_header_t * header,
			     serialize_stream_t * s,
			     uword n_bytes, uword flags)
{
  uword i, j, l;

  l = vec_len (s->overflow_buffer);
  i = s->current_buffer_index;
  j = i + n_bytes;
  s->current_buffer_index = j;
  if (l == 0 && j <= s->n_buffer_bytes)
    {
      return s->buffer + i;
    }
  else
    {
      s->current_buffer_index = i;
      return serialize_read_write_not_inline (header, s, n_bytes, flags);
    }
}

typedef struct
{
  serialize_main_header_t header;
  serialize_stream_t stream;
} serialize_main_t;

always_inline void
serialize_set_end_of_stream (serialize_main_t * m)
{
  serialize_stream_set_end_of_stream (&m->stream);
}

always_inline uword
serialize_is_end_of_stream (serialize_main_t * m)
{
  return serialize_stream_is_end_of_stream (&m->stream);
}

typedef struct
{
  serialize_main_header_t header;
  serialize_stream_t *streams;
} serialize_multiple_main_t;

typedef void (serialize_function_t) (serialize_main_t * m, va_list * va);

always_inline void *
unserialize_get (serialize_main_t * m, uword n_bytes)
{
  return serialize_stream_read_write (&m->header, &m->stream, n_bytes,
				      SERIALIZE_FLAG_IS_READ);
}

always_inline void *
serialize_get (serialize_main_t * m, uword n_bytes)
{
  return serialize_stream_read_write (&m->header, &m->stream, n_bytes,
				      SERIALIZE_FLAG_IS_WRITE);
}

always_inline void
serialize_integer (serialize_main_t * m, u64 x, u32 n_bytes)
{
  u8 *p = serialize_get (m, n_bytes);
  if (n_bytes == 1)
    p[0] = x;
  else if (n_bytes == 2)
    clib_mem_unaligned (p, u16) = clib_host_to_net_u16 (x);
  else if (n_bytes == 4)
    clib_mem_unaligned (p, u32) = clib_host_to_net_u32 (x);
  else if (n_bytes == 8)
    clib_mem_unaligned (p, u64) = clib_host_to_net_u64 (x);
  else
    ASSERT (0);
}

always_inline void
unserialize_integer (serialize_main_t * m, void *x, u32 n_bytes)
{
  u8 *p = unserialize_get (m, n_bytes);
  if (n_bytes == 1)
    *(u8 *) x = p[0];
  else if (n_bytes == 2)
    *(u16 *) x = clib_net_to_host_unaligned_mem_u16 ((u16 *) p);
  else if (n_bytes == 4)
    *(u32 *) x = clib_net_to_host_unaligned_mem_u32 ((u32 *) p);
  else if (n_bytes == 8)
    *(u64 *) x = clib_net_to_host_unaligned_mem_u64 ((u64 *) p);
  else
    ASSERT (0);
}

/* As above but tries to be more compact. */
always_inline void
serialize_likely_small_unsigned_integer (serialize_main_t * m, u64 x)
{
  u64 r = x;
  u8 *p;

  /* Low bit set means it fits into 1 byte. */
  if (r < (1 << 7))
    {
      p = serialize_get (m, 1);
      p[0] = 1 + 2 * r;
      return;
    }

  /* Low 2 bits 1 0 means it fits into 2 bytes. */
  r -= (1 << 7);
  if (r < (1 << 14))
    {
      p = serialize_get (m, 2);
      clib_mem_unaligned (p, u16) = clib_host_to_little_u16 (4 * r + 2);
      return;
    }

  r -= (1 << 14);
  if (r < (1 << 29))
    {
      p = serialize_get (m, 4);
      clib_mem_unaligned (p, u32) = clib_host_to_little_u32 (8 * r + 4);
      return;
    }

  p = serialize_get (m, 9);
  p[0] = 0;			/* Only low 3 bits are used. */
  clib_mem_unaligned (p + 1, u64) = clib_host_to_little_u64 (x);
}

always_inline u64
unserialize_likely_small_unsigned_integer (serialize_main_t * m)
{
  u8 *p = unserialize_get (m, 1);
  u64 r;
  u32 y = p[0];

  if (y & 1)
    return y / 2;

  r = 1 << 7;
  if (y & 2)
    {
      p = unserialize_get (m, 1);
      r += (y / 4) + (p[0] << 6);
      return r;
    }

  r += 1 << 14;
  if (y & 4)
    {
      p = unserialize_get (m, 3);
      r += ((y / 8)
	    + (p[0] << (5 + 8 * 0))
	    + (p[1] << (5 + 8 * 1)) + (p[2] << (5 + 8 * 2)));
      return r;
    }

  p = unserialize_get (m, 8);
  r = clib_mem_unaligned (p, u64);
  r = clib_little_to_host_u64 (r);

  return r;
}

always_inline void
serialize_likely_small_signed_integer (serialize_main_t * m, i64 s)
{
  u64 u = s < 0 ? -(2 * s + 1) : 2 * s;
  serialize_likely_small_unsigned_integer (m, u);
}

always_inline i64
unserialize_likely_small_signed_integer (serialize_main_t * m)
{
  u64 u = unserialize_likely_small_unsigned_integer (m);
  i64 s = u / 2;
  return (u & 1) ? -s : s;
}

void
serialize_multiple_1 (serialize_main_t * m,
		      void *data, uword data_stride, uword n_data);
void
serialize_multiple_2 (serialize_main_t * m,
		      void *data, uword data_stride, uword n_data);
void
serialize_multiple_4 (serialize_main_t * m,
		      void *data, uword data_stride, uword n_data);

void
unserialize_multiple_1 (serialize_main_t * m,
			void *data, uword data_stride, uword n_data);
void
unserialize_multiple_2 (serialize_main_t * m,
			void *data, uword data_stride, uword n_data);
void
unserialize_multiple_4 (serialize_main_t * m,
			void *data, uword data_stride, uword n_data);

always_inline void
serialize_multiple (serialize_main_t * m,
		    void *data,
		    uword n_data_bytes, uword data_stride, uword n_data)
{
  if (n_data_bytes == 1)
    serialize_multiple_1 (m, data, data_stride, n_data);
  else if (n_data_bytes == 2)
    serialize_multiple_2 (m, data, data_stride, n_data);
  else if (n_data_bytes == 4)
    serialize_multiple_4 (m, data, data_stride, n_data);
  else
    ASSERT (0);
}

always_inline void
unserialize_multiple (serialize_main_t * m,
		      void *data,
		      uword n_data_bytes, uword data_stride, uword n_data)
{
  if (n_data_bytes == 1)
    unserialize_multiple_1 (m, data, data_stride, n_data);
  else if (n_data_bytes == 2)
    unserialize_multiple_2 (m, data, data_stride, n_data);
  else if (n_data_bytes == 4)
    unserialize_multiple_4 (m, data, data_stride, n_data);
  else
    ASSERT (0);
}

/* Basic types. */
serialize_function_t serialize_64, unserialize_64;
serialize_function_t serialize_32, unserialize_32;
serialize_function_t serialize_16, unserialize_16;
serialize_function_t serialize_8, unserialize_8;
serialize_function_t serialize_f64, unserialize_f64;
serialize_function_t serialize_f32, unserialize_f32;

/* Basic vector types. */
serialize_function_t serialize_vec_8, unserialize_vec_8;
serialize_function_t serialize_vec_16, unserialize_vec_16;
serialize_function_t serialize_vec_32, unserialize_vec_32;
serialize_function_t serialize_vec_64, unserialize_vec_64;

/* Serialize generic vectors. */
serialize_function_t serialize_vector, unserialize_vector,
  unserialize_aligned_vector;

#define vec_serialize(m,v,f) \
  serialize ((m), serialize_vector, (v), sizeof ((v)[0]), (f))

#define vec_unserialize(m,v,f) \
  unserialize ((m), unserialize_vector, (v), sizeof ((*(v))[0]), (f))

#define vec_unserialize_aligned(m,v,f) \
  unserialize ((m), unserialize_aligned_vector, (v), sizeof ((*(v))[0]), (f))

/* Serialize pools. */
serialize_function_t serialize_pool, unserialize_pool,
  unserialize_aligned_pool;

#define pool_serialize(m,v,f) \
  serialize ((m), serialize_pool, (v), sizeof ((v)[0]), (f))

#define pool_unserialize(m,v,f) \
  unserialize ((m), unserialize_pool, (v), sizeof ((*(v))[0]), (f))

#define pool_unserialize_aligned(m,v,a,f)				\
  unserialize ((m), unserialize_aligned_pool, (v), sizeof ((*(v))[0]), (a), (f))

/* Serialize heaps. */
serialize_function_t serialize_heap, unserialize_heap;

void serialize_bitmap (serialize_main_t * m, uword * b);
uword *unserialize_bitmap (serialize_main_t * m);

void serialize_cstring (serialize_main_t * m, char *string);
void unserialize_cstring (serialize_main_t * m, char **string);

void serialize_close (serialize_main_t * m);
void unserialize_close (serialize_main_t * m);

void serialize_open_data (serialize_main_t * m, u8 * data,
			  uword n_data_bytes);
void unserialize_open_data (serialize_main_t * m, u8 * data,
			    uword n_data_bytes);

/* Starts serialization with expanding vector as buffer. */
void serialize_open_vector (serialize_main_t * m, u8 * vector);

/* Serialization is done: returns vector buffer to caller. */
void *serialize_close_vector (serialize_main_t * m);

void unserialize_open_vector (serialize_main_t * m, u8 * vector);

#ifdef CLIB_UNIX
clib_error_t *serialize_open_unix_file (serialize_main_t * m, char *file);
clib_error_t *unserialize_open_unix_file (serialize_main_t * m, char *file);

void serialize_open_unix_file_descriptor (serialize_main_t * m, int fd);
void unserialize_open_unix_file_descriptor (serialize_main_t * m, int fd);
#endif /* CLIB_UNIX */

/* Main routines. */
clib_error_t *serialize (serialize_main_t * m, ...);
clib_error_t *unserialize (serialize_main_t * m, ...);
clib_error_t *va_serialize (serialize_main_t * m, va_list * va);

void serialize_magic (serialize_main_t * m, void *magic, u32 magic_bytes);
void unserialize_check_magic (serialize_main_t * m, void *magic,
			      u32 magic_bytes);

#endif /* included_clib_serialize_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
