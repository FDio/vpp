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
  Copyright (c) 2012 Eliot Dresselhaus

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

#ifndef included_clib_smp_vec_h
#define included_clib_smp_vec_h

#include <vppinfra/smp.h>

#define foreach_clib_smp_fifo_data_state	\
  _ (free)					\
  _ (write_alloc)				\
  _ (write_done)				\
  _ (read_fetch)

typedef enum
{
#define _(f) CLIB_SMP_FIFO_DATA_STATE_##f,
  foreach_clib_smp_fifo_data_state
#undef _
    CLIB_SMP_FIFO_N_DATA_STATE,
} clib_smp_fifo_data_state_t;

/* Footer at end of each data element. */
typedef struct
{
  /* Magic number marking valid footer plus state encoded in low bits. */
  u32 magic_state;
} clib_smp_fifo_data_footer_t;

#define CLIB_SMP_DATA_FOOTER_MAGIC 0xfafbfcf0

always_inline clib_smp_fifo_data_state_t
clib_smp_fifo_data_footer_get_state (clib_smp_fifo_data_footer_t * f)
{
  u32 s = f->magic_state - CLIB_SMP_DATA_FOOTER_MAGIC;

  /* Check that magic number plus state is still valid. */
  if (s >= CLIB_SMP_FIFO_N_DATA_STATE)
    os_panic ();

  return s;
}

always_inline void
clib_smp_fifo_data_footer_set_state (clib_smp_fifo_data_footer_t * f,
				     clib_smp_fifo_data_state_t s)
{
  f->magic_state = CLIB_SMP_DATA_FOOTER_MAGIC + s;
}

typedef struct
{
  /* Read/write indices each on their own cache line.
     Atomic incremented for each read/write. */
  u32 read_index, write_index;

  /* Power of 2 number of elements in fifo less one. */
  u32 max_n_elts_less_one;

  /* Log2 of above. */
  u32 log2_max_n_elts;

  /* Cache aligned data. */
  void *data;
} clib_smp_fifo_t;

/* External functions. */
clib_smp_fifo_t *clib_smp_fifo_init (uword max_n_elts, uword n_bytes_per_elt);

/* Elements are always cache-line sized; this is to avoid smp cache thrashing. */
always_inline uword
clib_smp_fifo_round_elt_bytes (uword n_bytes_per_elt)
{
  return round_pow2 (n_bytes_per_elt, CLIB_CACHE_LINE_BYTES);
}

always_inline uword
clib_smp_fifo_n_elts (clib_smp_fifo_t * f)
{
  uword n = f->write_index - f->read_index;
  ASSERT (n <= f->max_n_elts_less_one + 1);
  return n;
}

always_inline clib_smp_fifo_data_footer_t *
clib_smp_fifo_get_data_footer (void *d, uword n_bytes_per_elt)
{
  clib_smp_fifo_data_footer_t *f;
  f = d + clib_smp_fifo_round_elt_bytes (n_bytes_per_elt) - sizeof (f[0]);
  return f;
}

always_inline void *
clib_smp_fifo_elt_at_index (clib_smp_fifo_t * f, uword n_bytes_per_elt,
			    uword i)
{
  uword n_bytes_per_elt_cache_aligned;

  ASSERT (i <= f->max_n_elts_less_one);

  n_bytes_per_elt_cache_aligned =
    clib_smp_fifo_round_elt_bytes (n_bytes_per_elt);

  return f->data + i * n_bytes_per_elt_cache_aligned;
}

always_inline void *
clib_smp_fifo_write_alloc (clib_smp_fifo_t * f, uword n_bytes_per_elt)
{
  void *d;
  clib_smp_fifo_data_footer_t *t;
  clib_smp_fifo_data_state_t s;
  u32 wi0, wi1;

  wi0 = f->write_index;

  /* Fifo full? */
  if (wi0 - f->read_index > f->max_n_elts_less_one)
    return 0;

  while (1)
    {
      wi1 = wi0 + 1;

      d =
	clib_smp_fifo_elt_at_index (f, n_bytes_per_elt,
				    wi0 & f->max_n_elts_less_one);
      t = clib_smp_fifo_get_data_footer (d, n_bytes_per_elt);

      s = clib_smp_fifo_data_footer_get_state (t);
      if (s != CLIB_SMP_FIFO_DATA_STATE_free)
	{
	  d = 0;
	  break;
	}

      wi1 = clib_smp_compare_and_swap (&f->write_index, wi1, wi0);

      if (wi1 == wi0)
	{
	  clib_smp_fifo_data_footer_set_state (t,
					       CLIB_SMP_FIFO_DATA_STATE_write_alloc);
	  break;
	}

      /* Other cpu wrote write index first: try again. */
      wi0 = wi1;
    }

  return d;
}

always_inline void
clib_smp_fifo_write_done (clib_smp_fifo_t * f, void *d, uword n_bytes_per_elt)
{
  clib_smp_fifo_data_footer_t *t;

  /* Flush out pending writes before we change state to write_done.
     This will hold off readers until data is flushed. */
  CLIB_MEMORY_BARRIER ();

  t = clib_smp_fifo_get_data_footer (d, n_bytes_per_elt);

  ASSERT (clib_smp_fifo_data_footer_get_state (t) ==
	  CLIB_SMP_FIFO_DATA_STATE_write_alloc);
  clib_smp_fifo_data_footer_set_state (t,
				       CLIB_SMP_FIFO_DATA_STATE_write_done);
}

always_inline void *
clib_smp_fifo_read_fetch (clib_smp_fifo_t * f, uword n_bytes_per_elt)
{
  void *d;
  clib_smp_fifo_data_footer_t *t;
  clib_smp_fifo_data_state_t s;
  u32 ri0, ri1;

  ri0 = f->read_index;

  /* Fifo empty? */
  if (f->write_index - ri0 == 0)
    return 0;

  while (1)
    {
      ri1 = ri0 + 1;

      d =
	clib_smp_fifo_elt_at_index (f, n_bytes_per_elt,
				    ri0 & f->max_n_elts_less_one);
      t = clib_smp_fifo_get_data_footer (d, n_bytes_per_elt);

      s = clib_smp_fifo_data_footer_get_state (t);
      if (s != CLIB_SMP_FIFO_DATA_STATE_write_done)
	{
	  d = 0;
	  break;
	}

      ri1 = clib_smp_compare_and_swap (&f->read_index, ri1, ri0);
      if (ri1 == ri0)
	{
	  clib_smp_fifo_data_footer_set_state (t,
					       CLIB_SMP_FIFO_DATA_STATE_read_fetch);
	  break;
	}

      ri0 = ri1;
    }

  return d;
}

always_inline void
clib_smp_fifo_read_done (clib_smp_fifo_t * f, void *d, uword n_bytes_per_elt)
{
  clib_smp_fifo_data_footer_t *t;

  t = clib_smp_fifo_get_data_footer (d, n_bytes_per_elt);

  ASSERT (clib_smp_fifo_data_footer_get_state (t) ==
	  CLIB_SMP_FIFO_DATA_STATE_read_fetch);
  clib_smp_fifo_data_footer_set_state (t, CLIB_SMP_FIFO_DATA_STATE_free);
}

always_inline void
clib_smp_fifo_memcpy (uword * dst, uword * src, uword n_bytes)
{
  word n_bytes_left = n_bytes;

  while (n_bytes_left >= 4 * sizeof (uword))
    {
      dst[0] = src[0];
      dst[1] = src[1];
      dst[2] = src[2];
      dst[3] = src[3];
      dst += 4;
      src += 4;
      n_bytes_left -= 4 * sizeof (dst[0]);
    }

  while (n_bytes_left > 0)
    {
      dst[0] = src[0];
      dst += 1;
      src += 1;
      n_bytes_left -= 1 * sizeof (dst[0]);
    }
}

always_inline void
clib_smp_fifo_write_inline (clib_smp_fifo_t * f, void *elt_to_write,
			    uword n_bytes_per_elt)
{
  uword *dst;
  dst = clib_smp_fifo_write_alloc (f, n_bytes_per_elt);
  clib_smp_fifo_memcpy (dst, elt_to_write, n_bytes_per_elt);
  clib_smp_fifo_write_done (f, dst, n_bytes_per_elt);
}

always_inline void
clib_smp_fifo_read_inline (clib_smp_fifo_t * f, void *elt_to_read,
			   uword n_bytes_per_elt)
{
  uword *src;
  src = clib_smp_fifo_read_fetch (f, n_bytes_per_elt);
  clib_smp_fifo_memcpy (elt_to_read, src, n_bytes_per_elt);
  clib_smp_fifo_read_done (f, src, n_bytes_per_elt);
}

#endif /* included_clib_smp_vec_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
