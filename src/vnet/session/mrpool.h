/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_MRPOOL_H_
#define SRC_VNET_SESSION_MRPOOL_H_

#include <vppinfra/pool.h>

typedef void (*mrpool_expand_cb_fn) (void *pool);

typedef struct mrpool_hdr_data_
{
  void *overflow;

} mrpool_hdr_data_t;

typedef struct mrpool_header_
{
  /** Bitmap of indices of free objects. */
  uword *free_bitmap;

  /** Vector of free indices.  One element for each set bit in bitmap. */
  u32 *free_indices;

  void *overflow;
  mrpool_expand_cb_fn expand_cb;
  u8 expand_pending;
} mrpool_header_t;

STATIC_ASSERT_SIZEOF (mrpool_header_t, sizeof (pool_header_t));

#define mrpool_init(P, FN)                                                    \
  do                                                                          \
    {                                                                         \
      mrpool_header_t *_p;                                                    \
      pool_alloc_aligned (P, 0, 0);                                           \
      _p = (mrpool_header_t *) pool_header (P);                               \
      _p->expand_pending = 0;                                                 \
      _p->expand_cb = (FN);                                                   \
    }                                                                         \
  while (0)

#define mrpool_get(P, E, I)                                                   \
  do                                                                          \
    {                                                                         \
      u8 will_expand = 0;                                                     \
      pool_get_aligned_will_expand ((P), will_expand, CLIB_CACHE_LINE_BYTES); \
      if (PREDICT_FALSE (will_expand))                                        \
	{                                                                     \
	  mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);          \
	  typeof (P) _op = (typeof (P)) _p->overflow;                         \
	  vec_validate (_op, 32);                                             \
	  vec_add2 (_op, (E), 1);                                             \
	  if (!_p->expand_pending)                                            \
	    {                                                                 \
	      _p->expand_pending = 1;                                         \
	      _p->expand_cb (P);                                              \
	    }                                                                 \
	  (I) = (E) -_op;                                                     \
	  _p->free_bitmap =                                                   \
	    clib_bitmap_andnoti_notrim (_p->free_bitmap, (I));                \
	}                                                                     \
      else                                                                    \
	{                                                                     \
	  pool_get_aligned (P, E, CLIB_CACHE_LINE_BYTES);                     \
	  (I) = (E) - (P);                                                    \
	}                                                                     \
    }                                                                         \
  while (0)

#define mrpool_elt_at_index(P, I)                                             \
  ({                                                                          \
    mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);                \
    typeof (P) _e;                                                            \
    if (PREDICT_FALSE (_p->expand_pending))                                   \
      {                                                                       \
	u32 len = pool_len (P);                                               \
	if (si < len)                                                         \
	  _e = (P) + si;                                                      \
	else                                                                  \
	  _e = (P) + (si - len);                                              \
      }                                                                       \
    else                                                                      \
      _e = (P) + si;                                                          \
    _e;                                                                       \
  })

#define mrpool_put_index(P, I)                                                \
  do                                                                          \
    {                                                                         \
      mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);              \
      if (PREDICT_FALSE (_p->expand_pending))                                 \
	{                                                                     \
	  if ((I) > pool_len (P))                                             \
	    _p->free_bitmap = clib_bitmap_ori_notrim (_p->free_bitmap, (I));  \
	  else                                                                \
	    pool_put_index ((P), (I));                                        \
	}                                                                     \
      else                                                                    \
	pool_put_index ((P), (I));                                            \
    }                                                                         \
  while (0)

#define mrpool_realloc(P)                                                     \
  do                                                                          \
    {                                                                         \
      mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);              \
      u32 len, pending_len, oit_index;                                        \
      typeof (P) oit;                                                         \
      if (!_p->expand_pending)                                                \
	break;                                                                \
                                                                              \
      len = pool_len ((P));                                                   \
      pending_len = vec_len (wrk->sessions_expand);                           \
      /* Grow pool to at least double the previous size */                    \
      pool_alloc ((P), clib_max (len, 2 * pending_len));                      \
      clib_memcpy_fast (&(P)[len], _p->overflow,                              \
			pending_len * sizeof (P[0]));                         \
      oit_index = len;                                                        \
      vec_foreach (oit, _p->overflow)                                         \
	{                                                                     \
	  /* Already freed, mark index as free */                             \
	  if (clib_bitmap_get (_p->free_bitmap, oit_index))                   \
	    {                                                                 \
	      pending_len -= 1;                                               \
	    }                                                                 \
	  oit_index += 1;                                                     \
	}                                                                     \
      _vec_len ((P)) += pending_len;                                          \
      _p->expand_pending = 0;                                                 \
      vec_reset_length (_p->overflow);                                        \
    }                                                                         \
  while (0)
#endif /* SRC_VNET_SESSION_MRPOOL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
