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

typedef struct mrpool_overflow_vec_ mrpool_overflow_vec_t;

struct mrpool_overflow_vec_
{
  mrpool_overflow_vec_t *next;
  u32 ofv_index;
  u32 n_elts;
  void *data;
};

typedef struct mrpool_hdr_data_
{
  u32 len_at_overflow;
  u32 n_elts;
  mrpool_overflow_vec_t head;
} mrpool_overflow_data_t;

typedef struct mrpool_header_
{
  /** Bitmap of indices of free objects. */
  uword *free_bitmap;

  /** Vector of free indices.  One element for each set bit in bitmap. */
  u32 *free_indices;

  mrpool_overflow_data_t *data;
  mrpool_expand_cb_fn expand_cb;
  u8 expand_pending;
} mrpool_header_t;

STATIC_ASSERT_SIZEOF (mrpool_header_t, sizeof (pool_header_t));

#define MRPOOL_ELTS_PER_OF_VEC 32

#define mrpool_init(P, FN)                                                    \
  do                                                                          \
    {                                                                         \
      mrpool_header_t *_p;                                                    \
      pool_alloc_aligned (P, 0, 0);                                           \
      _p = (mrpool_header_t *) pool_header (P);                               \
      _p->expand_pending = 0;                                                 \
      _p->expand_cb = (FN);                                                   \
      _p->data = clib_mem_alloc (sizeof (mrpool_overflow_data_t));            \
    }                                                                         \
  while (0)

always_inline mrpool_overflow_vec_t *
mrpool_get_next_of_vec (mrpool_overflow_data_t *od)
{
  mrpool_overflow_vec_t *prev = 0, *ofv = &od->head;

  while (ofv && vec_len (ofv->data) >= MRPOOL_ELTS_PER_OF_VEC)
    {
      prev = ofv;
      ofv = ofv->next;
    }

  if (ofv)
    return ofv;

  ofv = clib_mem_alloc (sizeof (*ofv));
  clib_memset (ofv, 0, sizeof (*ofv));
  ofv->ofv_index = prev->ofv_index + 1;
  prev->next = ofv;

  return ofv;
}

#define mrpool_get(P, E, I)                                                   \
  do                                                                          \
    {                                                                         \
      u8 will_expand = 0;                                                     \
      pool_get_aligned_will_expand ((P), will_expand, CLIB_CACHE_LINE_BYTES); \
      if (PREDICT_FALSE (will_expand))                                        \
	{                                                                     \
	  mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);          \
	  mrpool_overflow_vec_t *_ofv = mrpool_get_next_of_vec (_p->data);    \
	  if (!_of->data)                                                     \
	    {                                                                 \
	      vec_validate ((typeof (P)) _ofv->data, MRPOOL_ELTS_PER_OF_VEC); \
	      vec_reset_length ((typeof (P)) _of->data);                      \
	    }                                                                 \
	  vec_add2 ((typeof (P)) _ofv->data, (E), 1);                         \
	  if (!_p->expand_pending)                                            \
	    {                                                                 \
	      _p->data->len_at_overflow = pool_len ((P));                     \
	      _p->expand_pending = 1;                                         \
	      _p->expand_cb (&(P));                                           \
	    }                                                                 \
	  _p->data->n_elts += 1;                                              \
	  (I) = pool_len (P) + _ofv->ofv_index * MRPOOL_ELTS_PER_OF_VEC +     \
		(((typeof (P)) _ofv->data) - _op);                            \
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

always_inline mrpool_overflow_vec_t *
mrpool_ofv_lookup (mrpool_overflow_data_t *od, u32 elt_index)
{
  mrpool_overflow_vec_t *ofv = &od->head;
  u32 end_pos = 0;

  while (ofv)
    {
      end_pos += vec_len (ofv);

      if (elt_index < end_pos)
	return ofv;

      ofv = ofv->next;
    }

  return 0;
}

#define mrpool_elt_at_index(P, I)                                             \
  ({                                                                          \
    mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);                \
    typeof (P) _e;                                                            \
    if (PREDICT_FALSE (_p->expand_pending))                                   \
      {                                                                       \
	u32 len = pool_len (P);                                               \
	if (si < len)                                                         \
	  _e = (P) + (I);                                                     \
	else                                                                  \
	  {                                                                   \
	    mrpool_overflow_vec_t *_ofv;                                      \
	    _ofv = mrpool_ofv_lookup (_p->data, (I) -len);                    \
	    _e = (((typeof (P)) _ofv->data) + ((I) - len);                    \
	  }                                                                   \
      }                                                                       \
    else                                                                      \
      _e = (P) + (I);                                                         \
    _e;                                                                       \
  })

#define mrpool_put_index(P, I)                                                \
  do                                                                          \
    {                                                                         \
      mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);              \
      if (PREDICT_FALSE (_p->expand_pending))                                 \
	{                                                                     \
	  if ((I) > _p->data->len_at_overflow)                                \
	    _p->free_bitmap = clib_bitmap_ori_notrim (_p->free_bitmap, (I));  \
	  else                                                                \
	    pool_put_index ((P), (I));                                        \
	}                                                                     \
      else                                                                    \
	pool_put_index ((P), (I));                                            \
    }                                                                         \
  while (0)

always_inline void
mrpool_free_of_vecs (mrpool_overflow_data_t *od)
{
  mrpool_overflow_vec_t *next = 0, *ofv = &od->head;

  while (ofv)
    {
      vec_free (ofv->data);
      next = ofv->next;
      if (ofv->ofv_index != 0)
	{
	  clib_mem_free (ofv);
	}
      else
	{
	  ofv->ofv_index = 0;
	  ofv->next = 0;
	}
      ofv = next;
    }
}

#define mrpool_realloc(P)                                                     \
  do                                                                          \
    {                                                                         \
      mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);              \
      u32 len, pending_len, ofv_elts, del_elts = 0;                           \
      if (!_p->expand_pending)                                                \
	break;                                                                \
      len = _p->data->len_at_overflow;                                        \
      pending_len = _p->data->n_elts;                                         \
      pool_alloc ((P), clib_max (len, 2 * pending_len));                      \
      mrpool_overflow_vec_t *_ofv = &_p->data->head;                          \
      while (_ofv)                                                            \
	{                                                                     \
	  clib_memcpy_fast (&(P)[len - del_elts], _ofv->data,                 \
			    pending_len * sizeof (P[0]));                     \
	  ofv_elts = vec_len (_ofv->data);                                    \
	  for (int _i = len; _i < ofv_elts; _i++)                             \
	    if (clib_bitmap_get (_p->free_bitmap, _i))                        \
	      del_elts += 1;                                                  \
	  len += ofv_elts;                                                    \
	  _ofv = _ofv->next;                                                  \
	}                                                                     \
      _vec_len ((P)) += pending_len - del_elts;                               \
      _p->expand_pending = 0;                                                 \
      _p->data->len_at_overflow = ~0;                                         \
      mrpool_free_of_vecs (_p->data);                                         \
    }                                                                         \
  while (0)

#define mrpool_free(P)                                                        \
  do                                                                          \
    {                                                                         \
      mrpool_header_t *_p = (mrpool_header_t *) pool_header (P);              \
      mrpool_free_of_vecs (_p->data);                                         \
      clib_mem_free (_p->data);                                               \
      pool_free (P);                                                          \
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
