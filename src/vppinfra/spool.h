/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
/**
 * A "static" pool implementation. Compared to the simple pool, this
 * guarantees that elements are never moved, i.e., pointers to them are not
 * invalidated, as the data structure scales out.
 *
 * TODO: does not map allocated elements to sub vectors and does not provide
 * indices
 */

#ifndef SRC_VPPINFRA_SPOOL_H_
#define SRC_VPPINFRA_SPOOL_H_

#include <vppinfra/vec.h>

typedef struct
{
  /** Vector of elements */
  void **free_elts;
  void **chunks;
  u32 n_alloc;
} spool_header_t;

/** Local variable naming macro. */
#define _spv(v) _spool_##v

/** Align pool header so that pointers are naturally aligned. */
#define spool_aligned_header_bytes 					\
  vec_aligned_header_bytes (sizeof (spool_header_t), sizeof (void *))

/** Get spool header from user spool pointer */
always_inline spool_header_t *
spool_header (void *v)
{
  return vec_aligned_header (v, sizeof (spool_header_t), sizeof (void *));
}

#define _spool_chunk_free_elts(P, C)					\
({									\
  uword _spv (mb), _spv (ml);						\
  if (P == C)								\
    {									\
      _spv (mb) = vec_capacity (C, sizeof (spool_header_t));		\
      _spv (mb) -= spool_aligned_header_bytes;				\
    }									\
  else									\
    {									\
      _spv (mb) = vec_capacity (C, 0) - sizeof (vec_header_t);		\
    }									\
  _spv (ml) = (_spv (mb) / sizeof ((C)[0])) - vec_len (C);		\
  /*fprintf (stderr, "mb %lu ml %lu\n", _spv (mb), _spv (ml)); */\
  _spv (ml);								\
})

#define _spool_get_aligned_internal(P,E,A,Z)                      	\
do {                                                                    \
  spool_header_t * _spv (p);			                     	\
  uword _spv (l), _spv (ci);                                         	\
  typeof (P) _spv (cv);							\
  if (!(P))                                                             \
    {									\
      (P) = _vec_resize (P, 0, 4 * sizeof (P[0]), 			\
                         sizeof (spool_header_t), /* align */ (A));	\
      _spv (p) = spool_header (P); 					\
      vec_add1 (_spv (p)->chunks, (P));					\
    }									\
  else									\
    {									\
      _spv (p) = spool_header (P); 					\
    }									\
  _spv (l) = vec_len (_spv (p)->free_elts);              		\
  _spv (ci) = vec_len (_spv (p)->chunks) - 1;				\
  _spv (cv) = _spv (p)->chunks[_spv (ci)];				\
  if (_spv (l) > 0)                                                	\
    {                                                                   \
      /* Return free element from free list. */                         \
      (E) = (typeof (E)) vec_pop (_spv (p)->free_elts);			\
    }                                                                   \
  else if (_spool_chunk_free_elts (P, _spv (cv)))			\
    {									\
      (E) = _spv (cv) + vec_len (_spv (cv));				\
      _vec_len (_spv (cv)) += 1;					\
    }									\
  else                                                                  \
    {                                                                   \
      /* Allocate new chunk of memory */  				\
      typeof (P) _spv (new) = 0;					\
      _spv (new) = _vec_resize (_spv (new) , 0,				\
                                _spv (p)->n_alloc * sizeof (P[0]),	\
                                0 /* header */, (A));			\
      (E) = _spv (new);							\
      _vec_len (_spv (new)) = 1;       					\
      vec_add1 (_spv (p)->chunks, _spv (new));				\
    }                                                                   \
  if (Z)                                                                \
    memset(E, 0, sizeof(*E));                                           \
  _spv (p)->n_alloc += 1;						\
} while (0)

/** Allocate an object E from a spool P with alignment A */
#define spool_get_aligned(P,E,A) _spool_get_aligned_internal(P,E,A,0)

  /** Allocate an object E from a spool P with alignment A and zero it */
#define spool_get_aligned_zero(P,E,A) _spool_get_aligned_internal(P,E,A,1)

/** Allocate an object E from a spool P (unspecified alignment). */
#define spool_get(P,E) spool_get_aligned(P,E,0)

/** Allocate an object E from a spool P and zero it */
#define spool_get_zero(P,E) spool_get_aligned_zero(P,E,0)

/** Free an object E in spool P. */
#define spool_put(P,E)							\
do {									\
  spool_header_t * _spv (p) = spool_header (P);				\
  vec_add1 (_spv (p)->free_elts, (void *)(E));				\
  _spv (p)->n_alloc -= 1;						\
} while (0)

#define spool_free(P) 							\
do {									\
  spool_header_t * _spv (p);						\
  int i;								\
  if (!(P))								\
    return 0;								\
  _spv (p) = spool_header (P);						\
  for (i = 1; i < vec_len (_spv (p)->chunks); i++)			\
    {									\
      typeof (P) _spv (cv) = (typeof (P)) _spv (p)->chunks[i];		\
      vec_free (_spv (cv));						\
    }									\
  vec_free (_spv (p)->free_elts);					\
  vec_free (_spv (p)->chunks);						\
  vec_free_h ((P), sizeof (spool_header_t));				\
} while (0)

#define spool_elts(P) (spool_header(P)->n_alloc)

#endif /* SRC_VPPINFRA_SPOOL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
