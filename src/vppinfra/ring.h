/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_ring_h
#define included_ring_h

#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/vec.h>
#include <vppinfra/vector.h>

typedef struct
{
  u32 next, n_enq;
} clib_ring_header_t;

always_inline clib_ring_header_t *
clib_ring_header (void *v)
{
  return vec_aligned_header (v, sizeof (clib_ring_header_t), sizeof (void *));
}

always_inline void
clib_ring_new_inline (void **p, u32 elt_bytes, u32 size, u32 align)
{
  void *v;
  clib_ring_header_t *h;

  v = _vec_resize ((void *) 0,
		   /* length increment */ size,
		   /* data bytes */ elt_bytes * size,
		   /* header bytes */ sizeof (h[0]),
		   /* data align */ align);

  h = clib_ring_header (v);
  h->next = 0;
  h->n_enq = 0;
  p[0] = v;
}

#define clib_ring_new_aligned(ring, size, align) \
{ clib_ring_new_inline ((void **)&(ring), sizeof(ring[0]), size, align); }

#define clib_ring_new(ring, size) \
{ clib_ring_new_inline ((void **)&(ring), sizeof(ring[0]), size, 0);}

#define clib_ring_free(f) vec_free_h((f), sizeof(clib_ring_header_t))

always_inline u32
clib_ring_n_enq (void *v)
{
  clib_ring_header_t *h = clib_ring_header (v);
  return h->n_enq;
}

always_inline void *
clib_ring_get_last_inline (void *v, u32 elt_bytes, int enqueue)
{
  clib_ring_header_t *h = clib_ring_header (v);
  u32 slot;

  if (enqueue)
    {
      if (h->n_enq == _vec_len (v))
	return 0;
      slot = h->next;
      h->n_enq++;
      h->next++;
      if (h->next == _vec_len (v))
	h->next = 0;
    }
  else
    {
      if (h->n_enq == 0)
	return 0;
      slot = h->next == 0 ? _vec_len (v) - 1 : h->next - 1;
    }

  return (void *) ((u8 *) v + elt_bytes * slot);
}

#define clib_ring_enq(ring) \
clib_ring_get_last_inline (ring, sizeof(ring[0]), 1)

#define clib_ring_get_last(ring) \
clib_ring_get_last_inline (ring, sizeof(ring[0]), 0)

always_inline void *
clib_ring_get_first_inline (void *v, u32 elt_bytes, int dequeue)
{
  clib_ring_header_t *h = clib_ring_header (v);
  u32 slot;

  if (h->n_enq == 0)
    return 0;

  if (h->n_enq > h->next)
    slot = _vec_len (v) + h->next - h->n_enq;
  else
    slot = h->next - h->n_enq;

  if (dequeue)
    h->n_enq--;

  return (void *) ((u8 *) v + elt_bytes * slot);
}

#define clib_ring_deq(ring) \
clib_ring_get_first_inline (ring, sizeof(ring[0]), 1)

#define clib_ring_get_first(ring) \
clib_ring_get_first_inline (ring, sizeof(ring[0]), 0)

#endif /* included_ring_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
