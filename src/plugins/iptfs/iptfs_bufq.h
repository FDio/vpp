/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019, LabN Consulting, L.L.C.
 * September 10 2019, Christian Hopps <chopps@labn.net>
 */
#ifndef __included_iptfs_bufq_h__
#define __included_iptfs_bufq_h__

#include <stdbool.h>
#include <vnet/vnet.h>
#include <vppinfra/lock.h>
#include <vppinfra/ring.h>
#include <vppinfra/error.h>

// #define IPTFS_BUFQ_DEBUG

#ifdef IPTFS_BUFQ_DEBUG
#define iptfs_bufq_debug(...) clib_warning (__VA_ARGS__)
#else
#define iptfs_bufq_debug(...)
#endif

typedef clib_ring_header_t bufq_snapshot_t;

typedef struct
{
  u32 *q;  /* buffers */
  u32 *sz; /* sizes */
} iptfs_bufq;

typedef struct
{
  u32 size;
  u32 max_size;
  u32 hard_max_size;
} iptfs_bufq_limit;

static inline void
iptfs_bufq_init (iptfs_bufq *q, u32 ring_size)
{
  clib_ring_new (q->q, ring_size);
  clib_ring_new (q->sz, ring_size);
}

static inline void
iptfs_bufq_free (iptfs_bufq *q)
{
  ASSERT (clib_ring_n_enq (q->q) == 0);
  clib_ring_free (q->q);
  clib_ring_free (q->sz);
}

static inline u32
iptfs_bufq_n_enq (iptfs_bufq *q)
{
  return clib_ring_n_enq (q->q);
}

static inline u32
iptfs_bufq_capacity (iptfs_bufq *q)
{
  return _vec_len (q->q);
}

static inline u32
iptfs_bufq_avail (iptfs_bufq *q)
{
  return _vec_len (q->q) - clib_ring_n_enq (q->q);
}

static inline bool
iptfs_bufq_is_empty (iptfs_bufq *q)
{
  return clib_ring_n_enq (q->q) == 0;
}

static inline bool
iptfs_bufq_is_ring_full (iptfs_bufq *q)
{
  return clib_ring_n_enq (q->q) == _vec_len (q->q);
}

static inline bufq_snapshot_t
iptfs_bufq_snapshot (iptfs_bufq *q)
{
  return *clib_ring_header (q->q);
}

static inline void
iptfs_bufq_revert (iptfs_bufq *q, bufq_snapshot_t h)
{
  *clib_ring_header (q->q) = h;
}

static inline vlib_buffer_t *
iptfs_bufq_peek_last_locked (vlib_main_t *vm, iptfs_bufq *q, u32 *bi)
{
  u32 *_bi;
  if (!(_bi = (u32 *) clib_ring_get_last (q->q)))
    return NULL;

  if (bi)
    *bi = *_bi;
  return vlib_get_buffer (vm, *_bi);
}

/*
 * Dequeue up to N buffers.
 */

always_inline u32
clib_ring_ndeq_u32 (u32 *v, u32 *d, u32 ndeq)
{
  clib_ring_header_t *h = clib_ring_header (v);
  u32 slot, copy = 0;

  if (h->n_enq == 0)
    return 0;

  /* Trim down to the number of elts in ring */
  if (ndeq > h->n_enq)
    ndeq = h->n_enq;

  if (h->n_enq <= h->next)
    {
      /* All the elts precede h->next (no wrap) */
      slot = h->next - h->n_enq;
      clib_memcpy_fast (d, v + slot, ndeq * sizeof (*d));
    }
  else
    {
      /* Some of the elts are in front of h->next (wraps) */
      slot = _vec_len (v) + h->next - h->n_enq;
      if (slot + ndeq <= _vec_len (v))
	clib_memcpy_fast (d, v + slot, ndeq * sizeof (*d));
      else
	{
	  copy = _vec_len (v) - slot;
	  clib_memcpy_fast (d, v + slot, copy * sizeof (*d));
	  clib_memcpy_fast (d + copy, v, (ndeq - copy) * sizeof (*d));
	}
    }

  h->n_enq -= ndeq;
  return ndeq;
}

static inline u32
iptfs_bufq_ndequeue (iptfs_bufq *q, u32 *b, u32 *sz, u32 n)
{
  u32 n_actual = clib_ring_ndeq_u32 (q->q, b, n);
  (void) clib_ring_ndeq_u32 (q->sz, sz, n_actual);
  return n_actual;
}

static inline int
iptfs_bufq_enqueue (iptfs_bufq *q, u32 bi, u32 sz)
{
  u32 *slot;

  slot = clib_ring_enq (q->q);
  iptfs_bufq_debug ("%s queue q %p slot %p", __FUNCTION__, q->q, slot);
  if (PREDICT_FALSE ((!slot)))
    {
      clib_warning ("%s Exit Drop: no encap queue slots", __FUNCTION__);
      return 0;
    }
  *slot = bi;

  /* Enqueue the size for this packet */
  slot = clib_ring_enq (q->sz);
  *slot = sz;
  return 1;
}

static inline u32
iptfs_bufq_check_limit (iptfs_bufq *q, iptfs_bufq_limit *l, u16 newbytes)
{
  iptfs_bufq_debug ("%s Entered: len %u in thread %u", __FUNCTION__, newbytes,
		    vlib_get_thread_index ());
  u32 newqsz = l->size + newbytes;
  if (PREDICT_FALSE ((newqsz > l->max_size)))
    {
      if (newqsz > l->hard_max_size)
	{
	  iptfs_bufq_debug ("Drop: maxsize %u/%u newqsz %u", l->max_size, l->hard_max_size, newqsz);
	  return 0;
	}
    }

  iptfs_bufq_debug ("Queue: maxsize %u/%u newqsz %u", l->max_size, l->hard_max_size, newqsz);
  return newqsz;
}

#endif /* __included_iptfs_bufq_h__ */
