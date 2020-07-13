/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C
 * May 20 2020, Christian Hopps <chopps@labn.net>
 *
 * BSD sys/queue.h style macros for a fixed size lock-less ring implementation.
 *
 * Depends on a single thread doing the GETs and another sngle thread (or the
 * same thread) doing the PUTs. The getter reads the tail and writes the head
 * index while reading the elements between the head and the tail. The putter
 * reads the head and writes the tail while putting elements into the ring.
 */
#ifndef __included_iptfs_sring_h__
#define __included_iptfs_sring_h__

#include <vppinfra/clib.h>
#include <vppinfra/string.h>

/*
 * This macro is for situations where client code has multiple strings
 * and we don't want struct name collisions.
 */
#define SRING_RING_ANON(log2, etype)                                                               \
  struct                                                                                           \
  {                                                                                                \
    /* Want these aligned so the load/store is atomic */                                           \
    volatile uword head;                                                                           \
    volatile uword tail;                                                                           \
    etype q[1 << (log2)];                                                                          \
  }

/*
 * This is the original macro. Maybe instances of this can
 * be replaced by the macro above?
 */
#define SRING_RING(log2, etype)                                                                    \
  struct iptfs_sring_t                                                                             \
  {                                                                                                \
    /* Want these aligned so the load/store is atomic */                                           \
    volatile uword head;                                                                           \
    volatile uword tail;                                                                           \
    etype q[1 << (log2)];                                                                          \
  }

#define SRING_RSIZE(r) (sizeof ((r)->q) / sizeof ((r)->q[0]))
#define SRING_QSIZE(r) (sizeof ((r)->q) / sizeof ((r)->q[0]) - 1)

#define _SRING_NELT(r, _head, _tail)                                                               \
  ({                                                                                               \
    uword _h = (_head);                                                                            \
    uword _t = (_tail);                                                                            \
    ((_h > _t) ? (SRING_RSIZE (r) - (_h - _t)) : (_t - _h));                                       \
  })

/* Be careful when using this if you read tail again it might be different */
#define SRING_NELT(r) _SRING_NELT (r, (r)->head, (r)->tail)

#define SRING_GET(r, elts, upto)                                                                   \
  ({                                                                                               \
    uword head = (r)->head;                                                                        \
    uword tail = (r)->tail;                                                                        \
    uword nreq = (upto);                                                                           \
    uword n = 0;                                                                                   \
                                                                                                   \
    /* Be careful */                                                                               \
    /* Tail could have changed in the queue since caching above */                                 \
    uword n_avail = _SRING_NELT (r, head, tail);                                                   \
    if (n_avail < nreq)                                                                            \
      nreq = n_avail;                                                                              \
                                                                                                   \
    uword n_need = nreq;                                                                           \
    if (head > tail)                                                                               \
      {                                                                                            \
	n = clib_min (SRING_RSIZE (r) - head, n_need);                                             \
	clib_memcpy_fast ((elts), &(r)->q[head], n * sizeof ((r)->q[0]));                          \
	head = (head + n) & (SRING_RSIZE (r) - 1);                                                 \
	n_need -= n;                                                                               \
      }                                                                                            \
    if (n_need)                                                                                    \
      {                                                                                            \
	clib_memcpy_fast ((elts) + n, &(r)->q[head], n_need * sizeof ((r)->q[0]));                 \
	head = (head + n_need) & (SRING_RSIZE (r) - 1);                                            \
      }                                                                                            \
                                                                                                   \
    /* Make sure the buffer values are stored prior to updating head */                            \
    CLIB_MEMORY_STORE_BARRIER ();                                                                  \
    (r)->head = head;                                                                              \
                                                                                                   \
    nreq;                                                                                          \
  })

#define _SRING_OPEN(r, head, tail) (SRING_QSIZE (r) - _SRING_NELT (r, head, tail))

/* Be aware that more slots may open immediately after getting this value */
#define SRING_OPEN(r) _SRING_OPEN ((r), (r)->head, (r)->tail)

#define SRING_PUT(r, elts, n_put_req)                                                              \
  ({                                                                                               \
    u32 start = (r)->tail;                                                                         \
    u32 n_open = _SRING_OPEN (r, (r)->head, start);                                                \
    u32 n_put = n_put_req;                                                                         \
                                                                                                   \
    if (n_put > n_open)                                                                            \
      n_put = n_open;                                                                              \
                                                                                                   \
    if (start + n_put <= SRING_RSIZE (r))                                                          \
      clib_memcpy_fast ((r)->q + start, (elts), n_put * sizeof ((r)->q[0]));                       \
    else                                                                                           \
      {                                                                                            \
	u32 n = SRING_RSIZE (r) - start;                                                           \
	clib_memcpy_fast ((r)->q + start, (elts), n * sizeof ((r)->q[0]));                         \
	if (n_put - n)                                                                             \
	  clib_memcpy_fast ((r)->q, (elts) + n, (n_put - n) * sizeof ((r)->q[0]));                 \
      }                                                                                            \
                                                                                                   \
    /* make sure the elts are stored prior to updating tail */                                     \
    CLIB_MEMORY_STORE_BARRIER ();                                                                  \
    (r)->tail = (start + n_put) & (SRING_RSIZE (r) - 1);                                           \
    n_put;                                                                                         \
  })

#endif /* __included_iptfs_sring_h__ */
