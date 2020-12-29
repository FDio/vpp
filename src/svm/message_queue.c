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

#include <svm/message_queue.h>
#include <vppinfra/mem.h>
#include <vppinfra/format.h>
#include <sys/eventfd.h>

static inline svm_msg_q_ring_t *
svm_msg_q_ring_inline (svm_msg_q_t * mq, u32 ring_index)
{
  return vec_elt_at_index (mq->rings, ring_index);
}

svm_msg_q_ring_t *
svm_msg_q_ring (svm_msg_q_t * mq, u32 ring_index)
{
  return svm_msg_q_ring_inline (mq, ring_index);
}

static inline void *
svm_msg_q_ring_data (svm_msg_q_ring_t * ring, u32 elt_index)
{
  ASSERT (elt_index < ring->nitems);
  return (ring->shr->data + elt_index * ring->elsize);
}

svm_msg_q_shared_t *
svm_msg_q_init (void *base, svm_msg_q_cfg_t *cfg)
{
  svm_msg_q_ring_shared_t *ring;
  svm_msg_q_shared_t *smq;
  u32 q_sz, offset;
  int i;

  q_sz = sizeof (svm_queue_t) + cfg->q_nitems * sizeof (svm_msg_q_msg_t);

  smq = (svm_msg_q_shared_t *) base;
  svm_queue_init (&smq->q, cfg->q_nitems, sizeof (svm_msg_q_msg_t));
  smq->q->consumer_pid = cfg->consumer_pid;
  smq->n_rings = cfg->n_rings;
  ring = (void *) ((u8 *) smq->q + q_sz);
  for (i = 0; i < cfg->n_rings; i++)
    {
      ring->elsize = cfg->ring_cfgs[i].elsize;
      ring->nitems = cfg->ring_cfgs[i].nitems;
      ring->cursize = ring->head = ring->tail = 0;
      offset = sizeof (*ring) + ring->nitems * ring->elsize;
      ring = (void *) ((u8 *) ring + offset);
    }

  return smq;
}

uword
svm_msg_q_size_to_alloc (svm_msg_q_cfg_t *cfg)
{
  svm_msg_q_ring_cfg_t *ring_cfg;
  uword rings_sz = 0, mq_sz;
  u32 q_sz;
  int i;

  ASSERT (cfg);

  rings_sz = sizeof (svm_msg_q_ring_shared_t) * cfg->n_rings;
  for (i = 0; i < cfg->n_rings; i++)
    {
      if (cfg->ring_cfgs[i].data)
	continue;
      ring_cfg = &cfg->ring_cfgs[i];
      rings_sz += (uword) ring_cfg->nitems * ring_cfg->elsize;
    }

  q_sz = sizeof (svm_queue_t) + cfg->q_nitems * sizeof (svm_msg_q_msg_t);
  mq_sz = sizeof (svm_msg_q_shared_t) + q_sz + rings_sz;

  return mq_sz;
}

svm_msg_q_shared_t *
svm_msg_q_alloc (svm_msg_q_cfg_t *cfg)
{
  uword mq_sz;
  u8 *base;

  mq_sz = svm_msg_q_size_to_alloc (cfg);
  base = clib_mem_alloc_aligned (mq_sz, CLIB_CACHE_LINE_BYTES);
  if (!base)
    return 0;

  return svm_msg_q_init (base, cfg);
}

void
svm_msg_q_attach (svm_msg_q_t *mq, void *smq_base)
{
  svm_msg_q_ring_shared_t *ring;
  svm_msg_q_shared_t *smq;
  u32 i, n_rings, q_sz, offset;

  smq = (svm_msg_q_shared_t *) smq_base;
  mq->q = smq->q;
  n_rings = smq->n_rings;
  vec_validate (mq->rings, n_rings - 1);
  q_sz = sizeof (svm_queue_t) + mq->q->maxsize * sizeof (svm_msg_q_msg_t);
  ring = (void *) ((u8 *) smq->q + q_sz);
  for (i = 0; i < n_rings; i++)
    {
      mq->rings[i].nitems = ring->nitems;
      mq->rings[i].elsize = ring->elsize;
      mq->rings[i].shr = ring;
      offset = sizeof (*ring) + ring->nitems * ring->elsize;
      ring = (void *) ((u8 *) ring + offset);
    }
}

void
svm_msg_q_free (svm_msg_q_t * mq)
{
  svm_queue_free (mq->q);
  clib_mem_free (mq);
}

svm_msg_q_msg_t
svm_msg_q_alloc_msg_w_ring (svm_msg_q_t * mq, u32 ring_index)
{
  svm_msg_q_ring_shared_t *sr;
  svm_msg_q_ring_t *ring;
  svm_msg_q_msg_t msg;

  ring = svm_msg_q_ring_inline (mq, ring_index);
  sr = ring->shr;

  ASSERT (sr->cursize < ring->nitems);
  msg.ring_index = ring - mq->rings;
  msg.elt_index = sr->tail;
  sr->tail = (sr->tail + 1) % ring->nitems;
  clib_atomic_fetch_add (&sr->cursize, 1);
  return msg;
}

int
svm_msg_q_lock_and_alloc_msg_w_ring (svm_msg_q_t * mq, u32 ring_index,
				     u8 noblock, svm_msg_q_msg_t * msg)
{
  if (noblock)
    {
      if (svm_msg_q_try_lock (mq))
	return -1;
      if (PREDICT_FALSE (svm_msg_q_is_full (mq)
			 || svm_msg_q_ring_is_full (mq, ring_index)))
	{
	  svm_msg_q_unlock (mq);
	  return -2;
	}
      *msg = svm_msg_q_alloc_msg_w_ring (mq, ring_index);
    }
  else
    {
      svm_msg_q_lock (mq);
      while (svm_msg_q_is_full (mq)
	     || svm_msg_q_ring_is_full (mq, ring_index))
	svm_msg_q_wait (mq);
      *msg = svm_msg_q_alloc_msg_w_ring (mq, ring_index);
    }
  return 0;
}

svm_msg_q_msg_t
svm_msg_q_alloc_msg (svm_msg_q_t * mq, u32 nbytes)
{
  svm_msg_q_msg_t msg = {.as_u64 = ~0 };
  svm_msg_q_ring_shared_t *sr;
  svm_msg_q_ring_t *ring;

  vec_foreach (ring, mq->rings)
  {
    sr = ring->shr;
    if (ring->elsize < nbytes || sr->cursize == ring->nitems)
      continue;
    msg.ring_index = ring - mq->rings;
    msg.elt_index = sr->tail;
    sr->tail = (sr->tail + 1) % ring->nitems;
    clib_atomic_fetch_add (&sr->cursize, 1);
    break;
  }
  return msg;
}

void *
svm_msg_q_msg_data (svm_msg_q_t * mq, svm_msg_q_msg_t * msg)
{
  svm_msg_q_ring_t *ring = svm_msg_q_ring_inline (mq, msg->ring_index);
  return svm_msg_q_ring_data (ring, msg->elt_index);
}

void
svm_msg_q_free_msg (svm_msg_q_t * mq, svm_msg_q_msg_t * msg)
{
  svm_msg_q_ring_shared_t *sr;
  svm_msg_q_ring_t *ring;
  int need_signal;

  ASSERT (vec_len (mq->rings) > msg->ring_index);
  ring = svm_msg_q_ring_inline (mq, msg->ring_index);
  sr = ring->shr;
  if (msg->elt_index == sr->head)
    {
      sr->head = (sr->head + 1) % ring->nitems;
    }
  else
    {
      clib_warning ("message out of order");
      /* for now, expect messages to be processed in order */
      ASSERT (0);
    }

  need_signal = sr->cursize == ring->nitems;
  clib_atomic_fetch_sub (&sr->cursize, 1);

  if (PREDICT_FALSE (need_signal))
    svm_queue_send_signal (mq->q, 0);
}

static int
svm_msq_q_msg_is_valid (svm_msg_q_t * mq, svm_msg_q_msg_t * msg)
{
  u32 dist1, dist2, tail, head;
  svm_msg_q_ring_shared_t *sr;
  svm_msg_q_ring_t *ring;

  if (vec_len (mq->rings) <= msg->ring_index)
    return 0;

  ring = svm_msg_q_ring_inline (mq, msg->ring_index);
  sr = ring->shr;
  tail = sr->tail;
  head = sr->head;

  dist1 = ((ring->nitems + msg->elt_index) - head) % ring->nitems;
  if (tail == head)
    dist2 = (sr->cursize == 0) ? 0 : ring->nitems;
  else
    dist2 = ((ring->nitems + tail) - head) % ring->nitems;
  return (dist1 < dist2);
}

int
svm_msg_q_add (svm_msg_q_t * mq, svm_msg_q_msg_t * msg, int nowait)
{
  ASSERT (svm_msq_q_msg_is_valid (mq, msg));
  return svm_queue_add (mq->q, (u8 *) msg, nowait);
}

void
svm_msg_q_add_and_unlock (svm_msg_q_t * mq, svm_msg_q_msg_t * msg)
{
  ASSERT (svm_msq_q_msg_is_valid (mq, msg));
  svm_queue_add_raw (mq->q, (u8 *) msg);
  svm_msg_q_unlock (mq);
}

int
svm_msg_q_sub (svm_msg_q_t * mq, svm_msg_q_msg_t * msg,
	       svm_q_conditional_wait_t cond, u32 time)
{
  return svm_queue_sub (mq->q, (u8 *) msg, cond, time);
}

void
svm_msg_q_sub_w_lock (svm_msg_q_t * mq, svm_msg_q_msg_t * msg)
{
  svm_queue_sub_raw (mq->q, (u8 *) msg);
}

void
svm_msg_q_set_consumer_eventfd (svm_msg_q_t * mq, int fd)
{
  mq->q->consumer_evtfd = fd;
}

void
svm_msg_q_set_producer_eventfd (svm_msg_q_t * mq, int fd)
{
  mq->q->producer_evtfd = fd;
}

int
svm_msg_q_alloc_consumer_eventfd (svm_msg_q_t * mq)
{
  int fd;
  if ((fd = eventfd (0, EFD_NONBLOCK)) < 0)
    return -1;
  svm_msg_q_set_consumer_eventfd (mq, fd);
  return 0;
}

int
svm_msg_q_alloc_producer_eventfd (svm_msg_q_t * mq)
{
  int fd;
  if ((fd = eventfd (0, EFD_NONBLOCK)) < 0)
    return -1;
  svm_msg_q_set_producer_eventfd (mq, fd);
  return 0;
}

u8 *
format_svm_msg_q (u8 * s, va_list * args)
{
  svm_msg_q_t *mq = va_arg (*args, svm_msg_q_t *);
  s = format (s, " [Q:%d/%d]", mq->q->cursize, mq->q->maxsize);
  for (u32 i = 0; i < vec_len (mq->rings); i++)
    {
      s = format (s, " [R%d:%d/%d]", i, mq->rings[i].shr->cursize,
		  mq->rings[i].nitems);
    }
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
