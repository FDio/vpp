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
  return (ring->data + elt_index * ring->elsize);
}

svm_msg_q_t *
svm_msg_q_alloc (svm_msg_q_cfg_t * cfg)
{
  svm_msg_q_ring_cfg_t *ring_cfg;
  svm_msg_q_ring_t *ring;
  u8 *base, *rings_ptr;
  uword rings_sz = 0;
  vec_header_t *vh;
  svm_msg_q_t *mq;
  u32 vec_sz;
  int i;

  ASSERT (cfg);

  vec_sz = vec_header_bytes (0) + sizeof (svm_msg_q_ring_t) * cfg->n_rings;
  for (i = 0; i < cfg->n_rings; i++)
    {
      if (cfg->ring_cfgs[i].data)
	continue;
      ring_cfg = &cfg->ring_cfgs[i];
      rings_sz += (uword) ring_cfg->nitems * ring_cfg->elsize;
    }

  base = clib_mem_alloc_aligned (sizeof (svm_msg_q_t) + vec_sz + rings_sz,
				 CLIB_CACHE_LINE_BYTES);
  if (!base)
    return 0;

  mq = (svm_msg_q_t *) base;
  vh = (vec_header_t *) (base + sizeof (svm_msg_q_t));
  vh->len = cfg->n_rings;
  mq->rings = (svm_msg_q_ring_t *) (vh + 1);
  rings_ptr = (u8 *) mq->rings + vec_sz;
  for (i = 0; i < cfg->n_rings; i++)
    {
      ring = &mq->rings[i];
      ring->elsize = cfg->ring_cfgs[i].elsize;
      ring->nitems = cfg->ring_cfgs[i].nitems;
      ring->cursize = ring->head = ring->tail = 0;
      if (cfg->ring_cfgs[i].data)
	ring->data = cfg->ring_cfgs[i].data;
      else
	{
	  ring->data = rings_ptr;
	  rings_ptr += (uword) ring->nitems * ring->elsize;
	}
    }
  mq->q = svm_queue_init (cfg->q_nitems, sizeof (svm_msg_q_msg_t),
			  cfg->consumer_pid, 0);

  return mq;
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
  svm_msg_q_msg_t msg;
  svm_msg_q_ring_t *ring = svm_msg_q_ring_inline (mq, ring_index);

  ASSERT (ring->cursize < ring->nitems);
  msg.ring_index = ring - mq->rings;
  msg.elt_index = ring->tail;
  ring->tail = (ring->tail + 1) % ring->nitems;
  __sync_fetch_and_add (&ring->cursize, 1);
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
      if (PREDICT_FALSE (svm_msg_q_ring_is_full (mq, ring_index)))
	{
	  svm_msg_q_unlock (mq);
	  return -2;
	}
      *msg = svm_msg_q_alloc_msg_w_ring (mq, ring_index);
      if (PREDICT_FALSE (svm_msg_q_msg_is_invalid (msg)))
	{
	  svm_msg_q_unlock (mq);
	  return -2;
	}
    }
  else
    {
      svm_msg_q_lock (mq);
      while (svm_msg_q_ring_is_full (mq, ring_index))
	svm_msg_q_wait (mq);
      *msg = svm_msg_q_alloc_msg_w_ring (mq, ring_index);
    }
  return 0;
}

svm_msg_q_msg_t
svm_msg_q_alloc_msg (svm_msg_q_t * mq, u32 nbytes)
{
  svm_msg_q_msg_t msg = {.as_u64 = ~0 };
  svm_msg_q_ring_t *ring;

  vec_foreach (ring, mq->rings)
  {
    if (ring->elsize < nbytes || ring->cursize == ring->nitems)
      continue;
    msg.ring_index = ring - mq->rings;
    msg.elt_index = ring->tail;
    ring->tail = (ring->tail + 1) % ring->nitems;
    __sync_fetch_and_add (&ring->cursize, 1);
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
  svm_msg_q_ring_t *ring;

  if (vec_len (mq->rings) <= msg->ring_index)
    return;
  ring = &mq->rings[msg->ring_index];
  if (msg->elt_index == ring->head)
    {
      ring->head = (ring->head + 1) % ring->nitems;
    }
  else
    {
      /* for now, expect messages to be processed in order */
      ASSERT (0);
    }
  __sync_fetch_and_sub (&ring->cursize, 1);
}

static int
svm_msq_q_msg_is_valid (svm_msg_q_t * mq, svm_msg_q_msg_t * msg)
{
  u32 dist1, dist2, tail, head;
  svm_msg_q_ring_t *ring;

  if (vec_len (mq->rings) <= msg->ring_index)
    return 0;
  ring = &mq->rings[msg->ring_index];
  tail = ring->tail;
  head = ring->head;

  dist1 = ((ring->nitems + msg->elt_index) - head) % ring->nitems;
  if (tail == head)
    dist2 = (ring->cursize == 0) ? 0 : ring->nitems;
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
