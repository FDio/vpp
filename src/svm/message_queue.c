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

svm_msg_q_t *
svm_msg_q_alloc (svm_msg_q_cfg_t * cfg)
{
  svm_msg_q_ring_t *ring;
  svm_msg_q_t *mq;
  uword size;
  int i;

  if (!cfg)
    return 0;

  mq = clib_mem_alloc_aligned (sizeof (svm_msg_q_t), CLIB_CACHE_LINE_BYTES);
  memset (mq, 0, sizeof (*mq));
  mq->q = svm_queue_init (cfg->q_nitems, sizeof (svm_msg_q_msg_t),
			  cfg->consumer_pid, 0);
  vec_validate (mq->rings, cfg->n_rings - 1);
  for (i = 0; i < cfg->n_rings; i++)
    {
      ring = &mq->rings[i];
      ring->elsize = cfg->ring_cfgs[i].elsize;
      ring->nitems = cfg->ring_cfgs[i].nitems;
      if (cfg->ring_cfgs[i].data)
	ring->data = cfg->ring_cfgs[i].data;
      else
	{
	  size = (uword) ring->nitems * ring->elsize;
	  ring->data = clib_mem_alloc_aligned (size, CLIB_CACHE_LINE_BYTES);
	}
    }

  return mq;
}

void
svm_msg_q_free (svm_msg_q_t * mq)
{
  svm_msg_q_ring_t *ring;

  vec_foreach (ring, mq->rings)
  {
    clib_mem_free (ring->data);
  }
  vec_free (mq->rings);
  clib_mem_free (mq);
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

static inline svm_msg_q_ring_t *
svm_msg_q_get_ring (svm_msg_q_t * mq, u32 ring_index)
{
  return vec_elt_at_index (mq->rings, ring_index);
}

static inline void *
svm_msg_q_ring_data (svm_msg_q_ring_t * ring, u32 elt_index)
{
  ASSERT (elt_index < ring->nitems);
  return (ring->data + elt_index * ring->elsize);
}

void *
svm_msg_q_msg_data (svm_msg_q_t * mq, svm_msg_q_msg_t * msg)
{
  svm_msg_q_ring_t *ring = svm_msg_q_get_ring (mq, msg->ring_index);
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
  svm_msg_q_ring_t *ring;
  u32 dist1, dist2;

  if (vec_len (mq->rings) <= msg->ring_index)
    return 0;
  ring = &mq->rings[msg->ring_index];

  dist1 = ((ring->nitems + msg->ring_index) - ring->head) % ring->nitems;
  if (ring->tail == ring->head)
    dist2 = (ring->cursize == 0) ? 0 : ring->nitems;
  else
    dist2 = ((ring->nitems + ring->tail) - ring->head) % ring->nitems;
  return (dist1 < dist2);
}

int
svm_msg_q_add (svm_msg_q_t * mq, svm_msg_q_msg_t msg, int nowait)
{
  ASSERT (svm_msq_q_msg_is_valid (mq, &msg));
  return svm_queue_add (mq->q, (u8 *) & msg, nowait);
}

int
svm_msg_q_sub (svm_msg_q_t * mq, svm_msg_q_msg_t * msg,
	       svm_q_conditional_wait_t cond, u32 time)
{
  return svm_queue_sub (mq->q, (u8 *) msg, cond, time);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
