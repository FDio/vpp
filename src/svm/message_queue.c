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
#include <vppinfra/time.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

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

static void
svm_msg_q_init_mutex (svm_msg_q_shared_queue_t *sq)
{
  pthread_mutexattr_t attr;
  pthread_condattr_t cattr;

  clib_memset (&attr, 0, sizeof (attr));
  clib_memset (&cattr, 0, sizeof (cattr));

  if (pthread_mutexattr_init (&attr))
    clib_unix_warning ("mutexattr_init");
  if (pthread_mutexattr_setpshared (&attr, PTHREAD_PROCESS_SHARED))
    clib_unix_warning ("pthread_mutexattr_setpshared");
  if (pthread_mutexattr_setrobust (&attr, PTHREAD_MUTEX_ROBUST))
    clib_unix_warning ("setrobust");
  if (pthread_mutex_init (&sq->mutex, &attr))
    clib_unix_warning ("mutex_init");
  if (pthread_mutexattr_destroy (&attr))
    clib_unix_warning ("mutexattr_destroy");
  if (pthread_condattr_init (&cattr))
    clib_unix_warning ("condattr_init");
  if (pthread_condattr_setpshared (&cattr, PTHREAD_PROCESS_SHARED))
    clib_unix_warning ("condattr_setpshared");
  if (pthread_cond_init (&sq->condvar, &cattr))
    clib_unix_warning ("cond_init1");
  if (pthread_condattr_destroy (&cattr))
    clib_unix_warning ("cond_init2");
}

svm_msg_q_shared_t *
svm_msg_q_init (void *base, svm_msg_q_cfg_t *cfg)
{
  svm_msg_q_ring_shared_t *ring;
  svm_msg_q_shared_queue_t *sq;
  svm_msg_q_shared_t *smq;
  u32 q_sz, offset;
  int i;

  q_sz = sizeof (*sq) + cfg->q_nitems * sizeof (svm_msg_q_msg_t);

  smq = (svm_msg_q_shared_t *) base;
  sq = smq->q;
  clib_memset (sq, 0, sizeof (*sq));
  sq->elsize = sizeof (svm_msg_q_msg_t);
  sq->maxsize = cfg->q_nitems;
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

  svm_msg_q_init_mutex (sq);

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

  q_sz = sizeof (svm_msg_q_shared_queue_t) +
	 cfg->q_nitems * sizeof (svm_msg_q_msg_t);
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
  mq->q.shr = smq->q;
  mq->q.evtfd = -1;
  n_rings = smq->n_rings;
  vec_validate (mq->rings, n_rings - 1);
  q_sz = sizeof (svm_msg_q_shared_queue_t) +
	 mq->q.shr->maxsize * sizeof (svm_msg_q_msg_t);
  ring = (void *) ((u8 *) smq->q + q_sz);
  for (i = 0; i < n_rings; i++)
    {
      mq->rings[i].nitems = ring->nitems;
      mq->rings[i].elsize = ring->elsize;
      mq->rings[i].shr = ring;
      offset = sizeof (*ring) + ring->nitems * ring->elsize;
      ring = (void *) ((u8 *) ring + offset);
    }
  clib_spinlock_init (&mq->q.lock);
}

void
svm_msg_q_free (svm_msg_q_t * mq)
{
  clib_mem_free (mq->q.shr);
  clib_spinlock_free (&mq->q.lock);
  clib_mem_free (mq);
}

static void
svm_msg_q_send_signal (svm_msg_q_t *mq, u8 is_consumer)
{
  if (mq->q.evtfd == -1)
    {
      if (is_consumer)
	{
	  int rv = pthread_mutex_lock (&mq->q.shr->mutex);
	  if (PREDICT_FALSE (rv == EOWNERDEAD))
	    {
	      rv = pthread_mutex_consistent (&mq->q.shr->mutex);
	      return;
	    }
	}

      (void) pthread_cond_broadcast (&mq->q.shr->condvar);

      if (is_consumer)
	pthread_mutex_unlock (&mq->q.shr->mutex);
    }
  else
    {
      int __clib_unused rv;
      u64 data = 1;

      if (mq->q.evtfd < 0)
	return;

      rv = write (mq->q.evtfd, &data, sizeof (data));
      if (PREDICT_FALSE (rv < 0))
	clib_unix_warning ("signal write on %d returned %d", mq->q.evtfd, rv);
    }
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
  clib_atomic_fetch_add_rel (&sr->cursize, 1);
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
	svm_msg_q_wait (mq, SVM_MQ_WAIT_FULL);
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
    clib_atomic_fetch_add_relax (&sr->cursize, 1);
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
  u32 need_signal;

  ASSERT (vec_len (mq->rings) > msg->ring_index);
  ring = svm_msg_q_ring_inline (mq, msg->ring_index);
  sr = ring->shr;
  if (msg->elt_index == sr->head)
    {
      sr->head = (sr->head + 1) % ring->nitems;
    }
  else
    {
      clib_warning ("message out of order: elt %u head %u ring %u",
		    msg->elt_index, sr->head, msg->ring_index);
      /* for now, expect messages to be processed in order */
      ASSERT (0);
    }

  need_signal = clib_atomic_load_relax_n (&sr->cursize) == ring->nitems;
  clib_atomic_fetch_sub_relax (&sr->cursize, 1);

  if (PREDICT_FALSE (need_signal))
    svm_msg_q_send_signal (mq, 1 /* is consumer */);
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

static void
svm_msg_q_add_raw (svm_msg_q_t *mq, u8 *elem)
{
  svm_msg_q_shared_queue_t *sq = mq->q.shr;
  i8 *tailp;
  u32 sz;

  tailp = (i8 *) (&sq->data[0] + sq->elsize * sq->tail);
  clib_memcpy_fast (tailp, elem, sq->elsize);

  sq->tail = (sq->tail + 1) % sq->maxsize;

  sz = clib_atomic_fetch_add_rel (&sq->cursize, 1);
  if (!sz)
    svm_msg_q_send_signal (mq, 0 /* is consumer */);
}

int
svm_msg_q_add (svm_msg_q_t * mq, svm_msg_q_msg_t * msg, int nowait)
{
  ASSERT (svm_msq_q_msg_is_valid (mq, msg));

  if (nowait)
    {
      /* zero on success */
      if (svm_msg_q_try_lock (mq))
	{
	  return (-1);
	}
    }
  else
    svm_msg_q_lock (mq);

  if (PREDICT_FALSE (svm_msg_q_is_full (mq)))
    {
      if (nowait)
	return (-2);
      while (svm_msg_q_is_full (mq))
	svm_msg_q_wait (mq, SVM_MQ_WAIT_FULL);
    }

  svm_msg_q_add_raw (mq, (u8 *) msg);

  svm_msg_q_unlock (mq);

  return 0;
}

void
svm_msg_q_add_and_unlock (svm_msg_q_t * mq, svm_msg_q_msg_t * msg)
{
  ASSERT (svm_msq_q_msg_is_valid (mq, msg));
  svm_msg_q_add_raw (mq, (u8 *) msg);
  svm_msg_q_unlock (mq);
}

int
svm_msg_q_sub_raw (svm_msg_q_t *mq, svm_msg_q_msg_t *elem)
{
  svm_msg_q_shared_queue_t *sq = mq->q.shr;
  i8 *headp;
  u32 sz;

  ASSERT (!svm_msg_q_is_empty (mq));

  headp = (i8 *) (&sq->data[0] + sq->elsize * sq->head);
  clib_memcpy_fast (elem, headp, sq->elsize);

  sq->head = (sq->head + 1) % sq->maxsize;

  sz = clib_atomic_fetch_sub_relax (&sq->cursize, 1);
  if (PREDICT_FALSE (sz == sq->maxsize))
    svm_msg_q_send_signal (mq, 1 /* is consumer */);

  return 0;
}

int
svm_msg_q_sub_raw_batch (svm_msg_q_t *mq, svm_msg_q_msg_t *msg_buf, u32 n_msgs)
{
  svm_msg_q_shared_queue_t *sq = mq->q.shr;
  u32 sz, to_deq;
  i8 *headp;

  sz = svm_msg_q_size (mq);
  ASSERT (sz);
  to_deq = clib_min (sz, n_msgs);

  headp = (i8 *) (&sq->data[0] + sq->elsize * sq->head);

  if (sq->head + to_deq < sq->maxsize)
    {
      clib_memcpy_fast (msg_buf, headp, sq->elsize * to_deq);
      sq->head += to_deq;
    }
  else
    {
      u32 first_batch = sq->maxsize - sq->head;
      clib_memcpy_fast (msg_buf, headp, sq->elsize * first_batch);
      clib_memcpy_fast (msg_buf + first_batch, sq->data,
			sq->elsize * (to_deq - first_batch));
      sq->head = (sq->head + to_deq) % sq->maxsize;
    }

  clib_atomic_fetch_sub_relax (&sq->cursize, to_deq);
  if (PREDICT_FALSE (sz == sq->maxsize))
    svm_msg_q_send_signal (mq, 1 /* is consumer */);

  return to_deq;
}

int
svm_msg_q_sub (svm_msg_q_t *mq, svm_msg_q_msg_t *msg,
	       svm_q_conditional_wait_t cond, u32 time)
{
  int rc = 0;

  if (svm_msg_q_is_empty (mq))
    {
      if (cond == SVM_Q_NOWAIT)
	{
	  return (-2);
	}
      else if (cond == SVM_Q_TIMEDWAIT)
	{
	  if ((rc = svm_msg_q_timedwait (mq, time)))
	    return rc;
	}
      else
	{
	  svm_msg_q_wait (mq, SVM_MQ_WAIT_EMPTY);
	}
    }

  svm_msg_q_sub_raw (mq, msg);

  return 0;
}

void
svm_msg_q_set_eventfd (svm_msg_q_t *mq, int fd)
{
  mq->q.evtfd = fd;
}

int
svm_msg_q_alloc_eventfd (svm_msg_q_t *mq)
{
  int fd;
  if ((fd = eventfd (0, 0)) < 0)
    return -1;
  svm_msg_q_set_eventfd (mq, fd);
  return 0;
}

int
svm_msg_q_wait (svm_msg_q_t *mq, svm_msg_q_wait_type_t type)
{
  u8 (*fn) (svm_msg_q_t *);
  int rv;

  fn = (type == SVM_MQ_WAIT_EMPTY) ? svm_msg_q_is_empty : svm_msg_q_is_full;

  if (mq->q.evtfd == -1)
    {
      rv = pthread_mutex_lock (&mq->q.shr->mutex);
      if (PREDICT_FALSE (rv == EOWNERDEAD))
	{
	  rv = pthread_mutex_consistent (&mq->q.shr->mutex);
	  return rv;
	}

      while (fn (mq))
	pthread_cond_wait (&mq->q.shr->condvar, &mq->q.shr->mutex);

      pthread_mutex_unlock (&mq->q.shr->mutex);
    }
  else
    {
      u64 buf;

      while (fn (mq))
	{
	  while ((rv = read (mq->q.evtfd, &buf, sizeof (buf))) < 0)
	    {
	      if (errno != EAGAIN)
		{
		  clib_unix_warning ("read error");
		  return rv;
		}
	    }
	}
    }

  return 0;
}

int
svm_msg_q_timedwait (svm_msg_q_t *mq, double timeout)
{
  if (mq->q.evtfd == -1)
    {
      svm_msg_q_shared_queue_t *sq = mq->q.shr;
      struct timespec ts;
      u32 sz;
      int rv;

      rv = pthread_mutex_lock (&sq->mutex);
      if (PREDICT_FALSE (rv == EOWNERDEAD))
	{
	  rv = pthread_mutex_consistent (&sq->mutex);
	  return rv;
	}

      /* check if we're still in a signalable state after grabbing lock */
      sz = svm_msg_q_size (mq);
      if (sz != 0 && sz != sq->maxsize)
	{
	  pthread_mutex_unlock (&sq->mutex);
	  return 0;
	}

      ts.tv_sec = unix_time_now () + (u32) timeout;
      ts.tv_nsec = (timeout - (u32) timeout) * 1e9;
      rv = pthread_cond_timedwait (&sq->condvar, &sq->mutex, &ts);

      pthread_mutex_unlock (&sq->mutex);
      return rv;
    }
  else
    {
      struct timeval tv;
      u64 buf;
      int rv;

      tv.tv_sec = (u64) timeout;
      tv.tv_usec = ((u64) timeout - (u64) timeout) * 1e9;
      rv = setsockopt (mq->q.evtfd, SOL_SOCKET, SO_RCVTIMEO,
		       (const char *) &tv, sizeof tv);
      if (rv < 0)
	{
	  clib_unix_warning ("setsockopt");
	  return -1;
	}

      rv = read (mq->q.evtfd, &buf, sizeof (buf));
      if (rv < 0)
	clib_warning ("read %u", errno);

      return rv < 0 ? errno : 0;
    }
}

u8 *
format_svm_msg_q (u8 * s, va_list * args)
{
  svm_msg_q_t *mq = va_arg (*args, svm_msg_q_t *);
  s = format (s, " [Q:%d/%d]", mq->q.shr->cursize, mq->q.shr->maxsize);
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
